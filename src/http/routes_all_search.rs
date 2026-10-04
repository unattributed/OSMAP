//! Bounded mixed search over authenticated mail summaries and saved contacts.
//! Documents remain unavailable until their actual S08 adapter is implemented.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

const PAGE_SIZE: usize = 20;
const MAX_PAGES: usize = (crate::mailbox::DEFAULT_MAX_SEARCH_RESULTS
    + crate::contacts::MAX_CONTACTS)
    .div_ceil(PAGE_SIZE);

enum Category<T> {
    NotSearched,
    Unavailable,
    Available(T),
}

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_all_search(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let query = request
            .query_params
            .get("q")
            .map(String::as_str)
            .unwrap_or("");
        let mut filters = match crate::mail_navigation::SearchFilterContext::parse(&request.query_params) {
            Some(filters) if request.query_params.get("category").map(String::as_str) == Some("all")
                && filters.view.requested_page <= MAX_PAGES => filters,
            _ => return HandledHttpResponse {
                response: html_response(400,"Bad Request","Invalid Search Request",render_navigation_notice(
                    &session.record.canonical_username,&session.record.csrf_token,"Invalid Search Request",
                    "Use bounded keywords, supported message filters and an available results page.")),
                audit_events,
            },
        };
        let query = query.trim();
        if query.is_empty() {
            return HandledHttpResponse {
                response: html_response(
                    200,
                    "OK",
                    "Search All",
                    all_page(
                        &session,
                        query,
                        &filters,
                        &Category::NotSearched,
                        &Category::NotSearched,
                        false,
                        None,
                    ),
                ),
                audit_events,
            };
        }
        let (guard, event) = match self.acquire_search_budget(context, &session) {
            Ok(value) => value,
            Err(mut response) => {
                audit_events.extend(response.audit_events);
                response.audit_events = audit_events;
                return response;
            }
        };
        audit_events.push(event);
        // Existing mail helper deadlines and contact-store bounds still apply.
        // Reject late category projection without increasing any worker timeout.
        let deadline = Instant::now()
            + Duration::from_secs(self.policy.expensive_request_timeout_secs.clamp(1, 30));
        let outcome = self.gateway.search_messages(
            context,
            &session,
            filters.mailbox.as_deref(),
            query,
            MessageSearchField::All,
        );
        audit_events.extend(outcome.audit_events);
        let messages = match outcome.decision {
            BrowserMessageSearchDecision::Listed {
                canonical_username,
                mailbox_name,
                query: echoed,
                mut results,
            } if canonical_username == session.record.canonical_username
                && mailbox_name == filters.mailbox
                && echoed == query
                && Instant::now() < deadline
                && valid_messages(&results)
                && filters
                    .mailbox
                    .as_ref()
                    .is_none_or(|folder| results.iter().all(|row| &row.mailbox_name == folder)) =>
            {
                // Deterministic type-first ordering, then mailbox/UID. This
                // is not a fabricated cross-category relevance score.
                filters.view.order_search(&mut results);
                results.sort_by(|left, right| {
                    left.mailbox_name
                        .cmp(&right.mailbox_name)
                        .then(left.uid.cmp(&right.uid))
                });
                Category::Available(results)
            }
            _ => Category::Unavailable,
        };
        let people = if Instant::now() < deadline {
            match self.contact_snapshot(&session) {
                Ok(book) if Instant::now() < deadline => Category::Available(book),
                _ => Category::Unavailable,
            }
        } else {
            Category::Unavailable
        };
        let on_open = self
            .gateway
            .load_mark_read_policy(&session)
            .is_ok_and(|preference| preference.policy == crate::mark_read::Policy::OnOpen);
        let (messages, people) = if Instant::now() < deadline {
            (messages, people)
        } else {
            (Category::Unavailable, Category::Unavailable)
        };
        let status = if matches!(messages, Category::Unavailable)
            && matches!(people, Category::Unavailable)
        {
            503
        } else {
            200
        };
        let response = html_response(
            status,
            if status == 200 {
                "OK"
            } else {
                "Service Unavailable"
            },
            "Search All",
            all_page(&session, query, &filters, &messages, &people, on_open, None),
        );
        audit_events.push(self.release_request_budget(guard, "message_search", context, &session));
        HandledHttpResponse {
            response,
            audit_events,
        }
    }
}

fn valid_messages(results: &[MessageSearchResult]) -> bool {
    let policy = crate::mailbox::MessageSearchPolicy::default();
    if results.len() > policy.max_results {
        return false;
    }
    let mut identities = BTreeSet::new();
    let mut versions = BTreeSet::new();
    let mut mailbox_versions = BTreeMap::new();
    results.iter().all(|row| {
        if crate::mailbox::MailboxEntry::new(
            crate::mailbox::MailboxListingPolicy::default(),
            &row.mailbox_name,
        )
        .is_err()
            || row.uid == 0
            || row.uid > u64::from(u32::MAX)
            || !identities.insert((&row.mailbox_name, row.uid))
            || row.date_received.len() > policy.message_date_max_len
            || row.date_received.chars().any(char::is_control)
            || [&row.subject, &row.from].iter().any(|value| {
                value.as_ref().is_some_and(|text| {
                    text.len() > policy.header_value_max_len || text.chars().any(char::is_control)
                })
            })
        {
            return false;
        }
        if let Some(metadata) = &row.metadata {
            let version = &metadata.version;
            if crate::message_metadata::MessageVersion::new(
                version.mailbox_guid.clone(),
                version.message_guid.clone(),
            )
            .is_err()
                || !versions.insert((&row.mailbox_name, &version.message_guid))
            {
                return false;
            }
            match mailbox_versions.insert(&row.mailbox_name, &version.mailbox_guid) {
                Some(previous) if previous != &version.mailbox_guid => return false,
                _ => {}
            }
        }
        true
    })
}

enum Row<'a> {
    Message(&'a MessageSearchResult),
    Person(&'a crate::contacts::Contact),
}

fn all_page(
    session: &ValidatedSession,
    query: &str,
    filters: &crate::mail_navigation::SearchFilterContext,
    messages: &Category<Vec<MessageSearchResult>>,
    people: &Category<crate::contacts::ContactBook>,
    on_open: bool,
    error: Option<&str>,
) -> TrustedHtml {
    let requested_page = filters.view.requested_page;
    let q = query.to_lowercase();
    let mut contacts = match people {
        Category::Available(book) => book
            .contacts
            .iter()
            .filter(|contact| {
                contact.display_name.to_lowercase().contains(&q)
                    || contact.address.to_lowercase().contains(&q)
            })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    contacts.sort_by_cached_key(|contact| {
        (
            contact.display_name.to_lowercase(),
            contact.address.to_lowercase(),
            contact.id.clone(),
        )
    });
    let message_rows = match messages {
        Category::Available(rows) => rows.as_slice(),
        _ => &[],
    };
    let count = message_rows.len() + contacts.len();
    let pages = count.div_ceil(PAGE_SIZE).max(1);
    let measured =
        matches!(messages, Category::Available(_)) || matches!(people, Category::Available(_));
    let page = if measured {
        requested_page.min(pages)
    } else {
        requested_page
    };
    let href = |number| filters.href(crate::mail_navigation::SearchTab::All, query, Some(number));
    let back = href(page);
    let rows = message_rows
        .iter()
        .map(Row::Message)
        .chain(contacts.iter().copied().map(Row::Person));
    let mut markup = String::new();
    for row in rows.skip((page - 1) * PAGE_SIZE).take(PAGE_SIZE) {
        let (kind, control, detail, location, time, preview) = match row {
            Row::Message(message) => {
                let title = message.subject.as_deref().unwrap_or("(No subject)");
                let control = message.metadata.as_ref().and_then(|metadata| {
                    let target = format!("/message?mailbox={}&uid={}&mailbox_guid={}&message_guid={}&return_to={}",
                        url_encode(&message.mailbox_name), message.uid, url_encode(&metadata.version.mailbox_guid),
                        url_encode(&metadata.version.message_guid), url_encode(&back));
                    crate::mail_navigation::safe_mail_return(&target).map(|safe|
                        crate::http_ui::message_open_control(&session.record.csrf_token, &safe, "message-subject-link", title, false, on_open, None))
                }).unwrap_or_else(|| format!("<span class=\"message-subject-link\" aria-disabled=\"true\">{} <span class=\"muted\">(Open unavailable)</span></span>", escape_html(title)));
                (
                    "Message",
                    control,
                    message.from.as_deref().unwrap_or("Sender unavailable"),
                    message.mailbox_name.as_str(),
                    message.date_received.as_str(),
                    message
                        .metadata
                        .as_ref()
                        .filter(|metadata| {
                            metadata.protection
                                != crate::message_metadata::MessageProtection::Encrypted
                        })
                        .and_then(|metadata| metadata.preview.as_deref())
                        .filter(|preview| crate::message_metadata::valid_message_preview(preview))
                        .map(|preview| format!(" · {}", escape_html(preview)))
                        .unwrap_or_default(),
                )
            }
            Row::Person(contact) => {
                let revision = match people {
                    Category::Available(book) => book.revision,
                    _ => 0,
                };
                let link = format!(
                    "/contacts?edit={}&revision={revision}",
                    url_encode(&contact.id)
                );
                let title = if contact.display_name.is_empty() {
                    &contact.address
                } else {
                    &contact.display_name
                };
                (
                    "Person",
                    format!(
                        "<a class=\"message-subject-link\" href=\"{}\" dir=\"auto\">{}</a>",
                        escape_html(&link),
                        escape_html(title)
                    ),
                    contact.address.as_str(),
                    "Saved contacts",
                    "Unavailable",
                    String::new(),
                )
            }
        };
        markup.push_str(&format!("<li class=\"search-result-row\"><span>{kind}</span><div class=\"search-result-title\">{control}<span class=\"message-sender\" dir=\"auto\">{}{preview}</span></div><span class=\"search-result-location\" dir=\"auto\">{}</span><span class=\"search-result-date\">{}</span><span></span></li>", escape_html(detail), escape_html(location), escape_html(time)));
    }
    let label = |name: &str, available: bool, searched: bool, number: usize| {
        if available {
            format!("{name} ({number})")
        } else if searched {
            format!("{name} unavailable")
        } else {
            format!("{name} not searched")
        }
    };
    let all_label = if query.is_empty() {
        "All available".into()
    } else if !measured {
        "All unavailable".into()
    } else {
        format!("All available ({count})")
    };
    let messages_label = label(
        "Messages",
        matches!(messages, Category::Available(_)),
        !matches!(messages, Category::NotSearched),
        message_rows.len(),
    );
    let people_label = label(
        "People",
        matches!(people, Category::Available(_)),
        !matches!(people, Category::NotSearched),
        contacts.len(),
    );
    let partial =
        matches!(messages, Category::Unavailable) || matches!(people, Category::Unavailable);
    let mut notices = String::new();
    if let Some(error) = error {
        notices.push_str(&format!("<p role=\"alert\">{}</p>", escape_html(error)));
    }
    if partial && measured {
        notices.push_str("<p role=\"status\">Some categories are unavailable. Available results remain visible; unavailable does not mean no matches.</p>");
    } else if partial {
        notices.push_str("<p role=\"status\">Messages and saved contacts are unavailable. No result count could be verified; this does not mean there are no matches.</p>");
    }
    if markup.is_empty() {
        markup = if query.is_empty() {
            "<li class=\"message-empty-state\">Enter keywords to search messages and saved contacts.</li>".into()
        } else if !measured {
            "<li class=\"message-empty-state\">Search results unavailable. No category count could be measured.</li>".into()
        } else if partial {
            "<li class=\"message-empty-state\">No rows in the available categories. Unavailable categories have not been counted.</li>".into()
        } else {
            "<li class=\"message-empty-state\">No messages or saved contacts match this bounded search. Documents search remains unavailable.</li>".into()
        };
    }
    let mut pagination = if query.is_empty() {
        String::new()
    } else if !measured {
        format!(
            "<span>Result count unavailable</span> <a href=\"{}\">Retry All search</a>",
            escape_html(&href(page))
        )
    } else {
        format!("<span>{count} loaded available results · Page {page} of {pages}</span><nav aria-label=\"All result pages\">")
    };
    if !query.is_empty() && measured {
        if page > 1 {
            pagination.push_str(&format!(
                "<a href=\"{}\">Previous page</a> ",
                escape_html(&href(page - 1))
            ));
        }
        if page < pages {
            pagination.push_str(&format!(
                "<a href=\"{}\">Next page</a>",
                escape_html(&href(page + 1))
            ));
        }
        pagination.push_str("</nav>");
    }
    TrustedHtml::from_template(format!(concat!(
        "{}<main id=\"main-content\" class=\"page-shell coordinated-mail search-results all-search\" tabindex=\"-1\"><div class=\"page-intro mail-page-intro\"><h1>Search</h1><p>Find messages and people saved in your contacts.</p></div><section class=\"content-pane coordinated-list\"><h2 class=\"sr-only\">All available search results</h2>",
        "<div class=\"search-query-panel\"><form method=\"get\" action=\"/search\"><input type=\"hidden\" name=\"category\" value=\"all\">{filter_state}<label class=\"sr-only\" for=\"all-query\">Search query</label><input id=\"all-query\" type=\"search\" name=\"q\" value=\"{}\" maxlength=\"256\" placeholder=\"Search messages and people…\"><button type=\"submit\">Search</button></form>{filter_controls}</div>",
        "<nav class=\"search-result-tabs\" aria-label=\"Search types\"><span aria-current=\"page\">{all_label}</span><a href=\"{messages_href}\">{messages_label}</a><span aria-disabled=\"true\">Documents unavailable</span><a href=\"{people_href}\">{people_label}</a></nav>{notices}",
        "<div class=\"search-result-headings\" aria-hidden=\"true\"><span>Type</span><span>Result</span><span>Location</span><span>Received / Modified</span><span></span></div><ul class=\"search-result-list\" aria-label=\"All available results\">{markup}</ul><div class=\"search-result-footer\">{pagination}</div>",
        "<p class=\"search-capability-note muted\">Counts cover at most 250 loaded messages and 200 saved contacts. Messages appear first by mailbox and UID, then people by name and address. Documents search and contact modification times are unavailable. This is not a complete count of all content.</p><a href=\"/search?category=all\">Clear search</a></section></main>"),
        crate::http_ui::app_header(&session.record.canonical_username, &session.record.csrf_token, "search"), escape_html(query), filter_state=crate::http_ui::category_filter_hidden(filters),
        filter_controls=crate::http_ui::render_search_category_filters(filters,query),
        messages_href=escape_html(&filters.href(crate::mail_navigation::SearchTab::Messages,query,None)),
        people_href=escape_html(&filters.href(crate::mail_navigation::SearchTab::People,query,None)), all_label=all_label, messages_label=messages_label, people_label=people_label, notices=notices, markup=markup, pagination=pagination))
}
