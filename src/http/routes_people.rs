//! Bounded account-private saved-contact search; never dispatches mail search.
use super::*;
const PAGE_SIZE: usize = 20;

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_people_search(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let fields = &request.query_params;
        let query = fields.get("q").map(String::as_str).unwrap_or("");
        let page = fields
            .get("page")
            .map(|v| {
                v.parse::<usize>()
                    .ok()
                    .filter(|n| (1..=10).contains(n) && n.to_string() == *v)
            })
            .unwrap_or(Some(1));
        let valid = fields.get("category").map(String::as_str) == Some("people")
            && fields
                .keys()
                .all(|k| matches!(k.as_str(), "category" | "q" | "page"))
            && query.len() <= 256
            && !query.chars().any(char::is_control)
            && page.is_some();
        let (status, body) = if !valid {
            (400, people_page(&session, "", None, 1, Some("This search request is invalid. Use shorter keywords and a supported results page.")))
        } else {
            match self.contact_snapshot(&session) {
                Ok(book) => (200, people_page(&session, query, Some(&book), page.unwrap_or(1), None)),
                Err(_) => (503, people_page(&session, query, None, page.unwrap_or(1), Some("Saved contacts could not be verified for this account. Search results are unavailable; this does not mean there are no matches."))),
            }
        };
        HandledHttpResponse {
            response: html_response(
                status,
                match status {
                    200 => "OK",
                    400 => "Bad Request",
                    _ => "Service Unavailable",
                },
                "Search People",
                body,
            ),
            audit_events,
        }
    }
}

fn people_page(
    session: &ValidatedSession,
    query: &str,
    book: Option<&crate::contacts::ContactBook>,
    requested_page: usize,
    error: Option<&str>,
) -> TrustedHtml {
    let q = query.trim().to_lowercase();
    let mut matches: Vec<_> = book
        .into_iter()
        .flat_map(|b| &b.contacts)
        .filter(|c| {
            c.display_name.to_lowercase().contains(&q) || c.address.to_lowercase().contains(&q)
        })
        .collect();
    matches.sort_by_cached_key(|c| {
        (
            c.display_name.to_lowercase(),
            c.address.to_lowercase(),
            c.id.clone(),
        )
    });
    let count = matches.len();
    let pages = count.div_ceil(PAGE_SIZE).max(1);
    let page = if book.is_some() {
        requested_page.min(pages)
    } else {
        requested_page
    };
    let href = |p| format!("/search?category=people&q={}&page={p}", url_encode(query));
    let mut rows = String::new();
    for c in matches.iter().skip((page - 1) * PAGE_SIZE).take(PAGE_SIZE) {
        let link = format!(
            "/contacts?edit={}&revision={}",
            url_encode(&c.id),
            book.map(|b| b.revision).unwrap_or(0)
        );
        rows.push_str(&format!("<li class=\"search-result-row\"><span class=\"people-type\">Person</span><div class=\"search-result-title\"><a class=\"message-subject-link\" href=\"{}\" dir=\"auto\">{}</a><span class=\"message-sender\" dir=\"auto\">{}</span></div><span class=\"search-result-location\">Saved contacts</span><span class=\"search-result-date\">Unavailable</span><a class=\"people-edit\" href=\"{}\" aria-label=\"Edit contact {}\">Edit</a></li>",escape_html(&link),escape_html(if c.display_name.is_empty(){&c.address}else{&c.display_name}),escape_html(&c.address),escape_html(&link),escape_html(&c.address)));
    }
    if let Some(error) = error {
        rows=format!("<li class=\"message-empty-state\" role=\"status\"><strong>People search unavailable</strong><p>{}</p><a href=\"{}\">Retry People search</a> <a href=\"/search?category=people\">Clear search</a></li>",escape_html(error),escape_html(&href(page)));
    } else if count == 0 {
        rows="<li class=\"message-empty-state\"><strong>No saved contacts match.</strong><p>Try different keywords or add a contact.</p><a href=\"/search?category=people\">Clear search</a> <a href=\"/contacts\">Manage contacts</a></li>".into();
    }
    let mut pagination = String::new();
    if book.is_some() {
        pagination=format!("<span>{count} matching saved contacts · Page {page} of {pages}</span><nav aria-label=\"People result pages\">");
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
    TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell coordinated-mail search-results people-search\" tabindex=\"-1\"><div class=\"page-intro mail-page-intro\"><h1>Search</h1><p>Find messages and people saved in your contacts.</p></div><section class=\"content-pane coordinated-list\"><h2 class=\"sr-only\">People search results</h2><div class=\"search-query-panel\"><form method=\"get\" action=\"/search\"><input type=\"hidden\" name=\"category\" value=\"people\"><label class=\"sr-only\" for=\"people-query\">Search query</label><input id=\"people-query\" type=\"search\" name=\"q\" value=\"{}\" maxlength=\"256\" placeholder=\"Search saved contacts…\"><button type=\"submit\">Search</button></form><p>Saved contacts · Name or email address</p></div><nav class=\"search-result-tabs\" aria-label=\"Search types\"><a href=\"/search?category=all&amp;q={all_query}\">All</a><a href=\"/search?scope=all&amp;q={}\">Messages</a><span aria-disabled=\"true\">Documents</span><span aria-current=\"page\">People{}</span><span class=\"search-scope\">Saved contacts</span></nav><div class=\"search-result-headings\" aria-hidden=\"true\"><span>Type</span><span>Result</span><span>Location</span><span>Modified</span><span></span></div><ul class=\"search-result-list\" aria-label=\"People results\">{rows}</ul><div class=\"search-result-footer\">{pagination}</div><p class=\"search-capability-note muted\">Only your saved contacts are searched. Contact modification times and Documents search are unavailable.</p></section></main>",crate::http_ui::app_header(&session.record.canonical_username,&session.record.csrf_token,"search"),escape_html(query),escape_html(&url_encode(query)),if book.is_some(){format!(" ({count})")}else{String::new()},all_query=escape_html(&url_encode(query))))
}
