//! Account-private contact forms. Every change compares the displayed revision.
use super::*;
use crate::contacts::{ContactBook, ContactChange, ContactError};

pub(super) fn revision(value: Option<&String>) -> Option<u64> {
    let text = value?;
    let value = text.parse::<u64>().ok()?;
    (value.to_string() == *text).then_some(value)
}

fn status(error: ContactError) -> (u16, &'static str) {
    match error {
        ContactError::Invalid => (400, "Bad Request"),
        ContactError::NotFound => (404, "Not Found"),
        ContactError::Duplicate | ContactError::Quota | ContactError::Stale => (409, "Conflict"),
        ContactError::Busy => (429, "Too Many Requests"),
        ContactError::Unavailable => (503, "Service Unavailable"),
    }
}

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn contact_snapshot(
        &self,
        session: &ValidatedSession,
    ) -> Result<ContactBook, ContactError> {
        let book = self.gateway.load_contacts(session)?;
        book.ensure_account(&session.record.canonical_username)?;
        Ok(book)
    }

    pub(super) fn add_selected_contact(
        &self,
        session: &ValidatedSession,
        form: &mut BTreeMap<String, String>,
    ) -> Result<(), ContactError> {
        match form.get("compose_action").map(String::as_str) {
            None
            | Some(
                "minimize" | "preview" | "preflight" | "format-bold" | "format-italic"
                | "format-underline" | "format-bullets" | "format-numbers" | "format-link"
                | "format-emoji",
            ) => return Ok(()),
            Some("add-contact") => {}
            _ => return Err(ContactError::Invalid),
        }
        let target = form
            .get("contact_target")
            .cloned()
            .ok_or(ContactError::Invalid)?;
        if !["to", "cc", "bcc"].contains(&target.as_str()) {
            return Err(ContactError::Invalid);
        }
        let id = form.get("contact_id").ok_or(ContactError::Invalid)?;
        let address = if id.starts_with("key:") {
            // A posted handle is never address/key authority: reconstruct the
            // current account-owned certificate choices before touching a draft.
            let view = self
                .gateway
                .compose_protection(
                    session,
                    "",
                    "",
                    "",
                    crate::send::ProtectionIntent::default(),
                )
                .ok_or(ContactError::Unavailable)?;
            view.imported_recipients
                .as_ref()
                .ok_or(ContactError::Unavailable)?
                .selected(&session.record.canonical_username, id)?
                .address
                .clone()
        } else {
            let expected = revision(form.get("contact_revision")).ok_or(ContactError::Invalid)?;
            let book = self.contact_snapshot(session)?;
            book.selected(expected, id)?.address.clone()
        };
        let value = form.entry(target).or_default();
        let entered = crate::mail_address::parse_address_list(ComposePolicy::default(), value)
            .map_err(|_| ContactError::Invalid)?;
        if entered.iter().any(|entered_address| {
            crate::mail_address::comparison_key(entered_address)
                == crate::mail_address::comparison_key(&address)
        }) {
            return Ok(());
        }
        if !value.trim().is_empty() {
            value.push_str(", ");
        }
        value.push_str(&address);
        Ok(())
    }

    pub(super) fn handle_contacts(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(result) => result,
            Err(response) => return response,
        };
        let result = (|| {
            let query = &request.query_params;
            if query.keys().any(|key| {
                ![
                    "edit", "delete", "revision", "q", "filter", "new", "from_key",
                ]
                .contains(&key.as_str())
            }) || query.contains_key("edit") && query.contains_key("delete")
                || query
                    .get("q")
                    .is_some_and(|q| q.len() > 200 || q.chars().any(char::is_control))
                || query
                    .get("filter")
                    .is_some_and(|filter| !["all", "saved", "keys"].contains(&filter.as_str()))
                || query.get("new").is_some_and(|new| new != "1")
                || query.contains_key("new")
                    && (query.contains_key("edit") || query.contains_key("delete"))
                || query.contains_key("from_key")
                    && query.get("new").map(String::as_str) != Some("1")
                || query.contains_key("revision")
                    && !query.contains_key("edit")
                    && !query.contains_key("delete")
            {
                return Err(ContactError::Invalid);
            }
            let book = self.contact_snapshot(&session).ok();
            let mut input = query.clone();
            if let Some(id) = query.get("from_key") {
                if !id.starts_with("key:") {
                    return Err(ContactError::Invalid);
                }
                let mut selection = BTreeMap::from([
                    ("compose_action".into(), "add-contact".into()),
                    ("contact_target".into(), "to".into()),
                    ("contact_id".into(), id.clone()),
                ]);
                self.add_selected_contact(&session, &mut selection)?;
                input.insert(
                    "address".into(),
                    selection.remove("to").ok_or(ContactError::Unavailable)?,
                );
            }
            if let Some(id) = query.get("edit").or_else(|| query.get("delete")) {
                let expected = revision(query.get("revision")).ok_or(ContactError::Invalid)?;
                let contact = book
                    .as_ref()
                    .ok_or(ContactError::Unavailable)?
                    .selected(expected, id)?;
                input.insert("id".into(), contact.id.clone());
                input.insert("name".into(), contact.display_name.clone());
                input.insert("address".into(), contact.address.clone());
                input.insert("revision".into(), expected.to_string());
            }
            let outcome = self.gateway.key_management(context, &session);
            audit_events.extend(outcome.audit_events);
            Ok(render_page(
                &session,
                book.as_ref(),
                &input,
                None,
                query.contains_key("delete"),
                &outcome.state,
            ))
        })();
        match result {
            Ok(body) => HandledHttpResponse {
                response: html_response(200, "OK", "Contacts", body),
                audit_events,
            },
            Err(error) => HandledHttpResponse {
                response: contact_error_page(&session, error),
                audit_events,
            },
        }
    }

    pub(super) fn handle_contact_change(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
        deleting: bool,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(result) => result,
            Err(response) => return response,
        };
        let parsed = if allows_urlencoded_request_body(
            request.headers.get("content-type").map(String::as_str),
        ) {
            parse_urlencoded_form(&request.body, 6, 4096).map_err(|_| ContactError::Invalid)
        } else {
            Err(ContactError::Invalid)
        };
        let form = match parsed {
            Ok(form) => form,
            Err(error) => {
                return HandledHttpResponse {
                    response: contact_error_page(&session, error),
                    audit_events,
                }
            }
        };
        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return response;
        }
        let result = (|| {
            let allowed: &[&str] = if deleting {
                &["csrf_token", "revision", "id", "confirm"]
            } else {
                &["csrf_token", "revision", "id", "name", "address"]
            };
            if form.keys().any(|key| !allowed.contains(&key.as_str())) {
                return Err(ContactError::Invalid);
            }
            let expected = revision(form.get("revision")).ok_or(ContactError::Invalid)?;
            let id = form.get("id").filter(|value| !value.is_empty()).cloned();
            let change = if deleting {
                if form.get("confirm").map(String::as_str) != Some("1") {
                    return Err(ContactError::Invalid);
                }
                ContactChange::Delete {
                    id: id.ok_or(ContactError::Invalid)?,
                }
            } else {
                ContactChange::Save {
                    id,
                    display_name: form.get("name").cloned().unwrap_or_default(),
                    address: form.get("address").cloned().ok_or(ContactError::Invalid)?,
                }
            };
            let book = self.gateway.change_contact(&session, expected, change)?;
            book.ensure_account(&session.record.canonical_username)?;
            if Some(book.revision) != expected.checked_add(1) {
                return Err(ContactError::Unavailable);
            }
            Ok(book)
        })();
        match result {
            Ok(_) => {
                audit_events.push(build_http_info_event(
                    if deleting {
                        "contact_deleted"
                    } else {
                        "contact_saved"
                    },
                    "account contact change completed",
                    context,
                ));
                HandledHttpResponse {
                    response: redirect_response(303, "See Other", "/contacts"),
                    audit_events,
                }
            }
            Err(error) => {
                audit_events.push(build_http_warning_event(
                    "contact_change_refused",
                    "account contact change refused or unconfirmed",
                    context,
                ));
                let (code, reason) = status(error);
                let book = self.contact_snapshot(&session).ok();
                let outcome = self.gateway.key_management(context, &session);
                audit_events.extend(outcome.audit_events);
                let body = render_page(
                    &session,
                    book.as_ref(),
                    &form,
                    Some(error),
                    deleting,
                    &outcome.state,
                );
                HandledHttpResponse {
                    response: html_response(code, reason, "Contacts", body),
                    audit_events,
                }
            }
        }
    }
}

fn contact_error_page(session: &ValidatedSession, error: ContactError) -> HttpResponse {
    let (code, reason) = status(error);
    html_response(code, reason, "Contacts", TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><section class=\"content-pane\"><h1>Contacts</h1><p role=\"alert\">{}</p><a href=\"/contacts\">Reload contacts</a></section></main>", crate::http_ui::app_header(&session.record.canonical_username, &session.record.csrf_token, "contacts"), escape_html(error.message()))))
}

fn render_page(
    session: &ValidatedSession,
    book: Option<&ContactBook>,
    input: &BTreeMap<String, String>,
    error: Option<ContactError>,
    deleting: bool,
    state: &crate::key_management::State,
) -> TrustedHtml {
    let account = &session.record.canonical_username;
    let book = book.filter(|book| book.ensure_account(account).is_ok());
    let owned = state.canonical_username == *account;
    let bindings = owned.then_some(state.bindings.as_ref()).flatten();
    let inventory = owned.then_some(state.inventory.as_ref()).flatten();
    let now = crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider);
    // If imported metadata exceeds the projection bound, preserve the independent
    // saved directory and show key information as unavailable, never a partial list.
    let directory =
        crate::contacts::ContactDirectory::from_sources(account, book, bindings, inventory, now)
            .or_else(|_| {
                crate::contacts::ContactDirectory::from_sources(account, book, bindings, None, now)
            })
            .unwrap_or(crate::contacts::ContactDirectory {
                entries: vec![],
                saved_available: false,
                keys_available: false,
            });
    super::contacts_ui::render_page(
        session,
        super::contacts_ui::ContactsPageModel {
            book,
            directory: &directory,
            input,
            error,
            deleting,
            q: input.get("q").map(String::as_str).unwrap_or_default(),
            filter: input.get("filter").map(String::as_str).unwrap_or("all"),
        },
    )
}
