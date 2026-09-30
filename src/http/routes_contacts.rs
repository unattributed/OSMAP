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
            None | Some("minimize") => return Ok(()),
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
        let expected = revision(form.get("contact_revision")).ok_or(ContactError::Invalid)?;
        let id = form.get("contact_id").ok_or(ContactError::Invalid)?;
        let book = self.contact_snapshot(session)?;
        let contact = book.selected(expected, id)?;
        let value = form.entry(target).or_default();
        let entered = crate::mail_address::parse_address_list(ComposePolicy::default(), value)
            .map_err(|_| ContactError::Invalid)?;
        if entered.iter().any(|address| {
            crate::mail_address::comparison_key(address)
                == crate::mail_address::comparison_key(&contact.address)
        }) {
            return Ok(());
        }
        if !value.trim().is_empty() {
            value.push_str(", ");
        }
        value.push_str(&contact.address);
        Ok(())
    }

    pub(super) fn handle_contacts(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(result) => result,
            Err(response) => return response,
        };
        let result = (|| {
            let query = &request.query_params;
            if query
                .keys()
                .any(|key| !["edit", "delete", "revision"].contains(&key.as_str()))
                || query.contains_key("edit") && query.contains_key("delete")
            {
                return Err(ContactError::Invalid);
            }
            let book = self.contact_snapshot(&session)?;
            let mut input = BTreeMap::new();
            if let Some(id) = query.get("edit").or_else(|| query.get("delete")) {
                let expected = revision(query.get("revision")).ok_or(ContactError::Invalid)?;
                let contact = book.selected(expected, id)?;
                input.insert("id".into(), contact.id.clone());
                input.insert("name".into(), contact.display_name.clone());
                input.insert("address".into(), contact.address.clone());
                input.insert("revision".into(), expected.to_string());
            } else if !query.is_empty() {
                return Err(ContactError::Invalid);
            }
            Ok(render_page(
                &session,
                &book,
                &input,
                None,
                query.contains_key("delete"),
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
                let body = self
                    .contact_snapshot(&session)
                    .ok()
                    .map(|book| render_page(&session, &book, &form, Some(error), deleting));
                HandledHttpResponse {
                    response: body
                        .map(|body| html_response(code, reason, "Contacts", body))
                        .unwrap_or_else(|| contact_error_page(&session, error)),
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
    book: &ContactBook,
    input: &BTreeMap<String, String>,
    error: Option<ContactError>,
    deleting: bool,
) -> TrustedHtml {
    let id = input.get("id").map(String::as_str).unwrap_or_default();
    let name = input.get("name").map(String::as_str).unwrap_or_default();
    let address = input.get("address").map(String::as_str).unwrap_or_default();
    let expected = revision(input.get("revision")).unwrap_or(book.revision);
    let mut body = format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><section class=\"content-pane\"><h1>Contacts</h1><p>Your private address shortcuts. {} of 200 entries.</p><p><a href=\"/compose\">Compose a message</a> · <a href=\"/contacts\">Reload contacts</a></p>", crate::http_ui::app_header(&session.record.canonical_username, &session.record.csrf_token, "contacts"), book.contacts.len());
    if let Some(error) = error {
        body.push_str(&format!(
            "<p class=\"notice notice-error\" role=\"alert\">{}</p>",
            escape_html(error.message())
        ));
    }
    body.push_str(&format!("<form method=\"post\" action=\"/contacts/{}\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\"><input type=\"hidden\" name=\"id\" value=\"{}\">", if deleting {"delete"} else {"save"}, escape_html(&session.record.csrf_token), expected, escape_html(id)));
    if deleting {
        body.push_str(&format!("<h2>Remove this contact?</h2><p dir=\"auto\">{} &lt;{}&gt;</p><input type=\"hidden\" name=\"confirm\" value=\"1\"><button type=\"submit\">Remove contact</button><a href=\"/contacts\">Keep contact</a>", escape_html(name), escape_html(address)));
    } else {
        body.push_str(&format!("<h2>{}</h2><label for=\"contact-name\">Display name (optional)</label><input id=\"contact-name\" name=\"name\" maxlength=\"100\" value=\"{}\"><label for=\"contact-address\">Email address</label><input id=\"contact-address\" name=\"address\" type=\"email\" maxlength=\"320\" autocomplete=\"off\" required value=\"{}\"><p class=\"muted\">Up to 100 bytes for the name; one email address per contact.</p><button type=\"submit\">Save contact</button>", if id.is_empty() {"Add contact"} else {"Edit contact"}, escape_html(name), escape_html(address)));
    }
    body.push_str("</form><h2>Saved contacts</h2>");
    if book.contacts.is_empty() {
        body.push_str("<p>No contacts saved yet.</p>");
    } else {
        body.push_str("<ul class=\"contact-list\">");
        for contact in &book.contacts {
            body.push_str(&format!("<li><p dir=\"auto\"><strong>{}</strong> &lt;{}&gt;</p><div class=\"inline-actions\"><a href=\"/contacts?edit={}&amp;revision={}\">Edit</a><a href=\"/contacts?delete={}&amp;revision={}\">Remove</a></div></li>", escape_html(&contact.display_name), escape_html(&contact.address), contact.id, book.revision, contact.id, book.revision));
        }
        body.push_str("</ul>");
    }
    body.push_str("</section></main>");
    TrustedHtml::from_template(body)
}
