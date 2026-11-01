//! Account-owned contacts and imported public-key recipients, listed together.
use std::collections::BTreeMap;

use crate::contacts::{ContactBook, ContactDirectory, ContactError, DirectoryEncryption};
use crate::html::TrustedHtml;
use crate::http_support::{escape_html, url_encode};
use crate::openpgp_bindings::KeyStatus;
use crate::session::ValidatedSession;

pub(crate) struct ContactsPageModel<'a> {
    pub book: Option<&'a ContactBook>,
    pub directory: &'a ContactDirectory,
    pub input: &'a BTreeMap<String, String>,
    pub error: Option<ContactError>,
    pub deleting: bool,
    pub q: &'a str,
    pub filter: &'a str,
}

fn error_copy(error: ContactError) -> &'static str {
    match error {
        ContactError::Invalid => "Check the name and enter one valid email address.",
        ContactError::NotFound => "This saved contact is no longer available. Reload contacts.",
        ContactError::Duplicate => "This email address is already saved in your contacts.",
        ContactError::Quota => {
            "Your saved contacts are full. Remove a saved contact before adding another."
        }
        ContactError::Stale => "This contact changed. Reload before saving again.",
        ContactError::Busy => "Another contact change is in progress. Your change was not saved.",
        ContactError::Unavailable => {
            "Saved contacts could not be read or saved. Reload to check the current state."
        }
    }
}

fn policy_label(policy: DirectoryEncryption) -> &'static str {
    match policy {
        DirectoryEncryption::OffByDefault => "Off by default",
        DirectoryEncryption::Required => "Require encryption",
        DirectoryEncryption::Disabled => "Do not encrypt",
        DirectoryEncryption::Conflict => "Policies conflict",
        DirectoryEncryption::Unavailable => "Unavailable",
    }
}

fn key_label(status: Option<KeyStatus>, keys_available: bool) -> &'static str {
    match status {
        Some(KeyStatus::Ready) => "Public key available",
        Some(KeyStatus::MissingBinding) | None if keys_available => "No matching public key",
        Some(KeyStatus::MissingBinding | KeyStatus::InventoryUnavailable) | None => {
            "Public keys unavailable"
        }
        Some(KeyStatus::MissingKey) => "Public key missing",
        Some(KeyStatus::Revoked) => "Public key revoked",
        Some(KeyStatus::Expired) => "Public key expired",
        Some(KeyStatus::Invalid) => "Public key unavailable",
        Some(KeyStatus::Unsupported) => "Unsupported public key",
        Some(KeyStatus::WrongUsage) => "Key cannot encrypt",
        Some(KeyStatus::Ambiguous) => "Choose a public key",
    }
}

pub(crate) fn render_page(session: &ValidatedSession, model: ContactsPageModel<'_>) -> TrustedHtml {
    let account = &session.record.canonical_username;
    let book = model
        .book
        .filter(|book| book.ensure_account(account).is_ok());
    let saved_available = model.directory.saved_available && book.is_some();
    let value = |name: &str| model.input.get(name).map(String::as_str).unwrap_or("");
    let id = value("id");
    let revision = value("revision")
        .parse::<u64>()
        .ok()
        .filter(|revision| revision.to_string() == value("revision"))
        .unwrap_or_else(|| book.map(|book| book.revision).unwrap_or(0));
    let filter = match model.filter {
        "saved" => "saved",
        "keys" => "keys",
        _ => "all",
    };
    let query = model.q.trim().to_lowercase();
    let all = &model.directory.entries;
    let saved_count = all.iter().filter(|entry| entry.saved_id.is_some()).count();
    let imported_count = all.iter().filter(|entry| entry.imported).count();
    let mut rows = String::new();
    let mut shown = 0;
    for entry in all
        .iter()
        .filter(|entry| match filter {
            "saved" => entry.saved_id.is_some(),
            "keys" => entry.imported,
            _ => true,
        })
        .filter(|entry| {
            query.is_empty()
                || entry.display_name.to_lowercase().contains(&query)
                || entry.address.to_lowercase().contains(&query)
        })
    {
        shown += 1;
        let saved = entry.saved_id.as_deref().filter(|id| {
            book.is_some_and(|book| {
                book.contacts.iter().any(|contact| {
                    contact.id == *id
                        && crate::mail_address::comparison_key(&contact.address)
                            == crate::mail_address::comparison_key(&entry.address)
                })
            })
        });
        let source = match (saved.is_some(), entry.imported) {
            (true, true) => "Saved contact · Imported public key",
            (true, false) => "Saved contact",
            (false, true) => "Imported public key",
            (false, false) => "Contact",
        };
        let name = if entry.display_name.is_empty() {
            "Not provided"
        } else {
            &entry.display_name
        };
        let initial = entry
            .display_name
            .chars()
            .find(|ch| ch.is_alphanumeric())
            .map(|ch| ch.to_uppercase().to_string())
            .unwrap_or_else(|| "@".into());
        let write = if let Some(saved_id) = saved {
            Some(format!(
                "/compose?contact_id={}&amp;contact_revision={}",
                url_encode(saved_id),
                book.map(|book| book.revision).unwrap_or(0)
            ))
        } else {
            entry
                .imported_id
                .as_ref()
                .map(|id| format!("/compose?contact_id={}", url_encode(id)))
        };
        let mut actions = write.map(|href| format!("<a class=\"button-link contact-write\" href=\"{href}\" aria-label=\"Write to {}\">Write</a>", escape_html(&entry.address)))
            .unwrap_or_else(|| "<button type=\"button\" disabled title=\"Choose an available recipient in Manage keys\">Write</button>".into());
        if let Some(saved_id) = saved {
            let saved_revision = book.map(|book| book.revision).unwrap_or(0);
            actions.push_str(&format!("<a href=\"/contacts?edit={}&amp;revision={}#contact-editor\" aria-label=\"Edit {}\">Edit</a><a href=\"/contacts?delete={}&amp;revision={}#contact-editor\" aria-label=\"Remove {}\">Remove</a>", url_encode(saved_id), saved_revision, escape_html(&entry.address), url_encode(saved_id), saved_revision, escape_html(&entry.address)));
        } else if saved_available {
            if let Some(imported_id) = &entry.imported_id {
                actions.push_str(&format!("<a href=\"/contacts?new=1&amp;from_key={}#contact-editor\" aria-label=\"Add a name for {}\">Add name</a>", url_encode(imported_id), escape_html(&entry.address)));
            }
        }
        let key_management = if entry.imported || entry.key_status.is_some() {
            "<a class=\"contact-key-link\" href=\"/settings/keys\">Manage keys and policy</a>"
        } else {
            ""
        };
        rows.push_str(&format!(concat!(
            "<tr><td data-label=\"Name\"><div class=\"contact-person\"><span class=\"contact-avatar\" aria-hidden=\"true\">{}</span><div><strong dir=\"auto\">{}</strong><span class=\"contact-source\">{}</span></div></div></td>",
            "<td data-label=\"Email address\"><span dir=\"auto\">{}</span></td>",
            "<td data-label=\"Encryption policy\"><strong class=\"contact-policy\">{}</strong><span class=\"contact-key-state\">{}</span>{}</td>",
            "<td data-label=\"Actions\"><div class=\"contact-row-actions\">{}</div></td></tr>"
        ), escape_html(&initial), escape_html(name), source, escape_html(&entry.address), policy_label(entry.encryption), key_label(entry.key_status, model.directory.keys_available), key_management, actions));
    }
    let empty = if shown > 0 {
        String::new()
    } else {
        let message = if !model.q.trim().is_empty() || filter != "all" {
            "No contacts match this search or filter."
        } else if !saved_available && !model.directory.keys_available {
            "Contacts are unavailable. Reload to try again."
        } else {
            "No contacts yet. Save a contact or import a public key to get started."
        };
        format!("<p class=\"contacts-empty\" role=\"status\">{message}</p>")
    };
    let mut source_notices = String::new();
    if !saved_available {
        source_notices.push_str("<p class=\"contacts-source-notice\">Saved contacts are unavailable. Imported-key recipients can still be used when listed.</p>");
    }
    if !model.directory.keys_available {
        source_notices.push_str("<p class=\"contacts-source-notice\">Public keys are unavailable. Saved contacts can still be used when listed.</p>");
    }
    let error = model
        .error
        .map(|error| {
            format!(
                "<p class=\"notice notice-error\" role=\"alert\">{}</p>",
                error_copy(error)
            )
        })
        .unwrap_or_default();
    let new_contact = if saved_available {
        "<a class=\"button-link\" href=\"/contacts?new=1#contact-editor\">New contact</a>"
    } else {
        "<button type=\"button\" disabled>New contact</button>"
    };
    let clear = if !model.q.trim().is_empty() || filter != "all" {
        "<a href=\"/contacts\">Clear search and filters</a>"
    } else {
        ""
    };
    let options = [
        ("all", "All contacts", all.len()),
        ("saved", "Saved contacts", saved_count),
        ("keys", "Imported keys", imported_count),
    ]
    .into_iter()
    .map(|(value, label, count)| {
        format!(
            "<option value=\"{value}\"{}>{label} ({count})</option>",
            if filter == value { " selected" } else { "" }
        )
    })
    .collect::<String>();
    let open = model.error.is_some() || model.deleting || !id.is_empty() || value("new") == "1";
    let form_title = if model.deleting {
        "Remove saved contact?"
    } else if id.is_empty() {
        "New contact"
    } else {
        "Edit contact"
    };
    let fields = if model.deleting {
        format!("<h2 id=\"contact-delete-title\">Remove saved contact?</h2><p dir=\"auto\"><strong>{}</strong> &lt;{}&gt;</p><p>The imported public key, if any, will remain.</p><input type=\"hidden\" name=\"confirm\" value=\"1\"><div class=\"contact-form-actions\"><button type=\"submit\">Remove contact</button><a href=\"/contacts\">Keep contact</a></div>", escape_html(value("name")), escape_html(value("address")))
    } else {
        format!("<label for=\"contact-name\">Display name (optional)</label><input id=\"contact-name\" name=\"name\" maxlength=\"100\" autocomplete=\"name\" value=\"{}\"><label for=\"contact-address\">Email address</label><input id=\"contact-address\" name=\"address\" type=\"email\" maxlength=\"320\" autocomplete=\"off\" required value=\"{}\"><p>Imported keys appear automatically and do not need to be saved again.</p><div class=\"contact-form-actions\"><button type=\"submit\">Save contact</button><a href=\"/contacts\">Cancel</a></div>", escape_html(value("name")), escape_html(value("address")))
    };
    let editor = format!("<details id=\"contact-editor\" class=\"contacts-editor\"{}><summary>{form_title}</summary><form method=\"post\" action=\"/contacts/{}\"{}><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\"><input type=\"hidden\" name=\"id\" value=\"{}\"><fieldset{}><legend class=\"sr-only\">{form_title}</legend>{fields}</fieldset></form></details>", if open { " open" } else { "" }, if model.deleting { "delete" } else { "save" }, if model.deleting { " aria-labelledby=\"contact-delete-title\"" } else { "" }, escape_html(&session.record.csrf_token), revision, escape_html(id), if saved_available { "" } else { " disabled" });
    TrustedHtml::from_template(format!(concat!(
        "{}<main id=\"main-content\" class=\"page-shell contacts-page\" tabindex=\"-1\">",
        "<div class=\"contacts-heading\"><div><h1><svg class=\"contacts-people-icon\" viewBox=\"0 0 24 24\" aria-hidden=\"true\" focusable=\"false\"><circle cx=\"9\" cy=\"8\" r=\"3\"/><path d=\"M3 21v-3a6 6 0 0 1 12 0v3M16 5a3 3 0 0 1 0 6M18 15a5 5 0 0 1 3 5v1\"/></svg>Contacts</h1><p>People you have saved and email addresses from imported public keys.</p></div>{}</div>{}",
        "<section class=\"contacts-directory\" aria-labelledby=\"contacts-list-title\"><h2 id=\"contacts-list-title\" class=\"sr-only\">Your contacts</h2>",
        "<form class=\"contacts-search\" method=\"get\" action=\"/contacts\" role=\"search\"><div><label for=\"contacts-query\">Search contacts</label><input id=\"contacts-query\" name=\"q\" type=\"search\" value=\"{}\" maxlength=\"200\" placeholder=\"Name or email address\"></div><div><label for=\"contacts-filter\">Show</label><select id=\"contacts-filter\" name=\"filter\">{}</select></div><button type=\"submit\">Search</button>{}</form>",
        "<p class=\"contacts-count\" role=\"status\">Showing {} of {} contacts</p>{}",
        "<table class=\"contacts-table\"><caption class=\"sr-only\">Contacts, their email addresses, encryption policies and available actions</caption><thead><tr><th scope=\"col\">Name</th><th scope=\"col\">Email address</th><th scope=\"col\">Encryption policy</th><th scope=\"col\">Actions</th></tr></thead><tbody>{}</tbody></table>{}</section>{}</main>"
    ), crate::http_ui::app_header(account, &session.record.csrf_token, "contacts"), new_contact, error, escape_html(model.q), options, clear, shown, all.len(), source_notices, rows, empty, editor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::RequiredSecondFactor;
    use crate::config::LogLevel;
    use crate::logging::{EventCategory, LogEvent};
    use crate::openpgp_bindings::{BindingRecord, Requirement};
    use crate::session::SessionRecord;

    fn session() -> ValidatedSession {
        ValidatedSession {
            record: SessionRecord {
                account_epoch: None,
                session_id: "a".repeat(64),
                csrf_token: "b".repeat(64),
                canonical_username: "alice@example.test".into(),
                issued_at: 1,
                expires_at: 2000000000,
                last_seen_at: 1,
                revoked_at: None,
                remote_addr: "127.0.0.1".into(),
                user_agent: "Synthetic/Contacts".into(),
                factor: RequiredSecondFactor::Totp,
            },
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Session,
                "fixture",
                "fixture",
            ),
        }
    }
    fn book() -> ContactBook {
        serde_json::from_value(serde_json::json!({"version":1,"canonical_username":"alice@example.test","revision":7,
            "contacts":[{"id":"c".repeat(32),"display_name":"Desk <Public> & Team","address":"desk@example.test"}]})).unwrap()
    }
    fn inventory() -> crate::openpgp_inventory::Inventory {
        crate::openpgp_inventory::Inventory::parse(&serde_json::to_vec(&serde_json::json!({
            "version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.5.18",
            "keys":[{"primary":{"fingerprint":"A".repeat(40),"algorithm":1,"bits":3072,"created":1,"expires":0,
                "revoked":false,"expired":false,"disabled":false,"invalid":false,"can_sign":true,
                "can_encrypt":true,"can_certify":true,"can_authenticate":false},"subkeys":[],
                "email_addresses":["desk@example.test","key&tag@example.test"]}]
        })).unwrap()).unwrap()
    }
    fn model<'a>(
        book: Option<&'a ContactBook>,
        directory: &'a ContactDirectory,
        input: &'a BTreeMap<String, String>,
    ) -> ContactsPageModel<'a> {
        ContactsPageModel {
            book,
            directory,
            input,
            error: None,
            deleting: false,
            q: "",
            filter: "all",
        }
    }

    #[test]
    fn contacts_table_is_list_first_with_deduplicated_sources_and_owned_write_links() {
        let session = session();
        let book = book();
        let inventory = inventory();
        let bindings = BindingRecord::empty("alice@example.test").unwrap();
        let directory = ContactDirectory::from_sources(
            "alice@example.test",
            Some(&book),
            Some(&bindings),
            Some(&inventory),
            59,
        )
        .unwrap();
        let input = BTreeMap::new();
        let before = serde_json::to_vec(&book).unwrap();
        let html = render_page(&session, model(Some(&book), &directory, &input))
            .as_str()
            .to_owned();
        assert!(html.contains("<table class=\"contacts-table\"><caption"));
        assert!(html.contains("<th scope=\"col\">Encryption policy</th>"));
        assert!(html.find("<table").unwrap() < html.find("id=\"contact-editor\"").unwrap());
        assert!(!html.contains("id=\"contact-editor\" class=\"contacts-editor\" open"));
        assert!(html.contains("Desk &lt;Public&gt; &amp; Team"));
        assert!(!html.contains("Desk <Public>"));
        assert!(html.contains("Saved contact · Imported public key"));
        assert!(html.contains("Off by default"));
        assert!(html.contains("Public key available"));
        assert!(html.contains(&format!(
            "/compose?contact_id={}&amp;contact_revision=7",
            "c".repeat(32)
        )));
        assert!(html.contains("/compose?contact_id=key%3A"));
        assert!(!html.contains("/compose?to="));
        assert!(html.contains("key&amp;tag@example.test"));
        assert!(!html.contains("100 bytes"));
        assert_eq!(directory.entries.len(), 2);
        assert_eq!(serde_json::to_vec(&book).unwrap(), before);
        let imported = html
            .split("<tr>")
            .find(|row| row.contains("key&amp;tag@example.test"))
            .unwrap();
        assert!(!imported.contains(">Edit</a>"));
        assert!(!imported.contains(">Remove</a>"));
        assert!(imported.contains("/contacts?new=1&amp;from_key=key%3A"));
        assert!(imported.contains(">Add name</a>"));
        assert!(imported.contains("Not provided"));
    }

    #[test]
    fn contacts_filter_search_and_unavailable_sources_remain_truthful() {
        let session = session();
        let inventory = inventory();
        let bindings = BindingRecord::empty("alice@example.test").unwrap();
        let directory = ContactDirectory::from_sources(
            "alice@example.test",
            None,
            Some(&bindings),
            Some(&inventory),
            59,
        )
        .unwrap();
        let input = BTreeMap::new();
        let mut view = model(None, &directory, &input);
        view.q = "key&tag";
        view.filter = "keys";
        let html = render_page(&session, view).as_str().to_owned();
        assert!(html.contains("Showing 1 of 2 contacts"));
        assert!(html.contains("Saved contacts are unavailable."));
        assert!(!html.contains("Public keys are unavailable."));
        assert!(html.contains("value=\"key&amp;tag\""));
        assert!(html.contains("Clear search and filters"));
        assert!(html.contains("/compose?contact_id=key%3A"));
        let mut foreign: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&book()).unwrap()).unwrap();
        foreign["canonical_username"] = serde_json::json!("mallory@example.test");
        let foreign_book: ContactBook = serde_json::from_value(foreign).unwrap();
        let isolated = render_page(&session, model(Some(&foreign_book), &directory, &input))
            .as_str()
            .to_owned();
        assert!(!isolated.contains("Desk &lt;Public&gt; &amp; Team"));
        assert!(!isolated.contains("contact_revision=7"));
        assert!(isolated.contains("/compose?contact_id=key%3A"));
        let empty = ContactDirectory::from_sources("alice@example.test", Some(&ContactBook::empty("alice@example.test")), Some(&bindings), Some(&crate::openpgp_inventory::Inventory::parse(br#"{"version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.5.18","keys":[]}"#).unwrap()), 59).unwrap();
        let empty_book = ContactBook::empty("alice@example.test");
        assert!(
            render_page(&session, model(Some(&empty_book), &empty, &input))
                .as_str()
                .contains("No contacts yet.")
        );
        let unavailable =
            ContactDirectory::from_sources("alice@example.test", None, None, None, 59).unwrap();
        assert!(render_page(&session, model(None, &unavailable, &input))
            .as_str()
            .contains("Contacts are unavailable. Reload"));
    }

    #[test]
    fn contact_policy_and_public_key_status_are_distinct_from_private_readiness() {
        let session = session();
        let inventory = inventory();
        let mut bindings = BindingRecord::empty("alice@example.test").unwrap();
        bindings.revision = 1;
        bindings.policy.encryption = Requirement::Required;
        bindings
            .recipient_bindings
            .push(crate::openpgp_bindings::RecipientBinding {
                address: "key&tag@example.test".into(),
                primary_fingerprint: "A".repeat(40),
                encryption: Requirement::Disabled,
            });
        let directory = ContactDirectory::from_sources(
            "alice@example.test",
            None,
            Some(&bindings),
            Some(&inventory),
            59,
        )
        .unwrap();
        let html = render_page(&session, model(None, &directory, &BTreeMap::new()))
            .as_str()
            .to_owned();
        assert!(html.contains("Require encryption"));
        assert!(html.contains("Policies conflict"));
        assert!(html.contains("Public key available"));
        assert!(html.contains("Manage keys and policy"));
        assert!(!html.contains("Private key ready"));
    }

    #[test]
    fn contact_editor_opens_for_refusal_and_delete_requires_existing_confirmation_form() {
        let session = session();
        let book = book();
        let bindings = BindingRecord::empty("alice@example.test").unwrap();
        let directory = ContactDirectory::from_sources(
            "alice@example.test",
            Some(&book),
            Some(&bindings),
            None,
            59,
        )
        .unwrap();
        let input = BTreeMap::from([
            ("id".into(), "c".repeat(32)),
            ("revision".into(), "6".into()),
            ("name".into(), "<script>".into()),
            ("address".into(), "desk@example.test".into()),
        ]);
        let mut refused = model(Some(&book), &directory, &input);
        refused.error = Some(ContactError::Stale);
        let html = render_page(&session, refused).as_str().to_owned();
        assert!(html.contains("id=\"contact-editor\" class=\"contacts-editor\" open"));
        assert!(html.contains("role=\"alert\""));
        assert!(html.contains("name=\"revision\" value=\"6\""));
        assert!(html.contains("value=\"&lt;script&gt;\""));
        assert!(!html.contains("<script>"));
        let mut deleting = model(Some(&book), &directory, &input);
        deleting.deleting = true;
        let confirmation = render_page(&session, deleting).as_str().to_owned();
        assert!(confirmation
            .contains("action=\"/contacts/delete\" aria-labelledby=\"contact-delete-title\""));
        assert!(confirmation.contains("name=\"confirm\" value=\"1\""));
        assert!(confirmation.contains("name=\"csrf_token\""));
        assert!(confirmation.contains(">Keep contact</a>"));
        assert!(confirmation.contains("The imported public key, if any, will remain."));
    }
}
