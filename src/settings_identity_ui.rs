//! PAGE13 native account profile. Canonical sender authority is read-only.
use super::*;

pub(crate) struct IdentityPageModel<'a> {
    pub canonical_username: &'a str,
    pub csrf_token: &'a str,
    pub revision: u64,
    pub display_name: &'a str,
    pub reply_to: &'a str,
    pub error_message: Option<&'a str>,
    pub available: bool,
    pub sender_inventory: Option<&'a crate::sender_authority::Snapshot>,
    pub sender_record: Option<&'a crate::identity_preferences::IdentityPreferencesRecord>,
}

pub(crate) fn render_identity_page(model: &IdentityPageModel<'_>) -> TrustedHtml {
    render_identity_page_with_signature(model, None)
}

pub(crate) fn render_identity_page_with_signature(
    model: &IdentityPageModel<'_>,
    signature: Option<&crate::signature::SignatureRecord>,
) -> TrustedHtml {
    let signature_selection = crate::signature_ui::selection(signature, false);
    let signature_editor = crate::signature_ui::editor(model.csrf_token, signature, "identity");
    let notice = model
        .error_message
        .map(|message| {
            format!(
                "<p class=\"notice notice-error\" role=\"alert\">{} <a href=\"/settings?section=identity\">Load saved identity</a> to review the current values; this replaces the entries shown below.</p>",
                escape_html(message)
            )
        })
        .unwrap_or_default();
    let unavailable = if model.available { "" } else { " disabled" };
    let sender_controls = authorized_sender_controls(model);
    TrustedHtml::from_template(format!(concat!(
        "{header}<main id=\"main-content\" class=\"page-shell settings-page settings-identity-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Settings</h1><p>Manage account display identity and reply behaviour.</p></div>{notice}<div class=\"settings-layout\">{nav}<div class=\"identity-content\"><div class=\"identity-cards\">",
        "<section class=\"identity-card\"><h2>Primary Identity</h2><form class=\"identity-form\" method=\"post\" action=\"/settings/identity\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><input type=\"hidden\" name=\"identity_revision\" value=\"{revision}\">",
        "<div class=\"identity-field\"><label for=\"identity-display-name\">Display name</label><input id=\"identity-display-name\" name=\"display_name\" value=\"{name}\" autocomplete=\"name\"{unavailable}></div>",
        "<div class=\"identity-field\"><label for=\"identity-email\">Email address</label><input id=\"identity-email\" value=\"{email}\" readonly></div>",
        "<div class=\"identity-field\"><label for=\"identity-reply-to\">Reply-to</label><input id=\"identity-reply-to\" name=\"reply_to\" value=\"{reply_to}\" autocomplete=\"email\" aria-describedby=\"identity-help\"{unavailable}></div>",
        "<div class=\"identity-field\"><label for=\"identity-signature\">Signature</label>{signature_selection}</div>",
        "<div class=\"identity-field identity-actions\"><label for=\"identity-use-new\">Current new-mail default</label><div><input id=\"identity-use-new\" class=\"settings-switch\" type=\"checkbox\" role=\"switch\"{canonical_default} disabled aria-describedby=\"identity-help\"><button type=\"submit\"{unavailable}>Save identity</button></div></div></form></section>",
        "{sender_controls}</div>",
        "<div class=\"identity-authority-note\"><p>Sender choices come only from current server authority. OSMAP does not create aliases or permit arbitrary From addresses.</p><p id=\"identity-help\">New messages capture the saved default identity when first saved or submitted. Saved drafts keep their captured identity after profile changes. Blank Reply-to uses the captured sender address.</p></div>{signature_editor}</div></div></main>"
    ), signature_selection=signature_selection, signature_editor=signature_editor, header=app_header(model.canonical_username,model.csrf_token,"settings-identity"), nav=settings_navigation("identity"), csrf=escape_html(model.csrf_token), revision=model.revision, name=escape_html(model.display_name), email=escape_html(model.canonical_username), reply_to=escape_html(model.reply_to),  sender_controls=sender_controls, canonical_default=if model.sender_record.is_none_or(|record| record.primary_id() == crate::sender_authority::CANONICAL_ID) { " checked" } else { "" }, notice=notice, unavailable=unavailable))
}

fn authorized_sender_controls(model: &IdentityPageModel<'_>) -> String {
    let (Some(inventory), Some(record)) = (model.sender_inventory, model.sender_record) else {
        return "<section class=\"identity-card\"><h2>Authorized Sender Identities</h2><p class=\"identity-unavailable\">Additional sender identities are unavailable.</p><button type=\"button\" disabled>+ Add identity</button></section>".into();
    };
    if inventory.account != model.canonical_username {
        return String::new();
    }
    let mut html = format!("<section class=\"identity-card\"><h2>Authorized Sender Identities</h2><p>Choose only addresses already authorized by the mail administrator. This form does not create a server alias.</p><form id=\"sender-primary-form\" method=\"post\" action=\"/settings/sender-identity\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"sender_revision\" value=\"{}\"><input type=\"hidden\" name=\"action\" value=\"primary\"><label for=\"sender-primary-choice\">Identity for new mail</label><select id=\"sender-primary-choice\" name=\"identity_id\">", escape_html(model.csrf_token), record.revision);
    for identity in &inventory.identities {
        html.push_str(&format!(
            "<option value=\"{}\"{}>{}</option>",
            escape_html(&identity.id),
            if record.primary_id() == identity.id {
                " selected"
            } else {
                ""
            },
            escape_html(&identity.address)
        ));
    }
    html.push_str("</select><button type=\"submit\">Use for new mail</button></form>");
    if inventory.identities.len() == 1 {
        html.push_str(
            "<p>No additional sender addresses are authorized by the current server inventory.</p>",
        );
    }

    for identity in &inventory.identities {
        let registered = record.presentation(&identity.id);
        let primary = record.primary_id() == identity.id;
        html.push_str(&format!(
            "<div class=\"identity-sender\"><div><strong>{}</strong><span>{}</span></div>{}</div>",
            escape_html(
                registered
                    .map(|p| p.display_name())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("Authorized identity")
            ),
            escape_html(&identity.address),
            if primary {
                "<span class=\"identity-primary\">Primary</span>"
            } else {
                ""
            }
        ));
        if identity.id == crate::sender_authority::CANONICAL_ID {
            continue;
        }
        let fields = format!("<input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"sender_revision\" value=\"{}\"><input type=\"hidden\" name=\"identity_id\" value=\"{}\">", escape_html(model.csrf_token), record.revision, escape_html(&identity.id));
        if let Some(profile) = registered {
            html.push_str(&format!("<form class=\"identity-form\" method=\"post\" action=\"/settings/sender-identity\">{}<input type=\"hidden\" name=\"action\" value=\"edit\"><label>Display name<input name=\"display_name\" value=\"{}\"></label><label>Reply-to<input name=\"reply_to\" value=\"{}\"></label><label><input type=\"checkbox\" name=\"use_for_new\" value=\"on\"{}>Use for new mail</label><button type=\"submit\">Save identity</button></form>", fields, escape_html(profile.display_name()), escape_html(profile.reply_to().unwrap_or("")), if primary { " checked" } else { "" }));
        } else {
            html.push_str(&format!("<form method=\"post\" action=\"/settings/sender-identity\">{}<input type=\"hidden\" name=\"action\" value=\"add\"><button type=\"submit\">+ Add identity</button></form>", fields));
        }
    }
    if !inventory
        .identities
        .iter()
        .any(|i| i.id == record.primary_id())
    {
        html.push_str("<p class=\"notice notice-error\">The saved default identity is no longer authorized. Select a current authorized identity before creating new mail. Existing drafts were not retargeted.</p>");
    }
    html.push_str("</section>");
    html
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_page_preserves_literal_submissions_without_sender_authority() {
        let model = IdentityPageModel {
            canonical_username: "alice@example.test",
            csrf_token: "synthetic",
            revision: 7,
            display_name: "<script>name</script>",
            reply_to: "\"bad\" <reply>",
            error_message: Some("<invalid>"),
            available: true,
            sender_inventory: None,
            sender_record: None,
        };
        let html = render_identity_page(&model).as_str().to_owned();
        assert!(html.contains("value=\"&lt;script&gt;name&lt;/script&gt;\""));
        assert!(html.contains("&lt;invalid&gt;"));
        assert!(html.contains("name=\"identity_revision\" value=\"7\""));
        assert!(!html.contains("name=\"email\""));
        assert!(!html.contains("name=\"from\""));
        assert!(html.contains("id=\"identity-email\" value=\"alice@example.test\" readonly"));
        let disabled = IdentityPageModel {
            available: false,
            ..model
        };
        assert!(render_identity_page(&disabled)
            .as_str()
            .contains("type=\"submit\" disabled>Save identity"));
    }
}
