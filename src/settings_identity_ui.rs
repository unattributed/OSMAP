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
    let profile_label = if model.display_name.trim().is_empty() {
        "Primary account"
    } else {
        model.display_name
    };
    TrustedHtml::from_template(format!(concat!(
        "{header}<main id=\"main-content\" class=\"page-shell settings-page settings-identity-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Settings</h1><p>Manage account display identity and reply behaviour.</p></div>{notice}<div class=\"settings-layout\">{nav}<div class=\"identity-content\"><div class=\"identity-cards\">",
        "<section class=\"identity-card\"><h2>Primary Identity</h2><form class=\"identity-form\" method=\"post\" action=\"/settings/identity\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><input type=\"hidden\" name=\"identity_revision\" value=\"{revision}\">",
        "<div class=\"identity-field\"><label for=\"identity-display-name\">Display name</label><input id=\"identity-display-name\" name=\"display_name\" value=\"{name}\" autocomplete=\"name\"{unavailable}></div>",
        "<div class=\"identity-field\"><label for=\"identity-email\">Email address</label><input id=\"identity-email\" value=\"{email}\" readonly></div>",
        "<div class=\"identity-field\"><label for=\"identity-reply-to\">Reply-to</label><input id=\"identity-reply-to\" name=\"reply_to\" value=\"{reply_to}\" autocomplete=\"email\" aria-describedby=\"identity-help\"{unavailable}></div>",
        "<div class=\"identity-field\"><label for=\"identity-signature\">Signature</label>{signature_selection}</div>",
        "<div class=\"identity-field identity-actions\"><label for=\"identity-use-new\">Use for new mail</label><div><input id=\"identity-use-new\" class=\"settings-switch\" type=\"checkbox\" role=\"switch\" checked disabled aria-describedby=\"identity-help\"><button type=\"submit\"{unavailable}>Save identity</button></div></div></form></section>",
        "<section class=\"identity-card\"><h2>Authorized Sender Identities</h2><div class=\"identity-sender\"><span class=\"identity-avatar\" aria-hidden=\"true\">{initials}</span><div><strong>{profile_label}</strong><span>{email}</span></div><span class=\"identity-primary\">Primary</span></div><p class=\"identity-unavailable\">Additional sender identities are unavailable.</p><button type=\"button\" disabled>+ Add identity</button></section></div>",
        "<div class=\"identity-authority-note\"><p>Only the canonical account address can be used as the sender. OSMAP does not permit arbitrary From addresses.</p><p id=\"identity-help\">New messages capture these preferences when first saved or submitted. Saved drafts keep their captured identity after profile changes. This fixed behaviour cannot be toggled. Blank Reply-to uses the account address.</p></div>{signature_editor}</div></div></main>"
    ), signature_selection=signature_selection, signature_editor=signature_editor, header=app_header(model.canonical_username,model.csrf_token,"settings-identity"), nav=settings_navigation("identity"), csrf=escape_html(model.csrf_token), revision=model.revision, name=escape_html(model.display_name), email=escape_html(model.canonical_username), reply_to=escape_html(model.reply_to), profile_label=escape_html(profile_label), initials=escape_html(&sender_initials(Some(profile_label))), notice=notice, unavailable=unavailable))
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
