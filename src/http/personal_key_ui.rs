//! Personal private-key actions, distinct from contacts' public certificates.
use crate::http_support::escape_html;
use crate::openpgp_personal::PersonalState;

pub(crate) fn render(
    account: &str,
    csrf: &str,
    revision: u64,
    state: Option<&PersonalState>,
) -> String {
    let available = state.is_some();
    let installed = state.is_some_and(|value| value.installed);
    let disabled = |enabled| if enabled { "" } else { " disabled" };
    let status = match state {
        None => "Personal-key access is unavailable. Your key and signing permission could not be checked.".into(),
        Some(value) if !value.installed => "No personal private key installed.".into(),
        Some(value) if value.unlocked_for_session => match value.valid_until {
            Some(until) => format!(
                "Signing access permitted until {} for this browser session.",
                crate::logging::format_unix_timestamp_utc(until)
                    .replace('T', " ").replace('Z', " UTC")
            ),
            None => "Signing permission could not be confirmed. Unlock your personal key again.".into(),
        },
        Some(_) => "Personal key installed. Signing access is locked for this browser session.".into(),
    };
    let remembered = state.and_then(|value| value.remembered_until).map(|until| format!("<p>Key access remembered on this browser until {}. The deadline does not extend when you sign in or use your key. Sign out clears remembered access. A key-service restart requires unlocking again. Restarting the web service clears remembered sign-in restoration.</p>", escape_html(&crate::logging::format_unix_timestamp_utc(until).replace('T', " ").replace('Z', " UTC")))).unwrap_or_default();
    let key_details = state.map(|value| {
        let protection = if !value.installed {
            "Import the matching private key for this configured account fingerprint. Import does not replace an existing key or change your account key."
        } else if value.protected_at_rest {
            "Your imported private key retains its passphrase protection."
        } else {
            "Not all stored private-key material is passphrase-protected. OSMAP restricts access to its private storage."
        };
        format!(
            "<dl><dt>Personal key fingerprint</dt><dd><code>{}</code></dd></dl><p>{protection}</p>",
            escape_html(&value.primary_fingerprint)
        )
    }).unwrap_or_default();
    let fields = |action: &str| {
        format!(
        "<input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"binding_revision\" value=\"{revision}\"><input type=\"hidden\" name=\"key_action\" value=\"{action}\">",
        escape_html(csrf)
    )
    };
    let unlock_required = state.is_some_and(|value| value.installed && value.protected_at_rest);
    format!(
        concat!(
            "<section id=\"personal-key\" class=\"key-management-card personal-key-panel\" aria-labelledby=\"personal-key-heading\">",
            "<h2 id=\"personal-key-heading\">Your personal key</h2><p>For <strong>{account}</strong>. Use your own private key to sign and decrypt mail. Contacts’ public keys are managed separately below.</p>",
            "<p class=\"key-account-state\" data-personal-key-status>{status}</p>{remembered}{key_details}",
            "<p>Your personal key is stored on this OSMAP server. Signing and decryption happen here and are checked again when used; access permission does not guarantee that an operation will succeed.</p>",
            "<details{import_open}><summary>Import your personal private key</summary>",
            "<p>Choose the matching private-key .asc file for the configured fingerprint, not a contact’s public key. Import does not replace an existing key or change your account key. Passphrase-protected keys keep their protection. Keys supplied without passphrase protection are stored with restricted access.</p>",
            "<form method=\"post\" action=\"/settings/keys/change\" enctype=\"multipart/form-data\">{import_fields}<fieldset{import_disabled}><legend>Import your personal private key</legend>",
            "<label for=\"personal-key-file\">Private-key file (.asc)</label><input id=\"personal-key-file\" type=\"file\" name=\"personal_certificate\" accept=\".asc,application/pgp-keys\" required>",
            "<label for=\"personal-import-passphrase\">Key passphrase (if your key has one)</label><input id=\"personal-import-passphrase\" type=\"password\" name=\"key_passphrase\" autocomplete=\"off\" spellcheck=\"false\">",
            "<label for=\"personal-current-password\">Current mailbox password</label><input id=\"personal-current-password\" type=\"password\" name=\"current_password\" autocomplete=\"current-password\" required>",
            "<label for=\"personal-import-totp\">Fresh authenticator code</label><input id=\"personal-import-totp\" type=\"text\" name=\"totp_code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" pattern=\"[0-9]{{6}}\" maxlength=\"6\" required>",
            "<button type=\"submit\">Import personal key</button></fieldset></form></details>",
            "<details{unlock_open}><summary>Unlock your personal key</summary><p>Enter your key passphrase to permit signing and decryption for this browser session. Leave it empty only if your imported key has no passphrase. Unlocking ends earlier personal-key permissions for this account.</p>",
            "<form method=\"post\" action=\"/settings/keys/change\">{unlock_fields}<fieldset{unlock_disabled}><legend>Unlock personal-key access</legend>",
            "<label for=\"personal-unlock-passphrase\">Key passphrase</label><input id=\"personal-unlock-passphrase\" type=\"password\" name=\"key_passphrase\" autocomplete=\"off\" spellcheck=\"false\"{unlock_required}>",
            "<label class=\"personal-key-remember\" for=\"remember-personal-key\"><input id=\"remember-personal-key\" type=\"checkbox\" name=\"remember_key\" value=\"1\"> Remember key access on this browser for eight hours</label><p>Optional. Use only on your own device. New sign-ins still require your email, password and TOTP. The original eight-hour deadline stays fixed; ordinary Sign out clears remembered access. Your passphrase is not saved in this browser.</p>",
            "<button type=\"submit\">Unlock personal key</button></fieldset></form></details>",
            "<form method=\"post\" action=\"/settings/keys/change\">{lock_fields}<fieldset{lock_disabled}><legend>Lock personal-key access</legend>",
            "<p>Lock signing and decryption access for all OSMAP browser sessions for this account.</p><button type=\"submit\">Lock this account’s personal key</button></fieldset></form>",
            "</section>"
        ),
        account = escape_html(account), status = escape_html(&status), key_details = key_details, remembered = remembered,
        import_fields = fields("import_personal"), import_disabled = disabled(available && !installed),
        import_open = if available && !installed { " open" } else { "" },
        unlock_fields = fields("unlock_personal"), unlock_disabled = disabled(installed),
        unlock_open = if installed { " open" } else { "" },
        unlock_required = if unlock_required { " required" } else { "" },
        lock_fields = fields("lock_personal"), lock_disabled = disabled(installed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> PersonalState {
        PersonalState {
            primary_fingerprint: "A".repeat(40),
            private_revision: "private-revision-not-for-display".into(),
            installed: true,
            protected_at_rest: true,
            unlocked_for_session: false,
            valid_until: None,
            cache_seconds: 28800,
            remembered_until: None,
        }
    }

    fn form<'a>(html: &'a str, action: &str) -> &'a str {
        html.split("<form ")
            .find_map(|part| {
                let form = part.split_once("</form>")?.0;
                form.contains(&format!("value=\"{action}\""))
                    .then_some(form)
            })
            .unwrap()
    }

    #[test]
    fn unavailable_personal_capability_disables_all_actions_without_readiness_claim() {
        let html = render("alice@example.test", "csrf", 7, None);
        assert!(html.contains("Personal-key access is unavailable"));
        assert_eq!(html.matches("<fieldset disabled>").count(), 3);
        assert!(!html.contains("Signing access permitted"));
        assert!(!html.contains("No personal private key installed"));
    }

    #[test]
    fn missing_private_key_allows_import_and_keeps_unlock_and_lock_disabled() {
        let mut value = state();
        value.installed = false;
        let html = render("alice@example.test", "csrf", 7, Some(&value));
        assert!(html.contains("No personal private key installed"));
        assert!(!form(&html, "import_personal").contains("<fieldset disabled>"));
        for action in ["unlock_personal", "lock_personal"] {
            assert!(form(&html, action).contains("<fieldset disabled>"));
        }
        assert!(html.contains(&value.primary_fingerprint));
        assert!(html
            .contains("Import the matching private key for this configured account fingerprint"));
        assert!(html.contains("Import does not replace an existing key or change your account key"));
    }

    #[test]
    fn personal_import_is_file_only_with_stepup_and_other_actions_are_not() {
        let html = render("alice@example.test", "csrf", 7, Some(&state()));
        let import = form(&html, "import_personal");
        assert!(import.contains("<fieldset disabled>"));
        assert!(import.contains("enctype=\"multipart/form-data\""));
        assert!(import.contains("type=\"file\" name=\"personal_certificate\""));
        assert!(import.contains("name=\"current_password\""));
        assert!(import.contains("name=\"totp_code\""));
        assert!(!import.contains("<textarea"));
        for action in ["unlock_personal", "lock_personal"] {
            let form = form(&html, action);
            assert!(!form.contains("enctype="));
            assert!(!form.contains("name=\"current_password\""));
            assert!(!form.contains("name=\"totp_code\""));
            assert!(!form.contains("type=\"file\""));
        }
        assert!(form(&html, "unlock_personal").contains("name=\"key_passphrase\""));
        assert!(!form(&html, "lock_personal").contains("type=\"password\""));
    }

    #[test]
    fn session_permission_and_protection_are_explicit_without_crypto_success_claims() {
        let mut value = state();
        let locked = render("alice@example.test", "csrf", 7, Some(&value));
        assert!(locked.contains("Signing access is locked for this browser session"));
        value.unlocked_for_session = true;
        value.valid_until = Some(1704067200);
        value.protected_at_rest = false;
        let permitted = render("alice@example.test", "csrf", 7, Some(&value));
        assert!(permitted.contains("Signing access permitted until 2024-01-01 00:00:00 UTC"));
        assert!(permitted.contains("Not all stored private-key material is passphrase-protected"));
        assert!(permitted.contains("access permission does not guarantee"));
        assert!(permitted.contains("all OSMAP browser sessions for this account"));
        value.valid_until = None;
        let unknown = render("alice@example.test", "csrf", 7, Some(&value));
        assert!(unknown.contains("Signing permission could not be confirmed"));
        assert!(!unknown.contains("Signing access permitted"));
    }
    #[test]
    fn remembering_is_opt_in_and_original_deadline_and_logout_are_visible() {
        let mut value = state();
        value.unlocked_for_session = true;
        value.valid_until = Some(1704067200);
        value.remembered_until = Some(1704067300);
        let html = render("alice@example.test", "csrf", 7, Some(&value));
        let input = html
            .split("id=\"remember-personal-key\"")
            .nth(1)
            .unwrap()
            .split('>')
            .next()
            .unwrap();
        assert!(!input.contains("checked"));
        assert!(html.contains("Remember key access on this browser for eight hours"));
        assert!(
            html.contains("Key access remembered on this browser until 2024-01-01 00:01:40 UTC")
        );
        assert!(html.contains("Sign out clears remembered access"));
        assert!(html.contains("email, password and TOTP"));
    }

    #[test]
    fn account_fingerprint_and_csrf_are_escaped_and_secret_fields_never_refilled() {
        let mut value = state();
        value.primary_fingerprint = "<script>fingerprint</script>".into();
        let html = render("<img src=x onerror=alert(1)>", "csrf\"<&", 42, Some(&value));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<img src="));
        assert!(html.contains("&lt;script&gt;fingerprint&lt;/script&gt;"));
        assert_eq!(
            html.matches("name=\"binding_revision\" value=\"42\"")
                .count(),
            3
        );
        assert!(!html.contains(&value.private_revision));
        for input in html.split("<input ").skip(1) {
            let tag = input.split_once('>').unwrap().0;
            if tag.contains("type=\"password\"")
                || tag.contains("type=\"file\"")
                || tag.contains("name=\"totp_code\"")
            {
                assert!(!tag.contains("value="));
            }
            if tag.contains("name=\"key_passphrase\"") {
                assert!(tag.contains("autocomplete=\"off\""));
            }
        }
    }
}
