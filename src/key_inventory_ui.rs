//! Read-only public metadata. Public presence never supplies binding authority.
use super::*;
#[derive(Clone)]
pub(crate) enum PublicExpiry {
    Unknown,
    Never,
    At(u64),
}
#[derive(Clone)]
pub(crate) struct PublicKeyMaterialView {
    pub fingerprint: String,
    pub algorithm: String,
    pub bits: u32,
    pub created: Option<u64>,
    pub expires: PublicExpiry,
    pub revoked: bool,
    pub expired: bool,
    pub disabled: bool,
    pub invalid: bool,
    pub can_sign: bool,
    pub can_encrypt: bool,
    pub can_certify: bool,
    pub can_authenticate: bool,
}
pub(crate) struct PublicKeyView {
    pub primary: PublicKeyMaterialView,
    pub subkeys: Vec<PublicKeyMaterialView>,
}
pub(crate) enum PublicInventoryView {
    Unavailable,
    Verified {
        account: String,
        keys: Vec<PublicKeyView>,
    },
}
fn date(value: Option<u64>) -> String {
    value
        .map(|v| {
            crate::logging::format_unix_timestamp_utc(v)
                .replace('T', " ")
                .replace('Z', " UTC")
        })
        .unwrap_or_else(|| "Unknown".into())
}
fn material(key: &PublicKeyMaterialView) -> String {
    let flags = [
        (key.revoked, "Revoked"),
        (key.expired, "Expired"),
        (key.disabled, "Disabled"),
        (key.invalid, "Invalid"),
    ]
    .into_iter()
    .filter_map(|(yes, label)| yes.then_some(label))
    .collect::<Vec<_>>();
    let capabilities = [
        (key.can_sign, "Sign"),
        (key.can_encrypt, "Encrypt"),
        (key.can_certify, "Certify"),
        (key.can_authenticate, "Authenticate"),
    ]
    .into_iter()
    .filter_map(|(yes, label)| yes.then_some(label))
    .collect::<Vec<_>>();
    format!("<label>Full public fingerprint<input readonly value=\"{}\" spellcheck=\"false\" autocomplete=\"off\"></label><dl><dt>Algorithm</dt><dd>{} · {} bits</dd><dt>Created</dt><dd>{}</dd><dt>Expires</dt><dd>{}</dd><dt>Reported state</dt><dd>{}</dd><dt>Public capability flags</dt><dd>{}</dd></dl>",escape_html(&key.fingerprint),escape_html(&key.algorithm),key.bits,date(key.created),match key.expires{PublicExpiry::Unknown=>"Unknown".into(),PublicExpiry::Never=>"Does not expire".into(),PublicExpiry::At(v)=>date(Some(v))},if flags.is_empty(){"No adverse flags reported".into()}else{flags.join(", ")},if capabilities.is_empty(){"None reported".into()}else{capabilities.join(", ")})
}
#[cfg(test)]
pub(crate) fn render_key_inventory(
    account: &str,
    csrf: &str,
    inventory: &PublicInventoryView,
) -> TrustedHtml {
    let verified = match inventory {
        PublicInventoryView::Verified {
            account: owner,
            keys,
        } if owner == account => Some(keys),
        _ => None,
    };
    let mut rows = String::new();
    match verified {
  None=>rows.push_str("<p class=\"key-inventory-state\" role=\"status\">Public inventory unavailable. No conclusion about stored keys can be made.</p>"),
  Some(keys) if keys.is_empty()=>rows.push_str("<p class=\"key-inventory-state\" role=\"status\">No public keys were reported in this account’s verified inventory.</p>"),
  Some(keys)=>{for key in keys.iter().take(128) {rows.push_str(&format!("<details class=\"public-key-row\"><summary><span class=\"public-key-fingerprint\">{}</span><span>{}</span></summary><div class=\"public-key-details\">{}",escape_html(&key.primary.fingerprint),escape_html(&key.primary.algorithm),material(&key.primary)));for sub in key.subkeys.iter().take(32){rows.push_str(&format!("<h3>Public subkey</h3>{}",material(sub)));}if key.subkeys.len()>32 {rows.push_str("<p>Additional subkeys are not displayed.</p>");}rows.push_str("</div></details>");}if keys.len()>128{rows.push_str("<p>Additional keys are not displayed.</p>");}}
 }
    TrustedHtml::from_template(format!(concat!("{header}<main id=\"main-content\" class=\"page-shell key-management-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>OpenPGP Key Management</h1><p>Inspect public keys. Account bindings and key changes are unavailable.</p></div><div class=\"key-management-toolbar\"><p><a href=\"/settings?section=security\">Security</a> / <a href=\"/settings?section=openpgp\">OpenPGP</a> / Keys</p><div><button disabled>Import public key</button><button disabled>Add binding</button></div></div><div class=\"key-management-grid\"><section class=\"key-management-card\"><h2>Primary Account Key</h2><div class=\"key-account-state\"><strong>Account binding unavailable</strong><span>{account}</span></div><dl><dt>Fingerprint</dt><dd>Unavailable</dd><dt>Algorithm</dt><dd>Unknown</dd><dt>Created</dt><dd>Unknown</dd><dt>Expires</dt><dd>Unknown</dd><dt>Signing</dt><dd>Unavailable</dd><dt>Binding status</dt><dd>Unverified</dd></dl><div class=\"key-management-actions\"><button disabled>Copy fingerprint</button><button disabled>Rotate binding</button><button disabled>Remove binding</button></div></section><section class=\"key-management-card\"><h2>Public key inventory</h2>{rows}<p class=\"key-inventory-notice\">Public keys do not establish account or recipient trust, private-key availability, or signing and encryption readiness. Open a key to inspect its full fingerprint; select the field to copy using your keyboard.</p></section></div></main>"),header=app_header(account,csrf,"security"),account=escape_html(account),rows=rows))
}
#[cfg(test)]
mod tests {
    use super::*;
    pub(crate) fn fixture(mode: &str, account: &str) -> PublicInventoryView {
        if mode == "KeyInventoryUnavailable" {
            return PublicInventoryView::Unavailable;
        }
        let material = PublicKeyMaterialView {
            fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567".into(),
            algorithm: "RSA".into(),
            bits: 3072,
            created: Some(1704067200),
            expires: PublicExpiry::Never,
            revoked: false,
            expired: false,
            disabled: false,
            invalid: false,
            can_sign: true,
            can_encrypt: false,
            can_certify: true,
            can_authenticate: false,
        };
        PublicInventoryView::Verified {
            account: if mode == "KeyInventoryForeign" {
                "bob@example.com"
            } else {
                account
            }
            .into(),
            keys: if mode == "KeyInventoryEmpty" {
                vec![]
            } else {
                vec![PublicKeyView {
                    primary: material.clone(),
                    subkeys: vec![PublicKeyMaterialView {
                        fingerprint: "89ABCDEF0123456789ABCDEF0123456789ABCDEF".into(),
                        expires: PublicExpiry::At(1800000000),
                        can_sign: false,
                        can_encrypt: true,
                        ..material
                    }],
                }]
            },
        }
    }
    #[test]
    fn public_inventory_owner_and_empty_are_distinct() {
        let body = render_key_inventory(
            "alice@example.com",
            "test",
            &fixture("KeyInventoryForeign", "alice@example.com"),
        )
        .as_str()
        .to_owned();
        assert!(!body.contains("0123456789ABCDEF"));
        assert!(body.contains("Public inventory unavailable"));
        let body = render_key_inventory(
            "alice@example.com",
            "test",
            &fixture("KeyInventoryEmpty", "alice@example.com"),
        )
        .as_str()
        .to_owned();
        assert!(body.contains("No public keys were reported"));
    }
}

fn algorithm(value: u32) -> String {
    match value {
        1 => "RSA",
        2 => "RSA (encryption)",
        3 => "RSA (signing)",
        8 => "Kyber",
        16 => "ElGamal (encryption)",
        17 => "DSA",
        18 => "ECC",
        20 => "ElGamal",
        301 => "ECDSA",
        302 => "ECDH",
        303 => "EdDSA",
        _ => return format!("Unsupported algorithm ({value})"),
    }
    .into()
}
fn expiry(value: Option<u64>) -> PublicExpiry {
    match value {
        None => PublicExpiry::Unknown,
        Some(0) => PublicExpiry::Never,
        Some(v) => PublicExpiry::At(v),
    }
}
fn map_material(value: &crate::openpgp_inventory::KeyMaterial) -> PublicKeyMaterialView {
    PublicKeyMaterialView {
        fingerprint: value.fingerprint.clone(),
        algorithm: algorithm(value.algorithm),
        bits: value.bits,
        created: (value.created != 0).then_some(value.created),
        expires: expiry(Some(value.expires)),
        revoked: value.revoked,
        expired: value.expired,
        disabled: value.disabled,
        invalid: value.invalid,
        can_sign: value.can_sign,
        can_encrypt: value.can_encrypt,
        can_certify: value.can_certify,
        can_authenticate: value.can_authenticate,
    }
}
pub(crate) fn map_public_inventory(
    authenticated_account: &str,
    returned_account: &str,
    inventory: Option<&crate::openpgp_inventory::Inventory>,
) -> PublicInventoryView {
    if authenticated_account != returned_account {
        return PublicInventoryView::Unavailable;
    }
    match inventory.and_then(crate::openpgp_inventory::Inventory::keys) {
        None => PublicInventoryView::Unavailable,
        Some(keys) => PublicInventoryView::Verified {
            account: authenticated_account.into(),
            keys: keys
                .iter()
                .map(|k| PublicKeyView {
                    primary: map_material(&k.primary),
                    subkeys: k.subkeys.iter().map(map_material).collect(),
                })
                .collect(),
        },
    }
}
#[cfg(test)]
mod adapter_tests {
    use super::*;
    fn parsed(keys: serde_json::Value) -> crate::openpgp_inventory::Inventory {
        crate::openpgp_inventory::Inventory::parse(&serde_json::to_vec(&serde_json::json!({"version":1,"ok":true,"protocol":"openpgp","gpgme_version":"1.24.0","engine_version":"2.4.8","keys":keys})).unwrap()).unwrap()
    }
    #[test]
    fn adapter_owner_empty_unavailable_and_metadata() {
        let empty = parsed(serde_json::json!([]));
        assert!(matches!(
            map_public_inventory("alice@example.com", "bob@example.com", Some(&empty)),
            PublicInventoryView::Unavailable
        ));
        assert!(
            matches!(map_public_inventory("alice@example.com","alice@example.com",Some(&empty)),PublicInventoryView::Verified{keys,..} if keys.is_empty())
        );
        let unavailable = crate::openpgp_inventory::Inventory::parse(
            br#"{"version":1,"ok":false,"error":"inventory_unavailable"}"#,
        )
        .unwrap();
        assert!(matches!(
            map_public_inventory("alice@example.com", "alice@example.com", Some(&unavailable)),
            PublicInventoryView::Unavailable
        ));
        let inventory = parsed(
            serde_json::json!([{"primary":{"fingerprint":"0123456789ABCDEF0123456789ABCDEF01234567","algorithm":1,"bits":3072,"created":0,"expires":0,"revoked":false,"expired":true,"disabled":false,"invalid":true,"can_sign":true,"can_encrypt":false,"can_certify":true,"can_authenticate":false},"subkeys":[]}]),
        );
        let mapped =
            map_public_inventory("alice@example.com", "alice@example.com", Some(&inventory));
        let html = render_key_inventory("alice@example.com", "test", &mapped);
        assert!(html.as_str().contains("Expired, Invalid"));
        assert!(html.as_str().contains("RSA · 3072 bits"));
        assert!(html.as_str().contains("<dt>Created</dt><dd>Unknown</dd>"));
        assert!(html
            .as_str()
            .contains("<dt>Expires</dt><dd>Does not expire</dd>"));
        assert!(html.as_str().contains("Sign, Certify"));
        assert_eq!(algorithm(999), "Unsupported algorithm (999)");
        assert_eq!(date(Some(1704067200)), "2024-01-01 00:00:00 UTC");
    }
}

fn requirement_label(value: crate::openpgp_bindings::Requirement) -> &'static str {
    use crate::openpgp_bindings::Requirement::*;
    match value {
        Required => "required",
        Optional => "optional",
        Disabled => "disabled",
    }
}
fn requirement_select(name: &str, selected: crate::openpgp_bindings::Requirement) -> String {
    format!(
        "<select name=\"{}\">{}</select>",
        escape_html(name),
        ["optional", "required", "disabled"]
            .into_iter()
            .map(|v| format!(
                "<option value=\"{v}\"{}>{v}</option>",
                if v == requirement_label(selected) {
                    " selected"
                } else {
                    ""
                }
            ))
            .collect::<String>()
    )
}
fn binding_form(
    csrf: &str,
    revision: u64,
    action: &str,
    fields: &str,
    label: &str,
    available: bool,
) -> String {
    format!(concat!("<form method=\"post\" action=\"/settings/keys/change\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"binding_revision\" value=\"{}\"><input type=\"hidden\" name=\"key_action\" value=\"{}\"><fieldset{}>{}<label>Current mailbox password<input type=\"password\" name=\"current_password\" autocomplete=\"current-password\" required maxlength=\"1024\"></label><label>Fresh authenticator code<input name=\"totp_code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" pattern=\"[0-9]{{6}}\" maxlength=\"6\" required></label><button type=\"submit\">{}</button></fieldset></form>"),escape_html(csrf),revision,escape_html(action),if available{""}else{" disabled"},fields,escape_html(label))
}
fn fingerprint_input(name: &str, label: &str, value: &str, required: bool) -> String {
    format!("<label>{}<input name=\"{}\" value=\"{}\" maxlength=\"40\" pattern=\"[A-Fa-f0-9]{{40}}\" autocomplete=\"off\" spellcheck=\"false\"{}></label>",escape_html(label),escape_html(name),escape_html(value),if required{" required"}else{""})
}
fn inventoried_key_select(
    name: &str,
    label: &str,
    selected: &str,
    fingerprints: impl Iterator<Item = String>,
    required: bool,
) -> String {
    let choices = fingerprints.collect::<std::collections::BTreeSet<_>>();
    let mut options = format!(
        "<option value=\"\"{}>{}</option>",
        if selected.is_empty() { " selected" } else { "" },
        if required {
            "Choose an imported public key"
        } else {
            "No signing key selected"
        },
    );
    if !selected.is_empty() && !choices.contains(selected) {
        options.push_str(&format!(
            "<option value=\"{}\" selected>Current binding: {} (unavailable)</option>",
            escape_html(selected),
            escape_html(selected)
        ));
    }
    for fingerprint in choices {
        options.push_str(&format!(
            "<option value=\"{}\"{}>{}</option>",
            escape_html(&fingerprint),
            if fingerprint == selected {
                " selected"
            } else {
                ""
            },
            escape_html(&fingerprint)
        ));
    }
    format!(
        "<label>{}<select name=\"{}\"{}>{options}</select></label>",
        escape_html(label),
        escape_html(name),
        if required { " required" } else { "" }
    )
}
fn key_status(status: crate::openpgp_bindings::KeyStatus) -> &'static str {
    use crate::openpgp_bindings::KeyStatus::*;
    match status {
        Ready => "Ready public key",
        MissingBinding => "Missing binding",
        InventoryUnavailable => "Unavailable",
        MissingKey => "Missing public key",
        Revoked => "Revoked",
        Expired => "Expired",
        Invalid => "Invalid",
        Unsupported => "Unsupported",
        WrongUsage => "Wrong usage",
        Ambiguous => "Ambiguous",
    }
}
/// PAGE21 actual trusted binding state. Public presence never creates a binding.
#[cfg(test)]
pub(crate) fn render_key_management(
    account: &str,
    csrf: &str,
    state: &crate::key_management::State,
    error: Option<&str>,
) -> TrustedHtml {
    render_key_management_panel(account, csrf, state, error, None)
}

pub(crate) fn render_key_management_panel(
    account: &str,
    csrf: &str,
    state: &crate::key_management::State,
    error: Option<&str>,
    panel: Option<&str>,
) -> TrustedHtml {
    let opened = |name| if panel == Some(name) { " open" } else { "" };
    let owned = state.canonical_username == account;
    let record = owned
        .then_some(state.bindings.as_ref())
        .flatten()
        .filter(|r| r.ensure_account(account).is_ok());
    let inventory = map_public_inventory(
        account,
        &state.canonical_username,
        owned.then_some(state.inventory.as_ref()).flatten(),
    );
    let ready = owned
        && state.binding_changes_available
        && record.is_some()
        && matches!(inventory, PublicInventoryView::Verified { .. });
    let public_revision = state.public_inventory_revision.as_deref().filter(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    let public_ready = ready && state.public_key_changes_available && public_revision.is_some();
    let public_revision_field = public_revision
        .map(|value| {
            format!(
                "<input type=\"hidden\" name=\"public_inventory_revision\" value=\"{}\">",
                value
            )
        })
        .unwrap_or_default();
    let revision = record.map(|r| r.revision).unwrap_or(0);
    let bound = record.and_then(|r| r.account_binding.as_ref());
    let keys: &[PublicKeyView] = match &inventory {
        PublicInventoryView::Verified { keys, .. } => keys,
        _ => &[],
    };
    let usable =
        |key: &PublicKeyMaterialView| !key.revoked && !key.expired && !key.disabled && !key.invalid;
    let primary = inventoried_key_select(
        "primary_fingerprint",
        "Full account primary fingerprint",
        bound.map(|b| b.primary_fingerprint.as_str()).unwrap_or(""),
        keys.iter()
            .filter(|key| usable(&key.primary))
            .map(|key| key.primary.fingerprint.clone()),
        true,
    );
    let signing = inventoried_key_select(
        "signing_fingerprint",
        "Full signing primary or subkey fingerprint (optional)",
        bound
            .and_then(|b| b.signing_fingerprint.as_deref())
            .unwrap_or(""),
        keys.iter()
            .filter(|key| usable(&key.primary))
            .flat_map(|key| std::iter::once(&key.primary).chain(key.subkeys.iter()))
            .filter(|key| usable(key) && key.can_sign)
            .map(|key| key.fingerprint.clone()),
        false,
    );
    let account_fields=format!("{primary}{signing}<label>Decrypt primary fingerprints (comma separated)<input name=\"decrypt_fingerprints\" value=\"{}\" autocomplete=\"off\" spellcheck=\"false\" maxlength=\"327\"></label><p>Choose from imported public keys, then confirm the full fingerprints before saving. This does not import or unlock a private key.</p>",escape_html(&bound.map(|b|b.decrypt_primary_fingerprints.join(",")).unwrap_or_default()));
    let account_form = binding_form(
        csrf,
        revision,
        "set_account",
        &account_fields,
        "Save account binding",
        ready,
    );
    let clear = if bound.is_some() {
        binding_form(
            csrf,
            revision,
            "clear_account",
            "",
            "Remove account binding",
            ready,
        )
    } else {
        String::new()
    };
    let account_key = match &inventory {
        PublicInventoryView::Verified { keys, .. } => bound.and_then(|b| {
            keys.iter()
                .find(|k| k.primary.fingerprint == b.primary_fingerprint)
        }),
        _ => None,
    };
    let addresses = record
        .map(|r| {
            r.recipient_bindings
                .iter()
                .map(|b| b.address.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let assessment = record
        .zip(state.inventory.as_ref().filter(|_| owned))
        .and_then(|(r, i)| {
            crate::openpgp_bindings::evaluate(
                account,
                r,
                i,
                crate::openpgp_bindings::Recipients {
                    to: &addresses,
                    cc: &[],
                    bcc: &[],
                },
                crate::openpgp_bindings::Selections::default(),
                crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider),
            )
            .ok()
        });
    let overview = if let Some(b) = bound {
        let metadata=account_key.map(|k|format!("<dt>Algorithm</dt><dd>{} · {} bits</dd><dt>Created</dt><dd>{}</dd><dt>Expires</dt><dd>{}</dd><dt>Public capabilities</dt><dd>{}</dd>",escape_html(&k.primary.algorithm),k.primary.bits,date(k.primary.created),match k.primary.expires{PublicExpiry::Unknown=>"Unknown".into(),PublicExpiry::Never=>"Does not expire".into(),PublicExpiry::At(v)=>date(Some(v))},[(k.primary.can_sign,"Sign"),(k.primary.can_encrypt,"Encrypt")].into_iter().filter_map(|(v,l)|v.then_some(l)).collect::<Vec<_>>().join(", "))).unwrap_or_else(||"<dt>Public key metadata</dt><dd>Unavailable</dd>".into());
        format!("<div class=\"key-account-state\"><strong>Configured</strong><span>Bound to {}</span></div><dl><dt>Full fingerprint</dt><dd><input id=\"account-fingerprint\" readonly value=\"{}\" spellcheck=\"false\" autocomplete=\"off\"></dd>{}<dt>Signing public key</dt><dd>{}</dd><dt>Encryption public key</dt><dd>{}</dd><dt>Binding status</dt><dd>Confirmed account binding</dd></dl>",escape_html(account),escape_html(&b.primary_fingerprint),metadata,assessment.as_ref().map(|a|key_status(a.signing)).unwrap_or("Unavailable"),assessment.as_ref().map(|a|key_status(a.self_encryption)).unwrap_or("Unavailable"))
    } else {
        format!("<div class=\"key-account-state\"><strong>{}</strong><span>{}</span></div><dl><dt>Full fingerprint</dt><dd>Unavailable</dd><dt>Algorithm</dt><dd>Unknown</dd><dt>Created</dt><dd>Unknown</dd><dt>Expires</dt><dd>Unknown</dd><dt>Binding status</dt><dd>Unconfirmed</dd></dl>",if record.is_some(){"Not configured"}else{"Account binding unavailable"},escape_html(account))
    };
    let account_actions = if bound.is_some() {
        format!("<div class=\"key-management-actions\"><a href=\"/settings/keys?panel=account#account-binding\">Change account key</a><a href=\"#account-fingerprint\">Select fingerprint</a><a href=\"/settings/keys?panel=inventory#public-inventory\">Manage imported keys</a></div><details><summary>Remove binding</summary>{clear}</details>")
    } else {
        String::new()
    };
    let mut recipients = String::new();
    if let Some(r) = record {
        for b in &r.recipient_bindings {
            recipients.push_str(&format!("<details><summary>{} · {}</summary><p>Full primary fingerprint: <code>{}</code></p><p>Encryption: {}</p>{}</details>",escape_html(&b.address),assessment.as_ref().and_then(|a|a.recipients.iter().find(|r|r.address==b.address)).map(|r|key_status(r.state)).unwrap_or("Unavailable"),escape_html(&b.primary_fingerprint),requirement_label(b.encryption),binding_form(csrf,revision,"remove_recipient",&format!("<input type=\"hidden\" name=\"address\" value=\"{}\">",escape_html(&b.address)),"Remove recipient binding",ready)));
        }
    }
    if recipients.is_empty() {
        recipients.push_str(if record.is_some() {
            "<p>No recipient bindings are confirmed.</p>"
        } else {
            "<p>Recipient bindings unavailable.</p>"
        });
    }
    let recipient_fields=format!("<label>Exact recipient email address<input type=\"email\" name=\"address\" maxlength=\"254\" required></label>{}<label>Encryption policy{}</label>",fingerprint_input("primary_fingerprint","Full recipient primary fingerprint","",true),requirement_select("encryption",crate::openpgp_bindings::Requirement::Optional));
    let recipient_form = binding_form(
        csrf,
        revision,
        "set_recipient",
        &recipient_fields,
        "Save recipient binding",
        ready,
    );
    let policy = record.map(|r| r.policy).unwrap_or_default();
    let policy_fields = format!(
        "<label>Signing policy{}</label><label>Encryption policy{}</label>",
        requirement_select("signing", policy.signing),
        requirement_select("encryption", policy.encryption)
    );
    let cleanup=binding_form(csrf,revision,"clear_all_bindings","<p>This removes every account and recipient binding. Protection policy is retained. You will need to confirm fingerprints again.</p>","Remove all account and recipient bindings",ready);
    let policy_form = binding_form(
        csrf,
        revision,
        "set_policy",
        &policy_fields,
        "Save protection policy",
        ready,
    );
    let import_fields = format!("{public_revision_field}<label>OpenPGP public certificate (ASCII armoured)<textarea name=\"certificate\" maxlength=\"65536\" spellcheck=\"false\" autocomplete=\"off\" required></textarea></label>{}<p>Import stores public material only. Confirm the full primary fingerprint through a trusted channel, then create a separate account or recipient binding.</p>", fingerprint_input("expected_primary_fingerprint", "Expected full primary fingerprint", "", true));
    let import_form = binding_form(
        csrf,
        revision,
        "import_public",
        &import_fields,
        "Import public certificate",
        public_ready,
    );
    let mut rows = String::new();
    match inventory {
        PublicInventoryView::Unavailable => {
            rows.push_str("<p role=\"status\">Public inventory unavailable.</p>")
        }
        PublicInventoryView::Verified { keys, .. } => {
            if keys.is_empty() {
                rows.push_str("<p>No public keys were reported.</p>");
            }
            for key in keys.iter().take(128) {
                rows.push_str(&format!("<details class=\"public-key-row\"><summary><span class=\"public-key-fingerprint\">{}</span><span>{}</span></summary><div class=\"public-key-details\">{}",escape_html(&key.primary.fingerprint),escape_html(&key.primary.algorithm),material(&key.primary)));
                for sub in key.subkeys.iter().take(32) {
                    rows.push_str(&format!("<h3>Public subkey</h3>{}", material(sub)));
                }
                let remove_fields = format!("{public_revision_field}<input type=\"hidden\" name=\"primary_fingerprint\" value=\"{}\"><p>Remove account and recipient bindings first. The server checks binding and private-key use again before removal.</p>", escape_html(&key.primary.fingerprint));
                rows.push_str(&format!("<details><summary>Remove public certificate</summary>{}</details></div></details>", binding_form(csrf, revision, "remove_public", &remove_fields, "Remove public certificate", public_ready)));
            }
        }
    }
    let notice = error
        .map(|e| {
            format!(
                "<p class=\"inline-notice error\" role=\"alert\">{}</p>",
                escape_html(e)
            )
        })
        .unwrap_or_default();
    let import_link = if public_ready {
        "<a class=\"button-link\" href=\"/settings/keys?panel=import#public-import\">Import public key</a>"
    } else {
        "<button disabled>Import public key</button>"
    };
    let binding_link = if ready {
        "<a class=\"button-link\" href=\"/settings/keys?panel=recipient#recipient-binding\">+ Add binding</a>"
    } else {
        "<button disabled>+ Add binding</button>"
    };
    let toolbar_actions = format!("<div>{import_link}{binding_link}</div>");
    let public_state = if public_ready {
        "Public certificate import and removal are available with fresh verification. Import alone does not establish trust."
    } else {
        "Public certificate import and removal are unavailable. Existing binding changes are available when the verified inventory is present."
    };
    TrustedHtml::from_template(format!(concat!("{header}<main id=\"main-content\" class=\"page-shell key-management-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>OpenPGP Key Management</h1><p>Manage public keys, account bindings and key policy.</p>{notice}</div><div class=\"key-management-toolbar\"><p><a href=\"/settings?section=security\">Security</a> / <a href=\"/settings?section=openpgp\">OpenPGP</a> / Keys</p>{toolbar_actions}</div><p class=\"sr-only\" role=\"status\">{state_label} · Binding revision {revision}</p><div class=\"key-management-grid\"><section class=\"key-management-card\"><h2>Primary Account Key</h2>{overview}{account_actions}<details id=\"account-binding\"{account_open}><summary>{account_action}</summary>{account_form}</details><details id=\"protection-policy\"{policy_open}><summary>Protection policy</summary>{policy_form}</details><details><summary>Recover from unavailable or expired bindings</summary>{cleanup}</details></section><section class=\"key-management-card\"><h2>Recipient / Contact Keys</h2>{recipients}<details id=\"recipient-binding\"{recipient_open}><summary>Add or replace a recipient binding</summary>{recipient_form}</details><p class=\"key-inventory-notice\">Confirm full fingerprints through a trusted channel. OSMAP does not automatically trust keys discovered by email address. Each saved change requires your current mailbox password and a fresh authenticator code.</p><details id=\"public-import\"{import_open}><summary>Import public key</summary>{import_form}</details><details id=\"public-inventory\"{inventory_open}><summary>Public key inventory</summary>{rows}</details><p>{public_state}</p></section></div></main>"),account_open=opened("account"),policy_open=opened("policy"),recipient_open=opened("recipient"),import_open=opened("import"),inventory_open=opened("inventory"),notice=notice,revision=revision,account_form=account_form,account_actions=account_actions,policy_form=policy_form,cleanup=cleanup,recipients=recipients,recipient_form=recipient_form,rows=rows,overview=overview,account_action=if bound.is_some(){"Rotate binding"}else{"Add account binding"},header=app_header(account,csrf,"security"),state_label=if ready{"Verified public inventory and confirmed binding store"}else{"Binding changes unavailable"},toolbar_actions=toolbar_actions,import_form=import_form,public_state=public_state))
}

#[cfg(test)]
mod binding_page_tests {
    use super::*;
    #[test]
    fn key_management_page_preserves_two_cards_and_truthful_configured_status() {
        let account = "alice@example.test";
        let fp = "A".repeat(40);
        let mut bindings = crate::openpgp_bindings::BindingRecord::empty(account).unwrap();
        bindings.account_binding = Some(crate::openpgp_bindings::AccountBinding {
            primary_fingerprint: fp.clone(),
            signing_fingerprint: Some(fp.clone()),
            decrypt_primary_fingerprints: vec![fp.clone()],
        });
        bindings.revision = 1;
        let inventory=crate::openpgp_inventory::Inventory::parse(&serde_json::to_vec(&serde_json::json!({"version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.4.8","keys":[{"primary":{"fingerprint":fp,"algorithm":1,"bits":3072,"created":1704067200u64,"expires":0,"revoked":false,"expired":false,"disabled":false,"invalid":false,"can_encrypt":true,"can_sign":true,"can_certify":true,"can_authenticate":false},"subkeys":[]}]})).unwrap()).unwrap();
        let mut state = crate::key_management::State {
            canonical_username: account.into(),
            inventory: Some(inventory),
            bindings: Some(bindings),
            binding_changes_available: true,
            public_key_changes_available: false,
            public_inventory_revision: None,
        };
        let page = render_key_management(account, "test", &state, None);
        let body = page.as_str();
        assert_eq!(body.matches("class=\"key-management-card\"").count(), 2);
        assert!(body.contains("<strong>Configured</strong>"));
        assert!(body.contains("RSA · 3072 bits"));
        assert!(body.contains("Does not expire"));
        assert!(body.contains("Confirmed account binding"));
        assert!(body.contains("id=\"account-binding\"><summary>Rotate binding</summary>"));
        assert!(body.contains("id=\"protection-policy\"><summary>Protection policy</summary>"));
        assert!(body.contains("<button disabled>Import public key</button>"));
        assert!(body.contains("id=\"account-fingerprint\""));
        state.public_key_changes_available = true;
        state.public_inventory_revision = Some("a".repeat(64));
        let enabled = render_key_management(account, "test", &state, None)
            .as_str()
            .to_owned();
        assert!(enabled.contains("href=\"/settings/keys?panel=import#public-import\""));
        assert!(enabled.contains("name=\"primary_fingerprint\" required><option"));
        assert!(enabled.contains(&format!("value=\"{}\" selected", "A".repeat(40))));
        for (panel, id) in [
            ("account", "account-binding"),
            ("policy", "protection-policy"),
            ("recipient", "recipient-binding"),
            ("import", "public-import"),
            ("inventory", "public-inventory"),
        ] {
            let opened = render_key_management_panel(account, "test", &state, None, Some(panel))
                .as_str()
                .to_owned();
            assert!(opened.contains(&format!("<details id=\"{id}\" open>")));
            assert_eq!(opened.matches(" open>").count(), 1);
        }
        assert!(enabled.contains("name=\"certificate\""));
        assert!(enabled.contains("name=\"public_inventory_revision\" value=\"aaaaaaaa"));
        assert!(enabled.contains("<summary>Remove public certificate</summary>"));
        assert!(!enabled.contains("<button disabled>Import public key</button>"));
        let body = render_key_management(
            account,
            "test",
            &crate::key_management::State::unavailable(account),
            None,
        )
        .as_str()
        .to_owned();
        assert!(body.contains("Account binding unavailable"));
        assert!(!body.contains("<strong>Configured</strong>"));
        assert!(body.contains("<fieldset disabled>"));
        assert!(!body.contains(&"A".repeat(40)));
    }
}
