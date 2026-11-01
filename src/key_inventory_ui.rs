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
    pub email_addresses: Vec<String>,
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
fn binding_identities(
    account: &str,
    record: Option<&crate::openpgp_bindings::BindingRecord>,
    primary_fingerprint: &str,
    effective_recipients: Option<&[crate::openpgp_bindings::RecipientBinding]>,
) -> String {
    let Some(record) = record.filter(|record| record.ensure_account(account).is_ok()) else {
        return "<section class=\"public-key-bindings\"><h3 class=\"sr-only\">OSMAP-bound email addresses</h3><p>Email associations unavailable.</p></section>".into();
    };
    let mut identities = Vec::new();
    if record
        .account_binding
        .as_ref()
        .is_some_and(|binding| binding.primary_fingerprint == primary_fingerprint)
    {
        identities.push(format!(
            "<li><div class=\"key-email-identity\"><strong>{}</strong><span>Your account</span></div><div class=\"key-applied-policy\"><span>Encryption: <strong>{}</strong></span><span>Signing: {}</span></div></li>",
            escape_html(account), encryption_policy_label(record.policy.encryption),
            signing_policy_label(record.policy.signing)
        ));
    }
    identities.extend(
        effective_recipients.unwrap_or(&record.recipient_bindings)
            .iter()
            .filter(|binding| binding.primary_fingerprint == primary_fingerprint)
            .filter(|binding| !(crate::mail_address::comparison_key(&binding.address) == crate::mail_address::comparison_key(account)
                && record.account_binding.as_ref().is_some_and(|own| own.primary_fingerprint == primary_fingerprint)
                && !record.recipient_bindings.iter().any(|saved| crate::mail_address::comparison_key(&saved.address) == crate::mail_address::comparison_key(account))))
            .map(|binding| {
                format!(
                    "<li><div class=\"key-email-identity\"><strong>{}</strong><span>Recipient</span></div><div class=\"key-applied-policy\"><span>Encryption: <strong>{}</strong></span><span>Recipient policy: {}</span></div></li>",
                    escape_html(&binding.address),
                    applied_encryption_policy(record.policy.encryption, binding.encryption),
                    encryption_policy_label(binding.encryption)
                )
            }),
    );
    if identities.is_empty() {
        "<section class=\"public-key-bindings\"><h3 class=\"sr-only\">Selected email addresses</h3><p class=\"key-unassigned\">No email address currently uses this key.</p></section>".into()
    } else {
        format!(
            "<section class=\"public-key-bindings\"><h3 class=\"sr-only\">OSMAP-bound email addresses</h3><ul>{}</ul></section>",
            identities.join("")
        )
    }
}
fn certificate_identities(
    key: &PublicKeyView,
    account: &str,
    record: Option<&crate::openpgp_bindings::BindingRecord>,
    recipients: Option<&[crate::openpgp_bindings::RecipientBinding]>,
    associations_available: bool,
) -> String {
    if key.email_addresses.is_empty() {
        return "<p class=\"key-certificate-identities\">No usable email address is included in this public key.</p>".into();
    }
    let identities = key
        .email_addresses
        .iter()
        .filter_map(|address| {
            let selected = recipients.and_then(|recipients| {
                recipients.iter().find(|binding| {
                    crate::mail_address::comparison_key(&binding.address)
                        == crate::mail_address::comparison_key(address)
                })
            });
            let account_match = crate::mail_address::comparison_key(address)
                == crate::mail_address::comparison_key(account)
                && record
                    .and_then(|record| record.account_binding.as_ref())
                    .is_some_and(|binding| binding.primary_fingerprint == key.primary.fingerprint);
            if selected
                .is_some_and(|binding| binding.primary_fingerprint == key.primary.fingerprint)
                || (selected.is_none() && account_match)
            {
                return None;
            }
            let status = if !associations_available {
                "Recipient key selection unavailable."
            } else {
                match selected {
                    Some(binding) if binding.primary_fingerprint != key.primary.fingerprint => {
                        "This email currently uses another key."
                    }
                    Some(_) => "Email read from this public key.",
                    None => "No unique recipient key is selected for this email.",
                }
            };
            Some(format!(
                "<li><strong>{}</strong> <span>{status}</span></li>",
                escape_html(address)
            ))
        })
        .collect::<String>();
    if identities.is_empty() {
        String::new()
    } else {
        format!("<section class=\"key-certificate-identities\"><h3>Email addresses in this key</h3><ul>{identities}</ul></section>")
    }
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
                    email_addresses: vec![account.into()],
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
                    email_addresses: k.email_addresses.clone(),
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
pub(crate) fn encryption_policy_label(value: crate::openpgp_bindings::Requirement) -> &'static str {
    use crate::openpgp_bindings::Requirement::*;
    match value {
        Required => "Require encryption",
        Optional => "Off by default",
        Disabled => "Do not encrypt",
    }
}
fn signing_policy_label(value: crate::openpgp_bindings::Requirement) -> &'static str {
    use crate::openpgp_bindings::Requirement::*;
    match value {
        Required => "Require signing",
        Optional => "Choose per message",
        Disabled => "Do not sign",
    }
}
fn applied_encryption_policy(
    account: crate::openpgp_bindings::Requirement,
    recipient: crate::openpgp_bindings::Requirement,
) -> &'static str {
    use crate::openpgp_bindings::Requirement::*;
    match (account, recipient) {
        (Required, Disabled) | (Disabled, Required) => "Conflicting policies: sending blocked",
        (Required, Optional) => "Require encryption (account policy)",
        (Disabled, Optional) => "Do not encrypt (account policy)",
        (Optional, policy) | (Required, policy @ Required) | (Disabled, policy @ Disabled) => {
            encryption_policy_label(policy)
        }
    }
}
fn requirement_select(name: &str, selected: crate::openpgp_bindings::Requirement) -> String {
    use crate::openpgp_bindings::Requirement::{Disabled, Optional, Required};
    format!(
        "<select name=\"{}\">{}</select>",
        escape_html(name),
        [Optional, Required, Disabled]
            .into_iter()
            .map(|value| format!(
                "<option value=\"{}\"{}>{}</option>",
                requirement_label(value),
                if value == selected { " selected" } else { "" },
                if name == "encryption" {
                    encryption_policy_label(value)
                } else {
                    signing_policy_label(value)
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
    format!(concat!("<form method=\"post\" action=\"/settings/keys/change\"{}><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"binding_revision\" value=\"{}\"><input type=\"hidden\" name=\"key_action\" value=\"{}\"><fieldset{}>{}<label>Current mailbox password<input type=\"password\" name=\"current_password\" autocomplete=\"current-password\" required maxlength=\"1024\"></label><label>Fresh authenticator code<input name=\"totp_code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" pattern=\"[0-9]{{6}}\" maxlength=\"6\" required></label><button type=\"submit\">{}</button></fieldset></form>"),if action == "import_public" { " enctype=\"multipart/form-data\"" } else { "" },escape_html(csrf),revision,escape_html(action),if available{""}else{" disabled"},fields,escape_html(label))
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
fn recipient_fields(
    address: &str,
    fingerprint: &str,
    policy: crate::openpgp_bindings::Requirement,
    keys: &[PublicKeyView],
) -> String {
    format!(
        "<label>Email address<input type=\"email\" name=\"address\" value=\"{}\" maxlength=\"254\" required readonly></label>{}<label>Encryption policy{}</label><p>Compare the full fingerprint through a trusted channel before saving a key choice for this address.</p>",
        escape_html(address),
        inventoried_key_select("primary_fingerprint", "Public key (full fingerprint)", fingerprint,
            keys.iter().filter(|key| key.primary.fingerprint == fingerprint || key.email_addresses.iter().any(|email| crate::mail_address::comparison_key(email) == crate::mail_address::comparison_key(address))).map(|key| key.primary.fingerprint.clone()), true),
        requirement_select("encryption", policy)
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
    let raw_record = owned
        .then_some(state.bindings.as_ref())
        .flatten()
        .filter(|r| r.ensure_account(account).is_ok());
    let effective_result = raw_record
        .zip(state.inventory.as_ref().filter(|_| owned))
        .map(|(record, inventory)| record.with_certificate_recipients(inventory));
    let projection_unavailable = effective_result.as_ref().is_some_and(Result::is_err);
    let effective_recipients = effective_result.and_then(Result::ok).unwrap_or_else(|| {
        raw_record
            .map(|record| record.recipient_bindings.clone())
            .unwrap_or_default()
    });
    let record = raw_record;
    let inventory = map_public_inventory(
        account,
        &state.canonical_username,
        owned.then_some(state.inventory.as_ref()).flatten(),
    );
    let cleanup_ready = owned
        && state.binding_changes_available
        && record.is_some()
        && matches!(inventory, PublicInventoryView::Verified { .. });
    let ready = cleanup_ready && !projection_unavailable;
    let public_revision = state.public_inventory_revision.as_deref().filter(|value| {
        owned
            && value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    let public_ready = ready && state.public_key_changes_available && public_revision.is_some();
    let public_cleanup_ready =
        cleanup_ready && state.public_key_changes_available && public_revision.is_some();
    let public_revision_field = public_revision
        .map(|value| {
            format!(
                "<input type=\"hidden\" name=\"public_inventory_revision\" value=\"{}\">",
                value
            )
        })
        .unwrap_or_default();
    let revision = raw_record.map(|r| r.revision).unwrap_or(0);
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
            cleanup_ready,
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
    let now = crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider);
    // Assess one identity at a time: a saved list is not a composed message,
    // and can contain zero or more than the per-message recipient limit.
    let assess = |address: &str| {
        record
            .zip(state.inventory.as_ref().filter(|_| owned))
            .and_then(|(r, i)| {
                let addresses = [address.to_owned()];
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
                    now,
                )
                .ok()
            })
    };
    let assessment = assess(account);
    let overview = if let Some(b) = bound {
        let metadata=account_key.map(|k|format!("<dt>Algorithm</dt><dd>{} · {} bits</dd><dt>Created</dt><dd>{}</dd><dt>Expires</dt><dd>{}</dd><dt>Public capabilities</dt><dd>{}</dd>",escape_html(&k.primary.algorithm),k.primary.bits,date(k.primary.created),match k.primary.expires{PublicExpiry::Unknown=>"Unknown".into(),PublicExpiry::Never=>"Does not expire".into(),PublicExpiry::At(v)=>date(Some(v))},[(k.primary.can_sign,"Sign"),(k.primary.can_encrypt,"Encrypt")].into_iter().filter_map(|(v,l)|v.then_some(l)).collect::<Vec<_>>().join(", "))).unwrap_or_else(||"<dt>Public key metadata</dt><dd>Unavailable</dd>".into());
        format!("<div class=\"key-account-state\"><strong>{}</strong><span>{}</span></div><p class=\"key-status\">Signing: {} · Encryption: {}</p><details class=\"account-key-details\"><summary>Account key details</summary><dl><dt>Full fingerprint</dt><dd><input id=\"account-fingerprint\" aria-label=\"Full account fingerprint\" readonly value=\"{}\" spellcheck=\"false\" autocomplete=\"off\"></dd>{}<dt>Binding status</dt><dd>Confirmed account binding</dd></dl></details>",if account_key.is_some(){"Configured"}else{"Saved account key unavailable"},escape_html(account),assessment.as_ref().map(|a|key_status(a.signing)).unwrap_or("Unavailable"),assessment.as_ref().map(|a|key_status(a.self_encryption)).unwrap_or("Unavailable"),escape_html(&b.primary_fingerprint),metadata)
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
        let mut recipient_rows = effective_recipients.clone();
        for key in keys.iter().filter(|_| !projection_unavailable) {
            for address in &key.email_addresses {
                if !recipient_rows.iter().any(|binding| {
                    crate::mail_address::comparison_key(&binding.address)
                        == crate::mail_address::comparison_key(address)
                }) {
                    recipient_rows.push(crate::openpgp_bindings::RecipientBinding {
                        address: address.clone(),
                        primary_fingerprint: String::new(),
                        encryption: crate::openpgp_bindings::Requirement::Optional,
                    });
                }
            }
        }
        for b in &recipient_rows {
            let status = assess(&b.address)
                .and_then(|view| view.recipients.first().map(|recipient| recipient.state))
                .map(key_status)
                .unwrap_or("Unavailable");
            let edit = binding_form(
                csrf,
                revision,
                "set_recipient",
                &recipient_fields(&b.address, &b.primary_fingerprint, b.encryption, keys),
                "Save recipient key and policy",
                ready,
            );
            let reset = if raw_record.is_some_and(|raw| {
                raw.recipient_bindings.iter().any(|saved| {
                    crate::mail_address::comparison_key(&saved.address)
                        == crate::mail_address::comparison_key(&b.address)
                })
            }) {
                format!("<details><summary>Reset saved policy</summary>{}</details>", binding_form(csrf, revision, "remove_recipient",
                    &format!("<input type=\"hidden\" name=\"address\" value=\"{}\"><p>This resets the saved key choice and recipient policy. A unique email match from imported keys is then used with encryption off by default. No match leaves no recipient key selected; multiple matching keys require a choice.</p>", escape_html(&b.address)),
                    "Reset saved policy", cleanup_ready))
            } else {
                String::new()
            };
            recipients.push_str(&format!(
                "<article class=\"recipient-key-card\"><h3>{}</h3><p class=\"key-status\">{status}</p><p>Encryption: <strong>{}</strong></p><p class=\"key-policy-note\">Recipient policy: {}</p><details><summary>{}</summary>{edit}</details>{reset}</article>",
                escape_html(&b.address), applied_encryption_policy(r.policy.encryption, b.encryption),
                encryption_policy_label(b.encryption), if b.primary_fingerprint.is_empty() { "Choose a key for this email" } else { "Edit policy or replace key" }));
        }
    }
    if recipients.is_empty() {
        recipients.push_str(if record.is_some() {
            "<p>Import a public key file to read its email addresses automatically.</p>"
        } else {
            "<p>Recipient email associations unavailable.</p>"
        });
    }
    let policy = record.map(|r| r.policy).unwrap_or_default();
    let policy_summary = record.map(|r| format!(
        "<dl class=\"key-policy-summary\"><dt>Encryption for this account</dt><dd>{}</dd><dt>Signing for this account</dt><dd>{}</dd></dl><p>Off by default permits an explicit encryption choice for a message. Account and recipient policies both apply; conflicting policies block sending.</p>",
        encryption_policy_label(r.policy.encryption), signing_policy_label(r.policy.signing)))
        .unwrap_or_else(|| "<p>Account policies unavailable.</p>".into());
    let policy_fields = format!(
        "<label>Signing policy{}</label><label>Encryption policy{}</label>",
        requirement_select("signing", policy.signing),
        requirement_select("encryption", policy.encryption)
    );
    let cleanup=binding_form(csrf,revision,"clear_all_bindings","<p>This removes the account key and all saved recipient choices and policies. Protection policy is retained. Unique email matches from imported public keys remain available with encryption off by default.</p>","Reset account key and saved recipient policies",cleanup_ready);
    let policy_form = binding_form(
        csrf,
        revision,
        "set_policy",
        &policy_fields,
        "Save protection policy",
        ready,
    );
    let import_fields = format!("{public_revision_field}<label>OpenPGP public key file (.asc)<input type=\"file\" name=\"attachment\" accept=\".asc,application/pgp-keys\" required></label>{}<p>Choose one ASCII-armoured public key file, up to 64 KiB. Email addresses are read automatically from the key. Encryption is off by default; existing account and recipient policies still apply. Compare the full fingerprint through a trusted channel.</p>", fingerprint_input("expected_primary_fingerprint", "Expected full primary fingerprint", "", true));
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
            rows.push_str("<p role=\"status\">Public inventory unavailable. Saved email associations and policies are shown below when available.</p>")
        }
        PublicInventoryView::Verified { keys, .. } => {
            if keys.is_empty() {
                rows.push_str("<p>No public keys were reported.</p>");
            }
            for key in keys.iter().take(128) {
                let public_status = if key.primary.revoked { "Revoked" }
                    else if key.primary.expired || matches!(key.primary.expires, PublicExpiry::At(expiry) if expiry <= now) { "Expired" }
                    else if key.primary.invalid || key.primary.disabled { "Unavailable" }
                    else { "Imported public key" };
                rows.push_str(&format!(
                    "<article class=\"imported-key-card\"><p class=\"key-status\">{public_status}</p>{}{}<details class=\"public-key-row\"><summary>Details and key actions</summary><div class=\"public-key-details\">{}",
                    certificate_identities(key, account, record, record.map(|_| effective_recipients.as_slice()), record.is_some() && !projection_unavailable), binding_identities(account, record, &key.primary.fingerprint, Some(&effective_recipients)), material(&key.primary)));
                for sub in key.subkeys.iter().take(32) {
                    rows.push_str(&format!("<h3>Public subkey</h3>{}", material(sub)));
                }
                let remove_fields = format!("{public_revision_field}<input type=\"hidden\" name=\"primary_fingerprint\" value=\"{}\"><p>Removing this certificate removes its automatic email matches. Reset any saved recipient choices or account binding that use it first. The server checks saved bindings and private-key use again before removal.</p>", escape_html(&key.primary.fingerprint));
                rows.push_str(&format!("<details><summary>Remove public certificate</summary>{}</details></div></details></article>", binding_form(csrf, revision, "remove_public", &remove_fields, "Remove public certificate", public_cleanup_ready)));
            }
        }
    }
    let notice = error.or(if projection_unavailable { Some("Recipient key selection is unavailable. Imported email identities and saved policies are shown; no partial automatic selection is used.") } else { None })
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
    let toolbar_actions = format!("<div>{import_link}</div>");
    let public_state = if public_ready {
        "Public certificate import and removal are available with fresh verification. Import alone does not establish trust."
    } else if public_cleanup_ready {
        "Automatic recipient matching is unavailable. Reset saved choices or remove unused public certificates to recover. Fresh verification is required."
    } else {
        "Public certificate import and removal are unavailable. Existing binding changes are available when the verified inventory is present."
    };
    TrustedHtml::from_template(format!(concat!(
        "{header}<main id=\"main-content\" class=\"page-shell key-management-page\" tabindex=\"-1\">",
        "<div class=\"page-intro\"><h1>OpenPGP Key Management</h1><p>See imported keys, the email addresses they are used for, and the policies that apply.</p>{notice}</div>",
        "<div class=\"key-management-toolbar\"><p><a href=\"/settings?section=security\">Security</a> / <a href=\"/settings?section=openpgp\">OpenPGP</a> / Keys</p>{toolbar_actions}</div>",
        "<p class=\"sr-only\" role=\"status\">{state_label} · Binding revision {revision}</p>",
        "<section id=\"public-inventory\" class=\"key-management-card key-inventory-list\" aria-labelledby=\"imported-keys-heading\"><h2 id=\"imported-keys-heading\">Imported keys</h2><p>Email addresses are read from imported public keys automatically. Encryption is off by default. Existing saved policies take precedence.</p>{rows}<p>{public_state}</p></section>",
        "<div class=\"key-management-grid\"><section class=\"key-management-card\"><h2>Your email key and account policies</h2>{overview}{account_actions}{policy_summary}",
        "<details id=\"account-binding\"{account_open}><summary>{account_action}</summary>{account_form}</details><details id=\"protection-policy\"{policy_open}><summary>Protection policy</summary>{policy_form}</details><details><summary>Recover from unavailable or expired bindings</summary>{cleanup}</details></section>",
        "<section id=\"recipient-binding\" class=\"key-management-card\"><h2>Recipient keys and policies</h2>{recipients}",
        "<p class=\"key-inventory-notice\">Automatic online key discovery is off. Email addresses come from the public keys you import, not from independent identity verification. Compare full fingerprints through a trusted channel. Each saved change requires your current mailbox password and a fresh authenticator code. Importing a public key does not configure a private signing key.</p>",
        "<details id=\"public-import\"{import_open}><summary>Import public key</summary>{import_form}</details></section></div></main>"
    ),account_open=opened("account"),policy_open=opened("policy"),import_open=opened("import"),notice=notice,revision=revision,account_form=account_form,account_actions=account_actions,policy_summary=policy_summary,policy_form=policy_form,cleanup=cleanup,recipients=recipients,rows=rows,overview=overview,account_action=if bound.is_some(){"Advanced: change private-key binding"}else{"Advanced: configure private-key binding"},header=app_header(account,csrf,"security"),state_label=if ready{"Verified public inventory and confirmed binding store"}else{"Binding changes unavailable"},toolbar_actions=toolbar_actions,import_form=import_form,public_state=public_state))
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
        bindings
            .recipient_bindings
            .push(crate::openpgp_bindings::RecipientBinding {
                address: "bob@example.test".into(),
                primary_fingerprint: fp.clone(),
                encryption: crate::openpgp_bindings::Requirement::Required,
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
        assert!(body.contains("<strong>alice@example.test</strong><span>Your account</span>"));
        assert!(body.contains("<strong>bob@example.test</strong><span>Recipient</span>"));
        assert!(body.contains(
            "id=\"account-binding\"><summary>Advanced: change private-key binding</summary>"
        ));
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
            ("import", "public-import"),
        ] {
            let opened = render_key_management_panel(account, "test", &state, None, Some(panel))
                .as_str()
                .to_owned();
            assert!(opened.contains(&format!("<details id=\"{id}\" open>")));
            assert_eq!(opened.matches(" open>").count(), 1);
        }
        assert!(enabled.contains(
            "type=\"file\" name=\"attachment\" accept=\".asc,application/pgp-keys\" required"
        ));
        assert_eq!(
            enabled.matches("enctype=\"multipart/form-data\"").count(),
            1
        );
        assert!(!enabled.contains("name=\"certificate\""));
        assert!(enabled.contains("<section id=\"public-inventory\""));
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

    #[test]
    fn key_management_inventory_marks_unbound_and_refuses_foreign_state() {
        let account = "alice@example.test";
        let fp = "A".repeat(40);
        let bindings = crate::openpgp_bindings::BindingRecord::empty(account);
        assert!(bindings.is_ok());
        let Ok(mut bindings) = bindings else {
            return;
        };
        bindings.revision = 1;
        let encoded = serde_json::to_vec(
            &serde_json::json!({"version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.4.8","keys":[{"primary":{"fingerprint":fp,"algorithm":1,"bits":3072,"created":1704067200u64,"expires":0,"revoked":false,"expired":false,"disabled":false,"invalid":false,"can_encrypt":true,"can_sign":true,"can_certify":true,"can_authenticate":false},"subkeys":[]}]}),
        );
        assert!(encoded.is_ok());
        let Ok(encoded) = encoded else {
            return;
        };
        let inventory = crate::openpgp_inventory::Inventory::parse(&encoded);
        assert!(inventory.is_ok());
        let Ok(inventory) = inventory else {
            return;
        };
        let state = crate::key_management::State {
            canonical_username: account.into(),
            inventory: Some(inventory),
            bindings: Some(bindings),
            binding_changes_available: true,
            public_key_changes_available: false,
            public_inventory_revision: None,
        };
        let unbound = render_key_management(account, "test", &state, None)
            .as_str()
            .to_owned();
        assert!(unbound.contains("No email address currently uses this key."));
        let foreign = render_key_management("mallory@example.test", "test", &state, None)
            .as_str()
            .to_owned();
        assert!(!foreign.contains("alice@example.test"));
        assert!(!foreign.contains(&"A".repeat(40)));
    }

    fn practical_state() -> crate::key_management::State {
        use crate::openpgp_bindings::{
            AccountBinding, BindingRecord, RecipientBinding, Requirement,
        };
        let account = "alice@example.test";
        let mut bindings = BindingRecord::empty(account).unwrap();
        bindings.revision = 41;
        bindings.account_binding = Some(AccountBinding {
            primary_fingerprint: "A".repeat(40),
            signing_fingerprint: Some("A".repeat(40)),
            decrypt_primary_fingerprints: vec!["A".repeat(40)],
        });
        bindings.recipient_bindings = vec![RecipientBinding {
            address: "bob@example.test".into(),
            primary_fingerprint: "B".repeat(40),
            encryption: Requirement::Optional,
        }];
        let keys = ['A', 'B', 'C'].map(|letter| {
            serde_json::json!({
                "primary": {"fingerprint": letter.to_string().repeat(40), "algorithm":1,
                    "bits":3072, "created":1704067200u64, "expires":0,
                    "revoked":false,"expired":false,"disabled":false,"invalid":false,
                    "can_encrypt":true,"can_sign":true,"can_certify":true,"can_authenticate":false},
                "subkeys":[]
            })
        });
        let inventory = crate::openpgp_inventory::Inventory::parse(
            &serde_json::to_vec(&serde_json::json!({
                "version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1",
                "engine_version":"2.5.18","keys": keys
            }))
            .unwrap(),
        )
        .unwrap();
        crate::key_management::State {
            canonical_username: account.into(),
            inventory: Some(inventory),
            bindings: Some(bindings),
            binding_changes_available: true,
            public_key_changes_available: true,
            public_inventory_revision: Some("a".repeat(64)),
        }
    }

    fn certificate_emails(state: &mut crate::key_management::State, emails: &[&[&str]]) {
        let mut inventory: serde_json::Value =
            serde_json::from_slice(&state.inventory.as_ref().unwrap().to_bytes().unwrap()).unwrap();
        for (key, addresses) in inventory["keys"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .zip(emails)
        {
            key["email_addresses"] = serde_json::json!(addresses);
        }
        state.inventory = Some(
            crate::openpgp_inventory::Inventory::parse(&serde_json::to_vec(&inventory).unwrap())
                .unwrap(),
        );
    }

    #[test]
    fn certificate_email_workflow_is_automatic_default_off_and_has_no_free_email_form() {
        let mut state = practical_state();
        state.bindings =
            Some(crate::openpgp_bindings::BindingRecord::empty("alice@example.test").unwrap());
        certificate_emails(
            &mut state,
            &[&[], &["bob&tag@example.test", "second@example.test"], &[]],
        );
        let before = serde_json::to_vec(state.bindings.as_ref().unwrap()).unwrap();
        let html = render_key_management("alice@example.test", "fixture", &state, None)
            .as_str()
            .to_owned();
        assert!(html.contains("<strong>bob&amp;tag@example.test</strong>"));
        assert!(html.contains("<h3>second@example.test</h3>"));
        assert!(html.contains("Encryption: <strong>Off by default</strong>"));
        assert!(html.contains("Email addresses are read automatically from the key."));
        assert!(html.contains("No usable email address is included in this public key."));
        assert!(html.contains("Advanced: configure private-key binding"));
        assert!(!html.contains("+ Associate email"));
        assert!(!html.contains("name=\"address\" value=\"\""));
        assert!(!html.contains("Reset saved policy"));
        assert!(html.contains("name=\"binding_revision\" value=\"0\""));
        let editor = html
            .split("<h3>second@example.test</h3>")
            .nth(1)
            .unwrap()
            .split("</article>")
            .next()
            .unwrap();
        assert!(editor.contains(
            "name=\"address\" value=\"second@example.test\" maxlength=\"254\" required readonly"
        ));
        assert!(editor.contains(&format!("<option value=\"{}\" selected>", "B".repeat(40))));
        assert!(!editor.contains(&format!("<option value=\"{}\"", "A".repeat(40))));
        assert!(!editor.contains(&format!("<option value=\"{}\"", "C".repeat(40))));
        assert_eq!(
            serde_json::to_vec(state.bindings.as_ref().unwrap()).unwrap(),
            before
        );
        let foreign = render_key_management("mallory@example.test", "fixture", &state, None)
            .as_str()
            .to_owned();
        assert!(!foreign.contains("second@example.test"));
        assert!(!foreign.contains("bob&amp;tag@example.test"));
    }

    #[test]
    fn certificate_email_conflicts_require_a_key_choice_and_preserve_saved_policy() {
        let mut state = practical_state();
        certificate_emails(
            &mut state,
            &[&[], &["bob@example.test"], &["bob@example.test"]],
        );
        state.bindings.as_mut().unwrap().recipient_bindings.clear();
        let ambiguous = render_key_management("alice@example.test", "fixture", &state, None)
            .as_str()
            .to_owned();
        assert!(
            ambiguous.contains("<h3>bob@example.test</h3><p class=\"key-status\">Ambiguous</p>")
        );
        assert!(ambiguous.contains("Choose a key for this email"));
        assert!(ambiguous.contains("No unique recipient key is selected for this email."));
        assert!(!ambiguous.contains("Reset saved policy"));
        state.bindings.as_mut().unwrap().recipient_bindings.push(
            crate::openpgp_bindings::RecipientBinding {
                address: "bob@example.test".into(),
                primary_fingerprint: "B".repeat(40),
                encryption: crate::openpgp_bindings::Requirement::Required,
            },
        );
        let saved = render_key_management("alice@example.test", "fixture", &state, None)
            .as_str()
            .to_owned();
        assert!(saved.contains("This email currently uses another key."));
        assert!(saved.contains("Encryption: <strong>Require encryption</strong>"));
        assert!(saved.contains("Reset saved policy"));
        assert!(!saved.contains("Remove email association"));
        assert!(!saved.contains("Choose a key for this email"));
    }

    #[test]
    fn certificate_email_projection_quota_is_unavailable_without_partial_selection() {
        let mut state = practical_state();
        let record = state.bindings.as_mut().unwrap();
        record.recipient_bindings = (0..crate::openpgp_bindings::MAX_BINDINGS)
            .map(|n| crate::openpgp_bindings::RecipientBinding {
                address: format!("saved{n}@example.test"),
                primary_fingerprint: "B".repeat(40),
                encryption: crate::openpgp_bindings::Requirement::Optional,
            })
            .collect();
        certificate_emails(&mut state, &[&[], &["new@example.test"], &[]]);
        let html = render_key_management("alice@example.test", "fixture", &state, None)
            .as_str()
            .to_owned();
        assert!(html.contains("no partial automatic selection is used."));
        assert!(html.contains("<strong>new@example.test</strong>"));
        assert!(!html.contains("<h3>new@example.test</h3>"));
        assert!(html.contains("Recipient key selection unavailable."));
        assert!(html.contains("<button disabled>Import public key</button>"));
        let form_for = |action: &str| {
            html.split("<form ")
                .find(|form| form.contains(&format!("name=\"key_action\" value=\"{action}\"")))
                .unwrap()
        };
        for action in [
            "remove_recipient",
            "clear_account",
            "clear_all_bindings",
            "remove_public",
        ] {
            assert!(
                form_for(action).contains("<fieldset>"),
                "cleanup {action} must remain available"
            );
            assert!(!form_for(action).contains("<fieldset disabled>"));
        }
        for action in [
            "set_recipient",
            "set_account",
            "set_policy",
            "import_public",
        ] {
            assert!(
                form_for(action).contains("<fieldset disabled>"),
                "new edit {action} must refuse partial automatic selection"
            );
        }
    }

    #[test]
    fn matched_certificate_addresses_are_shown_once_with_their_applied_policy() {
        let mut state = practical_state();
        certificate_emails(
            &mut state,
            &[&["alice@example.test"], &["bob@example.test"], &[]],
        );
        let html = render_key_management("alice@example.test", "fixture", &state, None)
            .as_str()
            .to_owned();
        let cards = html
            .split("<article class=\"imported-key-card\">")
            .skip(1)
            .map(|card| card.split("</article>").next().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            cards[0]
                .matches("<strong>alice@example.test</strong>")
                .count(),
            1
        );
        assert!(cards[0].contains("Your account"));
        assert!(!cards[0].contains("No unique recipient key"));
        assert_eq!(
            cards[1]
                .matches("<strong>bob@example.test</strong>")
                .count(),
            1
        );
        assert!(cards[1].contains("Encryption: <strong>Off by default</strong>"));
        assert!(cards[2].contains("No usable email address is included in this public key."));
    }

    #[test]
    fn practical_inventory_pairs_email_policy_only_with_exact_approved_primary() {
        let state = practical_state();
        let record = state.bindings.as_ref();
        let account = binding_identities("alice@example.test", record, &"A".repeat(40), None);
        let recipient = binding_identities("alice@example.test", record, &"B".repeat(40), None);
        let unbound = binding_identities("alice@example.test", record, &"C".repeat(40), None);
        assert!(account.contains("<strong>alice@example.test</strong>"));
        assert!(!account.contains("bob@example.test"));
        assert!(recipient.contains("<strong>bob@example.test</strong>"));
        assert!(recipient.contains("Encryption: <strong>Off by default</strong>"));
        assert!(!recipient.contains("alice@example.test"));
        assert!(unbound.contains("No email address currently uses this key."));
        assert!(!unbound.contains("alice@example.test"));
        assert!(!unbound.contains("bob@example.test"));
        let short = binding_identities("alice@example.test", record, &"B".repeat(16), None);
        assert!(!short.contains("bob@example.test"));
        let foreign = binding_identities("mallory@example.test", record, &"B".repeat(40), None);
        assert!(foreign.contains("Email associations unavailable."));
        assert!(!foreign.contains("bob@example.test"));
    }

    #[test]
    fn displayed_applied_policy_agrees_with_both_backend_encryption_choices() {
        use crate::openpgp_bindings::{
            evaluate, PreflightState, Recipients, Requirement::*, Selections,
        };
        let state = practical_state();
        for account_policy in [Optional, Required, Disabled] {
            for recipient_policy in [Optional, Required, Disabled] {
                let mut record = state.bindings.as_ref().unwrap().clone();
                record.policy.encryption = account_policy;
                record.recipient_bindings[0].encryption = recipient_policy;
                let allowed = |encrypt| {
                    evaluate(
                        "alice@example.test",
                        &record,
                        state.inventory.as_ref().unwrap(),
                        Recipients {
                            to: &["bob@example.test".into()],
                            cc: &[],
                            bcc: &[],
                        },
                        Selections {
                            sign: false,
                            encrypt,
                            encrypt_to_self: false,
                        },
                        1800000000,
                    )
                    .unwrap()
                    .state
                        != PreflightState::Blocked
                };
                let applied = applied_encryption_policy(account_policy, recipient_policy);
                match (allowed(false), allowed(true)) {
                    (true, true) => assert_eq!(applied, "Off by default"),
                    (false, true) => assert!(applied.starts_with("Require encryption")),
                    (true, false) => assert!(applied.starts_with("Do not encrypt")),
                    (false, false) => assert_eq!(applied, "Conflicting policies: sending blocked"),
                }
                let identities =
                    binding_identities("alice@example.test", Some(&record), &"B".repeat(40), None);
                assert!(identities.contains(&format!("Encryption: <strong>{applied}</strong>")));
                assert!(identities.contains(&format!(
                    "Recipient policy: {}",
                    encryption_policy_label(recipient_policy)
                )));
            }
        }
    }

    #[test]
    fn practical_page_preserves_default_and_prefills_current_recipient_for_safe_edit() {
        let mut state = practical_state();
        state.bindings.as_mut().unwrap().recipient_bindings[0].encryption =
            crate::openpgp_bindings::Requirement::Required;
        let before = serde_json::to_vec(state.bindings.as_ref().unwrap()).unwrap();
        let html = render_key_management("alice@example.test", "fixture-csrf", &state, None)
            .as_str()
            .to_owned();
        let imported = html
            .split("<section id=\"public-inventory\"")
            .nth(1)
            .unwrap()
            .split("<div class=\"key-management-grid\"")
            .next()
            .unwrap();
        assert!(imported.contains("<h2 id=\"imported-keys-heading\">Imported keys</h2>"));
        assert!(imported.contains("<strong>bob@example.test</strong>"));
        assert!(imported.contains("Encryption: <strong>Require encryption</strong>"));
        assert!(!imported.contains("<details id=\"public-inventory\""));
        assert!(!imported.contains("class=\"public-key-row\" open"));
        let editor = html
            .split("<article class=\"recipient-key-card\"><h3>bob@example.test</h3>")
            .nth(1)
            .unwrap()
            .split("</article>")
            .next()
            .unwrap();
        assert!(editor.contains("name=\"key_action\" value=\"set_recipient\""));
        assert!(editor.contains(
            "name=\"address\" value=\"bob@example.test\" maxlength=\"254\" required readonly"
        ));
        assert!(editor.contains(&format!("<option value=\"{}\" selected>", "B".repeat(40))));
        assert!(editor.contains("<option value=\"required\" selected>Require encryption</option>"));
        assert!(editor.contains("name=\"binding_revision\" value=\"41\""));
        assert!(editor.contains("name=\"csrf_token\" value=\"fixture-csrf\""));
        assert!(
            editor.contains("name=\"current_password\" autocomplete=\"current-password\" required")
        );
        assert!(!html.contains("+ Associate email"));
        assert!(!html.contains("Associate an email address with a key"));
        assert!(!html.contains("name=\"address\" value=\"\""));
        assert!(!html.contains("name=\"pgp_encrypt\""));
        assert!(html.contains("Automatic online key discovery is off."));
        assert_eq!(
            before,
            serde_json::to_vec(state.bindings.as_ref().unwrap()).unwrap()
        );
    }

    #[test]
    fn saved_missing_keys_and_unavailable_inventory_remain_visible_without_foreign_leakage() {
        let mut state = practical_state();
        state.bindings.as_mut().unwrap().recipient_bindings[0].primary_fingerprint = "D".repeat(40);
        let missing = render_key_management("alice@example.test", "fixture", &state, None)
            .as_str()
            .to_owned();
        assert!(missing
            .contains("<h3>bob@example.test</h3><p class=\"key-status\">Missing public key</p>"));
        assert!(missing.contains(&format!(
            "Current binding: {} (unavailable)",
            "D".repeat(40)
        )));
        state.inventory = None;
        let unavailable = render_key_management("alice@example.test", "fixture", &state, None)
            .as_str()
            .to_owned();
        assert!(unavailable.contains("Public inventory unavailable."));
        assert!(unavailable.contains("<h3>bob@example.test</h3>"));
        assert!(unavailable.contains("Recipient policy: Off by default"));
        let foreign = render_key_management("mallory@example.test", "fixture", &state, None)
            .as_str()
            .to_owned();
        assert!(!foreign.contains("bob@example.test"));
        assert!(!foreign.contains(&"D".repeat(40)));
        assert!(!foreign.contains(&"a".repeat(64)));
    }

    #[test]
    fn approved_addresses_are_escaped_and_list_size_is_not_a_message_recipient_limit() {
        let mut state = practical_state();
        let record = state.bindings.as_mut().unwrap();
        record.recipient_bindings[0].address = "bob&tag@example.test".into();
        for n in 0..55 {
            record
                .recipient_bindings
                .push(crate::openpgp_bindings::RecipientBinding {
                    address: format!("recipient{n}@example.test"),
                    primary_fingerprint: "B".repeat(40),
                    encryption: crate::openpgp_bindings::Requirement::Optional,
                });
        }
        let html = render_key_management("alice@example.test", "fixture", &state, None)
            .as_str()
            .to_owned();
        assert!(html.contains("bob&amp;tag@example.test"));
        assert!(!html.contains("bob&tag@example.test"));
        assert!(html.contains(
            "<h3>recipient54@example.test</h3><p class=\"key-status\">Ready public key</p>"
        ));
        state.bindings.as_mut().unwrap().recipient_bindings.clear();
        let account_only = render_key_management("alice@example.test", "fixture", &state, None)
            .as_str()
            .to_owned();
        assert!(account_only.contains("Signing: Ready public key · Encryption: Ready public key"));
    }
}
