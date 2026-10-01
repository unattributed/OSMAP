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
