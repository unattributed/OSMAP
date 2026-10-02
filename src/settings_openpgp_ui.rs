//! PAGE19 account OpenPGP capability, projected from authenticated public state.
use super::*;

fn requirement(value: crate::openpgp_bindings::Requirement) -> &'static str {
    match value {
        crate::openpgp_bindings::Requirement::Required => "Required",
        crate::openpgp_bindings::Requirement::Optional => "Optional",
        crate::openpgp_bindings::Requirement::Disabled => "Disabled",
    }
}

pub(crate) fn render_openpgp_settings(
    account: &str,
    csrf: &str,
    inventory: &crate::http_ui::key_inventory_ui::PublicInventoryView,
    capability: Option<&crate::http::ComposeProtectionView>,
) -> TrustedHtml {
    use crate::http_ui::key_inventory_ui::PublicInventoryView;
    let inventory_verified = matches!(inventory, PublicInventoryView::Verified { account: owner, .. } if owner == account);
    let public_keys = match inventory {
        PublicInventoryView::Verified {
            account: owner,
            keys,
        } if owner == account => Some(keys.len()),
        _ => None,
    };
    let configured = capability.is_some_and(|view| {
        view.runtime_configured && view.account_binding.is_some() && inventory_verified
    });
    let status = if configured {
        format!("<strong>OpenPGP configured</strong><span>{} public keys reported. Private-key readiness is checked when an operation runs.</span>", public_keys.unwrap_or(0))
    } else if capability.is_some() && inventory_verified {
        "<strong>Account binding needed</strong><span>Public keys are present, but no account key is approved for this identity.</span>".to_string()
    } else {
        "<strong>OpenPGP unavailable</strong><span>Runtime capability or verified public inventory could not be established.</span>".to_string()
    };
    let fingerprint = capability
        .and_then(|view| view.account_binding.as_ref())
        .map(|binding| escape_html(&binding.primary_fingerprint).to_string())
        .unwrap_or_else(|| "Account binding unavailable".to_string());
    let (signing, encryption) = capability
        .map(|view| {
            (
                requirement(view.policy.signing),
                requirement(view.policy.encryption),
            )
        })
        .unwrap_or(("Unavailable", "Unavailable"));
    let recipient_count = capability
        .map(|view| view.recipient_binding_count)
        .unwrap_or(0);
    let policies = [
        ("Full fingerprint binding", "Approved account and recipient bindings use full fingerprints.", if configured { "Required" } else { "Unavailable" }),
        ("Missing recipient key", "A requested encrypted send stops if any recipient key is missing or ineligible.", if capability.is_some() { "Fail closed" } else { "Unavailable" }),
        ("Automatic key discovery", "Keys are never silently discovered or trusted.", "Off"),
        ("Private-key handling", "Private-key operations run outside the web process; readiness is confirmed on use.", if capability.is_some() { "Isolated" } else { "Unavailable" }),
    ].into_iter().map(|(label, help, state)| format!("<li><div><strong>{label}</strong><span>{help}</span></div><span class=\"openpgp-policy-state\">{state}</span></li>")).collect::<String>();
    TrustedHtml::from_template(format!(concat!(
        "{header}<main id=\"main-content\" class=\"page-shell settings-page openpgp-settings-page\" tabindex=\"-1\">",
        "<div class=\"page-intro\"><h1>Settings</h1><p>Configure key bindings and protected-delivery defaults for this account.</p></div>",
        "<div class=\"settings-layout\">{nav}<div class=\"openpgp-settings-grid\">",
        "<section class=\"openpgp-settings-card\"><h2>Account Capability</h2><div class=\"openpgp-account-status\">{status}</div>",
        "<div class=\"openpgp-setting-row\"><label for=\"account-key\">Key fingerprint</label><div><input id=\"account-key\" readonly value=\"{fingerprint}\"><a href=\"/settings/keys?panel=account\">Choose account key</a></div></div>",
        "<div class=\"openpgp-setting-row\"><label for=\"signing-setting\">Signing policy</label><div><input id=\"signing-setting\" readonly value=\"{signing}\"><a href=\"/settings/keys?panel=policy\" aria-label=\"Edit signing policy\">Edit policy</a></div></div>",
        "<div class=\"openpgp-setting-row\"><label for=\"encryption-setting\">Encryption policy</label><div><input id=\"encryption-setting\" readonly value=\"{encryption}\"><a href=\"/settings/keys?panel=policy\" aria-label=\"Edit encryption policy\">Edit policy</a></div></div>",
        "<div class=\"openpgp-setting-row\"><label for=\"self-setting\">Encrypt to self</label><div><input id=\"self-setting\" readonly value=\"Selected per message\"><a href=\"/compose\">Choose for a message</a></div></div>",
        "<p>{recipient_count} recipient bindings approved for this account.</p><a class=\"button-link openpgp-manage\" href=\"/settings/keys\">Manage Keys</a></section>",
        "<section class=\"openpgp-settings-card\"><h2>Policy Behavior</h2><ul class=\"openpgp-policy-list\">{policies}</ul></section></div></div></main>"
    ), header=app_header(account,csrf,"settings-openpgp"),nav=settings_navigation("openpgp"),status=status,fingerprint=fingerprint,signing=signing,encryption=encryption,recipient_count=recipient_count,policies=policies))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::ComposeProtectionView;
    use crate::openpgp_bindings::{AccountBinding, ProtectionPolicy, Requirement};

    #[test]
    fn openpgp_settings_saved_values_link_to_real_account_policy_and_compose_workflows() {
        let account = "alice@example.test";
        let fingerprint = "A".repeat(40);
        let inventory = crate::openpgp_inventory::Inventory::parse(
            &serde_json::to_vec(&serde_json::json!({
                "version":1,"ok":true,"protocol":"openpgp",
                "gpgme_version":"2.0.1","engine_version":"2.5.18",
                "keys":[{"primary":{"fingerprint":fingerprint,"algorithm":1,
                "bits":3072,"created":0,"expires":0,"revoked":false,
                "expired":false,"disabled":false,"invalid":false,
                "can_sign":true,"can_encrypt":true,"can_certify":true,
                "can_authenticate":false},"subkeys":[]}]
            }))
            .unwrap(),
        )
        .unwrap();
        let view = crate::http_ui::key_inventory_ui::map_public_inventory(
            account,
            account,
            Some(&inventory),
        );
        let capability = ComposeProtectionView {
            runtime_configured: true,
            revision: Some(2),
            preflight: None,
            account_binding: Some(AccountBinding {
                primary_fingerprint: fingerprint.clone(),
                signing_fingerprint: Some(fingerprint.clone()),
                decrypt_primary_fingerprints: vec![fingerprint.clone()],
            }),
            policy: ProtectionPolicy {
                signing: Requirement::Optional,
                encryption: Requirement::Required,
            },
            recipient_binding_count: 1,
        };
        let page = render_openpgp_settings(account, "fixture", &view, Some(&capability));
        let html = page.as_str();
        assert!(html.contains("OpenPGP configured"));
        assert!(html.contains(&format!(
            "id=\"account-key\" readonly value=\"{fingerprint}\""
        )));
        assert!(html.contains("id=\"signing-setting\" readonly value=\"Optional\""));
        assert!(html.contains("id=\"encryption-setting\" readonly value=\"Required\""));
        assert!(html.contains("href=\"/settings/keys?panel=account\">Choose account key"));
        assert!(html
            .contains("href=\"/settings/keys?panel=policy\" aria-label=\"Edit signing policy\""));
        assert!(html.contains(
            "href=\"/settings/keys?panel=policy\" aria-label=\"Edit encryption policy\""
        ));
        assert!(html.contains("href=\"/compose\">Choose for a message"));
        assert!(!html.contains("action=\"/settings/keys/change\""));
        assert!(!html.contains("<button disabled"));
    }

    #[test]
    fn openpgp_settings_unavailable_state_keeps_recovery_navigation_truthful() {
        let page = render_openpgp_settings(
            "alice@example.test",
            "fixture",
            &crate::http_ui::key_inventory_ui::PublicInventoryView::Unavailable,
            None,
        );
        let html = page.as_str();
        assert!(html.contains("OpenPGP unavailable"));
        assert!(html.contains("id=\"signing-setting\" readonly value=\"Unavailable\""));
        assert!(html.contains("id=\"encryption-setting\" readonly value=\"Unavailable\""));
        assert!(html.contains("href=\"/settings/keys?panel=account\""));
        assert!(html.contains("href=\"/settings/keys?panel=policy\""));
        assert!(!html.contains("OpenPGP configured"));
        assert!(!html.contains("name=\"pgp_sign\""));
        assert!(!html.contains("name=\"pgp_encrypt\""));
    }
}
