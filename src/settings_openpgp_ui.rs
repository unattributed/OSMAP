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
        "<div class=\"openpgp-setting-row\"><label for=\"account-key\">Key fingerprint</label><input id=\"account-key\" readonly value=\"{fingerprint}\"></div>",
        "<div class=\"openpgp-setting-row\"><label for=\"signing-setting\">Signing</label><input id=\"signing-setting\" readonly value=\"{signing}\"></div>",
        "<div class=\"openpgp-setting-row\"><label for=\"encryption-setting\">Encryption</label><input id=\"encryption-setting\" readonly value=\"{encryption}\"></div>",
        "<div class=\"openpgp-setting-row\"><label for=\"self-setting\">Encrypt to self</label><input id=\"self-setting\" readonly value=\"Selected per message\"></div>",
        "<p>{recipient_count} recipient bindings approved for this account.</p><a class=\"button-link openpgp-manage\" href=\"/settings/keys\">Manage Keys</a></section>",
        "<section class=\"openpgp-settings-card\"><h2>Policy Behavior</h2><ul class=\"openpgp-policy-list\">{policies}</ul></section></div></div></main>"
    ), header=app_header(account,csrf,"settings-openpgp"),nav=settings_navigation("openpgp"),status=status,fingerprint=fingerprint,signing=signing,encryption=encryption,recipient_count=recipient_count,policies=policies))
}
