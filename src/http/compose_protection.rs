//! Authenticated compose protection projection and strict finite form choices.
use super::*;
use crate::openpgp_bindings::{Preflight, PreflightState, Recipients, Selections};
use crate::send::ProtectionIntent;

pub struct ComposeProtectionView {
    pub runtime_configured: bool,
    pub revision: Option<u64>,
    pub preflight: Option<Preflight>,
    pub account_binding: Option<crate::openpgp_bindings::AccountBinding>,
    pub policy: crate::openpgp_bindings::ProtectionPolicy,
    pub recipient_binding_count: usize,
}

/// Browser choices are intent, never fingerprints, key paths or agent authority.
pub(super) fn intent_from_form(
    form: &BTreeMap<String, String>,
) -> Result<ProtectionIntent, &'static str> {
    let flag = |name| match form.get(name).map(String::as_str) {
        None => Ok(false),
        Some("on") => Ok(true),
        _ => Err("Invalid OpenPGP selection. Refresh the compose page."),
    };
    let sign = flag("pgp_sign")?;
    let encrypt = flag("pgp_encrypt")?;
    let encrypt_to_self = flag("pgp_self")?;
    if encrypt_to_self && !encrypt {
        return Err("Encrypt to self requires encryption.");
    }
    let binding_revision = match form.get("pgp_binding_revision") {
        None => None,
        Some(value)
            if !value.is_empty()
                && value.len() <= 20
                && value.bytes().all(|b| b.is_ascii_digit())
                && (value == "0" || !value.starts_with('0')) =>
        {
            Some(
                value
                    .parse()
                    .map_err(|_| "Invalid OpenPGP binding revision. Refresh the compose page.")?,
            )
        }
        _ => return Err("Invalid OpenPGP binding revision. Refresh the compose page."),
    };
    if (sign || encrypt) && binding_revision.is_none() {
        return Err("OpenPGP binding state is missing. Refresh the compose page.");
    }
    Ok(ProtectionIntent {
        sign,
        encrypt,
        encrypt_to_self,
        binding_revision,
    })
}

/// Render only: retain finite submitted choices after a refused form without
/// granting them dispatch authority or replacing the pinned binding revision.
pub(super) fn retained_intent_from_form(form: &BTreeMap<String, String>) -> ProtectionIntent {
    let revision = form.get("pgp_binding_revision").and_then(|value| {
        if value.is_empty()
            || value.len() > 20
            || !value.bytes().all(|b| b.is_ascii_digit())
            || (value != "0" && value.starts_with('0'))
        {
            None
        } else {
            value.parse().ok()
        }
    });
    ProtectionIntent {
        sign: form.get("pgp_sign").is_some_and(|value| value == "on"),
        encrypt: form.get("pgp_encrypt").is_some_and(|value| value == "on"),
        encrypt_to_self: form.get("pgp_self").is_some_and(|value| value == "on"),
        binding_revision: revision,
    }
}

impl RuntimeBrowserGateway {
    pub(super) fn compose_protection_view(
        &self,
        session: &ValidatedSession,
        to: &str,
        cc: &str,
        bcc: &str,
        intent: ProtectionIntent,
    ) -> Option<ComposeProtectionView> {
        self.crypto_client.as_ref()?;
        let account = &session.record.canonical_username;
        let record =
            crate::openpgp_bindings::BindingStore::new(self.settings_dir.join("openpgp-bindings"))
                .load(account)
                .ok()?;
        let revision = Some(record.revision);
        let inventory = self
            .public_inventory_client
            .as_ref()
            .and_then(|client| client.read(account).ok());
        let parse =
            |raw: &str| crate::mail_address::parse_address_list(ComposePolicy::default(), raw).ok();
        let preflight = match (
            inventory.as_ref(),
            parse(to),
            parse(cc),
            parse(bcc),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|v| v.as_secs()),
        ) {
            (Some(inventory), Some(to), Some(cc), Some(bcc), Some(now)) => {
                crate::openpgp_bindings::evaluate(
                    account,
                    &record,
                    inventory,
                    Recipients {
                        to: &to,
                        cc: &cc,
                        bcc: &bcc,
                    },
                    Selections {
                        sign: intent.sign,
                        encrypt: intent.encrypt,
                        encrypt_to_self: intent.encrypt_to_self,
                    },
                    now,
                )
                .ok()
            }
            _ => None,
        };
        Some(ComposeProtectionView {
            runtime_configured: true,
            revision,
            preflight,
            account_binding: record.account_binding.clone(),
            policy: record.policy,
            recipient_binding_count: record.recipient_bindings.len(),
        })
    }
}

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn render_protected_compose_page(
        &self,
        session: &ValidatedSession,
        mut model: ComposePageModel<'_>,
    ) -> TrustedHtml {
        model.openpgp = self.gateway.compose_protection(
            session,
            model.to_value,
            model.cc_value,
            model.bcc_value,
            model.protection,
        );
        render_compose_page(&model)
    }
}

pub(crate) fn selection_text(state: PreflightState) -> &'static str {
    match state {
        PreflightState::Green => "Eligible public keys",
        PreflightState::Orange => "Attention",
        PreflightState::Blocked => "Blocked",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_protection_requires_exact_finite_form_and_version() {
        let mut fields = BTreeMap::new();
        fields.insert("pgp_sign".to_string(), "on".to_string());
        assert!(intent_from_form(&fields).is_err());
        fields.insert("pgp_binding_revision".to_string(), "7".to_string());
        let intent = intent_from_form(&fields).unwrap();
        assert!(intent.sign);
        assert_eq!(intent.binding_revision, Some(7));
        fields.insert("pgp_sign".to_string(), "false".to_string());
        assert!(intent_from_form(&fields).is_err());
        fields.remove("pgp_sign");
        fields.insert("pgp_self".to_string(), "on".to_string());
        assert!(intent_from_form(&fields).is_err());
        fields.insert("pgp_encrypt".to_string(), "on".to_string());
        assert!(intent_from_form(&fields).is_ok());
        fields.insert(
            "pgp_binding_revision".to_string(),
            "18446744073709551616".to_string(),
        );
        assert!(intent_from_form(&fields).is_err());
        let retained = retained_intent_from_form(&fields);
        assert!(retained.encrypt && retained.encrypt_to_self);
        assert_eq!(retained.binding_revision, None);
    }
}
