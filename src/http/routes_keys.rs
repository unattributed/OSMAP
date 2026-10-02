//! Session/CSRF-bound fresh authentication for PAGE21 key-binding changes.
use super::*;
use crate::key_management::{Action, Error, MutationRequest};
use crate::openpgp_bindings::Requirement;
use std::collections::BTreeMap;

fn requirement(value: &str) -> Result<Requirement, Error> {
    match value {
        "required" => Ok(Requirement::Required),
        "optional" => Ok(Requirement::Optional),
        "disabled" => Ok(Requirement::Disabled),
        _ => Err(Error::Invalid),
    }
}
fn action<'a>(
    form: &'a BTreeMap<String, String>,
) -> Result<(Action<'a>, u64, Option<&'a str>), Error> {
    let value = |key: &str| form.get(key).map(String::as_str).unwrap_or("");
    let name = value("key_action");
    let specific: &[&str] = match name {
        "set_account" => &[
            "primary_fingerprint",
            "signing_fingerprint",
            "decrypt_fingerprints",
        ],
        "clear_account" | "clear_all_bindings" => &[],
        "set_recipient" => &["address", "primary_fingerprint", "encryption"],
        "remove_recipient" => &["address"],
        "set_policy" => &["signing", "encryption"],
        "import_public" => &[
            "certificate",
            "expected_primary_fingerprint",
            "public_inventory_revision",
        ],
        "remove_public" => &["primary_fingerprint", "public_inventory_revision"],
        _ => return Err(Error::Invalid),
    };
    if form.keys().any(|k| {
        !specific.contains(&k.as_str())
            && ![
                "key_action",
                "binding_revision",
                "csrf_token",
                "current_password",
                "totp_code",
            ]
            .contains(&k.as_str())
    }) {
        return Err(Error::Invalid);
    }
    let raw = value("binding_revision");
    let revision = raw
        .parse::<u64>()
        .ok()
        .filter(|n| n.to_string() == raw)
        .ok_or(Error::Invalid)?;
    let public_revision = if matches!(name, "import_public" | "remove_public") {
        let value = value("public_inventory_revision");
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::Invalid);
        }
        Some(value)
    } else {
        None
    };
    let action = match name {
        "set_account" => Action::SetAccount {
            primary_fingerprint: value("primary_fingerprint"),
            signing_fingerprint: (!value("signing_fingerprint").is_empty())
                .then_some(value("signing_fingerprint")),
            decrypt_fingerprints: value("decrypt_fingerprints"),
        },
        "clear_account" => Action::ClearAccount,
        "clear_all_bindings" => Action::ClearAllBindings,
        "set_recipient" => Action::SetRecipient {
            address: value("address"),
            primary_fingerprint: value("primary_fingerprint"),
            encryption: requirement(value("encryption"))?,
        },
        "remove_recipient" => Action::RemoveRecipient {
            address: value("address"),
        },
        "set_policy" => Action::SetPolicy {
            signing: requirement(value("signing"))?,
            encryption: requirement(value("encryption"))?,
        },
        "import_public" => Action::ImportPublic {
            certificate: value("certificate").as_bytes(),
            expected_primary_fingerprint: value("expected_primary_fingerprint"),
        },
        "remove_public" => Action::RemovePublic {
            primary_fingerprint: value("primary_fingerprint"),
        },
        _ => return Err(Error::Invalid),
    };
    Ok((action, revision, public_revision))
}
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_key_management_page(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let panel = request.query_params.get("panel").map(String::as_str);
        if request.query_params.keys().any(|key| key != "panel")
            || panel.is_some_and(|value| {
                !["account", "policy", "recipient", "import", "inventory"].contains(&value)
            })
        {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Key Management Request",
                    "<p>Open Key Management from OpenPGP Settings.</p>",
                ),
                audit_events,
            };
        }
        let outcome = self.gateway.key_management(context, &session);
        audit_events.extend(outcome.audit_events);
        HandledHttpResponse {
            response: html_response(
                200,
                "OK",
                "OpenPGP Key Management",
                crate::http_ui::key_inventory_ui::render_key_management_panel(
                    &session.record.canonical_username,
                    &session.record.csrf_token,
                    &outcome.state,
                    None,
                    panel,
                ),
            ),
            audit_events,
        }
    }
    pub(super) fn handle_key_management_change(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let mut form = if request.query_params.is_empty()
            && allows_urlencoded_request_body(
                request.headers.get("content-type").map(String::as_str),
            ) {
            parse_urlencoded_form(&request.body, 12, 256 * 1024).ok()
        } else {
            None
        };
        let Some(ref mut form) = form else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Key Change Not Saved",
                    "<p>The key management form could not be read. Reload before retrying.</p>",
                ),
                audit_events,
            };
        };
        if let Some(r) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return r;
        }
        for key in [
            "primary_fingerprint",
            "signing_fingerprint",
            "expected_primary_fingerprint",
        ] {
            if let Some(v) = form.get_mut(key) {
                *v = v.trim().to_ascii_uppercase();
            }
        }
        if let Some(v) = form.get_mut("decrypt_fingerprints") {
            *v = v
                .split(',')
                .map(|s| s.trim().to_ascii_uppercase())
                .collect::<Vec<_>>()
                .join(",");
        }
        let result = match action(form) {
            Err(e) => Err(e),
            Ok((action, expected_revision, expected_public_revision)) => {
                let outcome = self.gateway.change_keys(
                    context,
                    &session,
                    MutationRequest {
                        action,
                        expected_revision,
                        expected_public_revision,
                        password: form
                            .get("current_password")
                            .map(String::as_str)
                            .unwrap_or(""),
                        totp: form.get("totp_code").map(String::as_str).unwrap_or(""),
                    },
                );
                audit_events.extend(outcome.audit_events);
                outcome.result
            }
        };
        match result {
            Ok(()) => HandledHttpResponse {
                response: redirect_response(303, "See Other", "/settings/keys"),
                audit_events,
            },
            Err(e) => {
                let state = self.gateway.key_management(context, &session);
                audit_events.extend(state.audit_events);
                let (status, reason) = match e {
                    Error::Authentication => (403, "Forbidden"),
                    Error::Throttled => (429, "Too Many Requests"),
                    Error::Stale => (409, "Conflict"),
                    Error::Unavailable | Error::Unconfirmed => (503, "Service Unavailable"),
                    _ => (400, "Bad Request"),
                };
                HandledHttpResponse {
                    response: html_response(
                        status,
                        reason,
                        "Key Change Not Saved",
                        crate::http_ui::key_inventory_ui::render_key_management_panel(
                            &session.record.canonical_username,
                            &session.record.csrf_token,
                            &state.state,
                            Some(e.message()),
                            Some(match form.get("key_action").map(String::as_str) {
                                Some("set_account" | "clear_account") => "account",
                                Some("set_policy" | "clear_all_bindings") => "policy",
                                Some("import_public") => "import",
                                Some("remove_public") => "inventory",
                                _ => "recipient",
                            }),
                        ),
                    ),
                    audit_events,
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn form(action: &str) -> BTreeMap<String, String> {
        [
            ("key_action".into(), action.into()),
            ("binding_revision".into(), "0".into()),
        ]
        .into()
    }
    #[test]
    fn key_management_form_rejects_authority_fields_and_noncanonical_revision() {
        let mut f = form("clear_account");
        assert!(action(&f).is_ok());
        for field in ["username", "confirmed", "home", "session_id"] {
            f.insert(field.into(), "x".into());
            assert!(action(&f).is_err());
            f.remove(field);
        }
        f.insert("binding_revision".into(), "00".into());
        assert!(action(&f).is_err());
    }
    #[test]
    fn key_management_form_requires_explicit_policy_values() {
        let mut f = form("set_policy");
        f.insert("signing".into(), "optional".into());
        f.insert("encryption".into(), "required".into());
        assert!(action(&f).is_ok());
        f.insert("encryption".into(), "on".into());
        assert!(action(&f).is_err());
    }
    #[test]
    fn public_mutation_requires_canonical_page_load_inventory_revision() {
        for name in ["import_public", "remove_public"] {
            let mut f = form(name);
            assert_eq!(action(&f).err(), Some(Error::Invalid));
            f.insert("public_inventory_revision".into(), "A".repeat(64));
            assert_eq!(action(&f).err(), Some(Error::Invalid));
            f.insert("public_inventory_revision".into(), "a".repeat(64));
            assert!(action(&f).is_ok());
        }
        let mut f = form("clear_account");
        f.insert("public_inventory_revision".into(), "a".repeat(64));
        assert_eq!(action(&f).err(), Some(Error::Invalid));
    }
}
