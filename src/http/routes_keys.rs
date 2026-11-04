//! Session/CSRF-bound fresh authentication for PAGE21 key-binding changes.
use super::*;
use crate::key_management::{Action, Error, MutationRequest};
use crate::openpgp_bindings::Requirement;
use std::collections::BTreeMap;

// Error pages are always rebuilt from metadata. Request-local copies of key
// material and credentials are never retained for redisplay or Debug output.
struct SensitiveKeyForm(BTreeMap<String, String>);
impl std::ops::Deref for SensitiveKeyForm {
    type Target = BTreeMap<String, String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for SensitiveKeyForm {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for SensitiveKeyForm {
    fn drop(&mut self) {
        for (_, value) in std::mem::take(&mut self.0) {
            crate::openpgp_personal::clear(&mut value.into_bytes());
        }
    }
}

fn key_form(body: &[u8], content_type: Option<&str>) -> Result<BTreeMap<String, String>, Error> {
    if content_type.is_some_and(crate::http_form::is_multipart_form_data) {
        let limit = crate::key_management::MAX_PUBLIC_CERTIFICATE;
        let (mut parsed, file_names) = crate::http_form::parse_key_upload_form(
            body,
            content_type.ok_or(Error::Invalid)?,
            12,
            256 * 1024,
            ComposePolicy {
                max_attachments: 1,
                attachment_max_bytes: limit,
                total_attachment_max_bytes: limit,
                ..ComposePolicy::default()
            },
        )
        .map_err(|_| Error::Invalid)?;
        let expected_file = match parsed.fields.get("key_action").map(String::as_str) {
            Some("import_personal") => "personal_certificate",
            Some("import_public") => "attachment",
            _ => return Err(Error::Invalid),
        };
        if parsed.upload_error.is_some()
            || file_names != [expected_file]
            || parsed.fields.contains_key("certificate")
            || !matches!(
                parsed.fields.get("key_action").map(String::as_str),
                Some("import_public" | "import_personal")
            )
            || parsed.attachments.len() != 1
        {
            return Err(Error::Invalid);
        }
        let upload = parsed.attachments.pop().ok_or(Error::Invalid)?;
        if upload.body.is_empty()
            || upload.body.len() > limit
            || !upload.body.is_ascii()
            || !upload
                .filename
                .rsplit_once('.')
                .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("asc"))
        {
            return Err(Error::Invalid);
        }
        // The filename and MIME type are upload metadata, never key authority
        // or filesystem paths. Existing native inspection validates the packets.
        let certificate = String::from_utf8(upload.body).map_err(|_| Error::Invalid)?;
        parsed.fields.insert("certificate".into(), certificate);
        Ok(parsed.fields)
    } else if allows_urlencoded_request_body(content_type) {
        let form = parse_urlencoded_form(body, 12, 256 * 1024).map_err(|_| Error::Invalid)?;
        if matches!(
            form.get("key_action").map(String::as_str),
            Some("import_public" | "import_personal")
        ) || form.contains_key("certificate")
        {
            return Err(Error::Invalid);
        }
        Ok(form)
    } else {
        Err(Error::Invalid)
    }
}

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
        "import_personal" => &["certificate", "key_passphrase"],
        "unlock_personal" => &["key_passphrase"],
        "lock_personal" => &[],
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
        "import_personal" => Action::ImportPersonal {
            certificate: value("certificate").as_bytes(),
            passphrase: value("key_passphrase").as_bytes(),
        },
        "unlock_personal" => Action::UnlockPersonal {
            passphrase: value("key_passphrase").as_bytes(),
        },
        "lock_personal" => Action::LockPersonal,
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
        let personal = personal_key_ui::render(
            &session.record.canonical_username,
            &session.record.csrf_token,
            outcome
                .state
                .bindings
                .as_ref()
                .map_or(0, |record| record.revision),
            self.gateway.personal_key_state(&session).as_ref(),
        );
        HandledHttpResponse {
            response: html_response(
                200,
                "OK",
                "OpenPGP Key Management",
                crate::http_ui::key_inventory_ui::render_key_management_panel_with_personal(
                    &session.record.canonical_username,
                    &session.record.csrf_token,
                    &outcome.state,
                    None,
                    panel,
                    &personal,
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
        let mut form = if request.query_params.is_empty() {
            key_form(
                &request.body,
                request.headers.get("content-type").map(String::as_str),
            )
            .ok()
            .map(SensitiveKeyForm)
        } else {
            None
        };
        let Some(ref mut form) = form else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Key Change Not Saved",
                    "<p>The key management form could not be read. Reload before retrying. Choose one nonempty .asc file up to 64 KiB in the correct personal or public key form. Pasted certificates are not accepted.</p>",
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
        let remember = match form.remove("remember_key") {
            None => false,
            Some(value)
                if value == "1"
                    && form.get("key_action").map(String::as_str) == Some("unlock_personal") =>
            {
                true
            }
            Some(_) => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Key Request",
                        "<p>Reload the key form before retrying.</p>",
                    ),
                    audit_events,
                }
            }
        };
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
                let Some(token) = session_cookie_value(request, self.policy.session_cookie_name)
                    .and_then(|value| SessionToken::new(value).ok())
                else {
                    return HandledHttpResponse {
                        response: html_response(
                            401,
                            "Unauthorized",
                            "Sign In Required",
                            "<p>Sign in again before changing keys or protection policy.</p>",
                        ),
                        audit_events,
                    };
                };
                let outcome = self.gateway.change_keys(
                    context,
                    &session,
                    &token,
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
            Ok(()) => {
                let personal_change = matches!(
                    form.get("key_action").map(String::as_str),
                    Some("unlock_personal" | "lock_personal" | "import_personal")
                );
                let mut response = redirect_response(303, "See Other", "/settings/keys");
                if remember {
                    match self.remember_browser_key(request, &session) {
                        Ok(cookie) => response = response.with_header("Set-Cookie", cookie),
                        Err(()) => {
                            response = html_response(200, "OK", "Personal Key Unlocked", "<p>Your key was unlocked for this session, but remembered access could not be established. Do not repeat the import. <a href=\"/settings/keys\">Review personal-key access</a>.</p>")
                                .with_header("Set-Cookie", self.forget_browser_key(request).0);
                        }
                    }
                } else if personal_change {
                    response =
                        response.with_header("Set-Cookie", self.forget_browser_key(request).0);
                }
                HandledHttpResponse {
                    response,
                    audit_events,
                }
            }
            Err(e) => {
                let state = self.gateway.key_management(context, &session);
                audit_events.extend(state.audit_events);
                let personal = personal_key_ui::render(
                    &session.record.canonical_username,
                    &session.record.csrf_token,
                    state
                        .state
                        .bindings
                        .as_ref()
                        .map_or(0, |record| record.revision),
                    self.gateway.personal_key_state(&session).as_ref(),
                );
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
                        crate::http_ui::key_inventory_ui::render_key_management_panel_with_personal(
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
                            &personal,
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
    fn upload_form(fields: &[(&str, &str)], files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, value) in fields {
            body.extend_from_slice(format!("--key-upload\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes());
        }
        for (filename, bytes) in files {
            body.extend_from_slice(format!("--key-upload\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
            body.extend_from_slice(bytes);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"--key-upload--\r\n");
        body
    }
    const UPLOAD_TYPE: Option<&str> = Some("multipart/form-data; boundary=key-upload");
    #[test]
    fn public_key_upload_preserves_file_and_credentials_without_filename_authority() {
        let armor = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\nYWJj+ZGVm\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n";
        let fields = [
            ("key_action", "import_public"),
            ("binding_revision", "0"),
            ("public_inventory_revision", &"a".repeat(64)),
            ("expected_primary_fingerprint", &"A".repeat(40)),
            ("current_password", "synthetic +&= café"),
            ("totp_code", "123456"),
            ("csrf_token", "synthetic-csrf"),
        ];
        let parsed = key_form(
            &upload_form(&fields, &[("publickey.cBwZTCpU@protonmail.com-02b34119c22074fc68b10e23e3294df8de68c834.asc", armor)]),
            UPLOAD_TYPE,
        )
        .unwrap();
        assert_eq!(parsed.get("certificate").unwrap().as_bytes(), armor);
        assert_eq!(
            parsed.get("current_password").unwrap(),
            "synthetic +&= café"
        );
        assert!(!parsed.contains_key("attachment"));
        assert!(!parsed.contains_key("filename"));
        assert!(
            matches!(action(&parsed).unwrap().0, Action::ImportPublic { certificate, .. } if certificate == armor)
        );
    }
    #[test]
    fn public_key_upload_requires_one_bounded_ascii_asc_file_and_no_mixed_source() {
        let fields = [("key_action", "import_public")];
        let limit = crate::key_management::MAX_PUBLIC_CERTIFICATE;
        assert!(key_form(
            &upload_form(&fields, &[("key.ASC", &vec![b'A'; limit])]),
            UPLOAD_TYPE
        )
        .is_ok());
        for files in [
            vec![],
            vec![("key.asc", b"".as_slice())],
            vec![("key.txt", b"public".as_slice())],
            vec![("../key.asc", b"public".as_slice())],
            vec![("key.asc", b"\xff".as_slice())],
            vec![
                ("one.asc", b"first".as_slice()),
                ("two.asc", b"second".as_slice()),
            ],
        ] {
            assert_eq!(
                key_form(&upload_form(&fields, &files), UPLOAD_TYPE).err(),
                Some(Error::Invalid)
            );
        }
        let oversized = vec![b'A'; limit + 1];
        assert!(key_form(
            &upload_form(&fields, &[("key.asc", &oversized)]),
            UPLOAD_TYPE
        )
        .is_err());
        for fields in [
            vec![("key_action", "import_public"), ("certificate", "pasted")],
            vec![
                ("key_action", "import_public"),
                ("key_action", "import_public"),
            ],
            vec![("key_action", "clear_account")],
        ] {
            assert!(key_form(
                &upload_form(&fields, &[("key.asc", b"public")]),
                UPLOAD_TYPE
            )
            .is_err());
        }
        assert!(key_form(
            b"key_action=import_public&certificate=pasted",
            Some("application/x-www-form-urlencoded")
        )
        .is_err());
        let ordinary = key_form(
            b"key_action=clear_account&binding_revision=0",
            Some("application/x-www-form-urlencoded"),
        )
        .unwrap();
        assert!(matches!(action(&ordinary).unwrap().0, Action::ClearAccount));
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
