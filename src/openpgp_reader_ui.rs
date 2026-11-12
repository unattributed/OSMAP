//! Reader status uses actual processing results, independently of identity trust.
use crate::protected_message::{
    KeyValidity, ProtectedError, ProtectionState, SignatureValidity, SignerIdentityState,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReaderState {
    Assessed(ProtectionState),
    Refused(ProtectedError),
}

pub fn refusal_description(error: ProtectedError) -> &'static str {
    match error {
        ProtectedError::Locked => "The mailbox key is locked. Open Settings → Keys → Your personal key and unlock it, then reload this message. If personal-key controls are unavailable, contact the mail operator.",
        ProtectedError::MissingKey => "No usable decryption key is available for this account. The encrypted content has not been displayed.",
        ProtectedError::UnknownSigner => "The signing key is unavailable. The signature could not be verified and protected content has not been displayed.",
        ProtectedError::ExpiredKey => "The signing key has expired. Its signature was not accepted and protected content has not been displayed.",
        ProtectedError::RevokedKey => "The signing key is revoked. Its signature was not accepted and protected content has not been displayed.",
        ProtectedError::IntegrityFailure => "Encrypted content failed its integrity check. No decrypted content has been displayed.",
        ProtectedError::SignatureFailure => "The message signature could not be validated. Protected content has not been displayed.",
        ProtectedError::UnsupportedCrypto | ProtectedError::UnsupportedProtectionLayer | ProtectedError::UnsupportedTextEncoding | ProtectedError::Mime(_) => "This message uses an unsupported or invalid protection format. Protected content has not been displayed.",
        _ => "OpenPGP processing could not be completed with the available keys, services or message format. Protected content has not been displayed.",
    }
}

pub fn render(state: &ReaderState) -> String {
    let assessment = match state {
        ReaderState::Assessed(_) => "assessed",
        ReaderState::Refused(_) => "refused",
    };
    let (summary, signature, identity, decrypted, key, fingerprint, explanation) = match state {
        ReaderState::Assessed(p) => (
            if p.decrypted_on_mail_host {
                "Decrypted on mail host"
            } else if p.signature == SignatureValidity::Valid {
                "Signature verified"
            } else {
                "No OpenPGP protection"
            },
            if p.signature == SignatureValidity::Valid {
                "cryptographically valid"
            } else {
                "unsigned"
            },
            match p.signer_identity {
                SignerIdentityState::ConfirmedBinding => "matches the confirmed sender binding",
                SignerIdentityState::Mismatch => "does not match the confirmed sender binding",
                SignerIdentityState::Unknown => "identity binding unknown",
                SignerIdentityState::NotApplicable => "not applicable",
            },
            if p.decrypted_on_mail_host {
                "yes"
            } else {
                "no"
            },
            match p.key_validity {
                Some(KeyValidity::Current) => "current",
                Some(KeyValidity::Expired) => "expired",
                Some(KeyValidity::Revoked) => "revoked",
                _ => "not established",
            },
            p.signer_primary_fingerprint
                .as_deref()
                .unwrap_or("not established"),
            if p.decrypted_on_mail_host {
                "Decryption ran on this OSMAP server. Your browser receives the result over HTTPS. A verified signature and a confirmed sender binding are separate checks. Message content still passes protected rendering."
            } else {
                "A verified signature and a confirmed sender binding are separate checks. Message content still passes protected rendering."
            },
        ),
        ReaderState::Refused(error) => (
            "OpenPGP processing refused",
            "not accepted",
            "not established",
            "not released",
            "not established",
            "not established",
            refusal_description(*error),
        ),
    };
    format!(concat!(
        "<details class=\"openpgp-reader-states\" aria-label=\"OpenPGP reader states\" data-openpgp-reader-states=\"{}\"><summary><strong>{}</strong><span>{}</span></summary>",
        "<p>{}</p><dl class=\"openpgp-state-list\"><dt>Decrypted on mail host</dt><dd>{}</dd><dt>Signature</dt><dd>{}</dd><dt>Signer identity</dt><dd>{}</dd><dt>Signer fingerprint</dt><dd>{}</dd><dt>Key validity</dt><dd>{}</dd></dl>",
        "<p class=\"muted openpgp-boundary-note\">Verified signatures do not make content safe. Active content and remote images remain blocked.</p><p><a href=\"/settings?section=openpgp\">OpenPGP settings</a></p></details>"
    ), assessment, crate::http_support::escape_html(summary), crate::http_support::escape_html(signature), crate::http_support::escape_html(explanation), decrypted, signature, identity, crate::http_support::escape_html(fingerprint), key)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn valid_signature_does_not_claim_sender_identity_or_content_safety() {
        let state = ReaderState::Assessed(ProtectionState {
            decrypted_on_mail_host: true,
            signature: SignatureValidity::Valid,
            signer_identity: SignerIdentityState::Mismatch,
            signer_primary_fingerprint: Some("A".repeat(40)),
            key_validity: Some(KeyValidity::Current),
        });
        let html = render(&state);
        assert!(html.contains("cryptographically valid"));
        assert!(html.contains("does not match"));
        assert!(html.contains("Verified signatures do not make content safe"));
        assert!(!html.contains("ui-only"));
        assert!(html.contains("data-openpgp-reader-states=\"assessed\""));
        assert!(html.contains("href=\"/settings?section=openpgp\""));
    }
    #[test]
    fn refused_content_is_not_reported_as_successful_decryption() {
        let html = render(&ReaderState::Refused(ProtectedError::IntegrityFailure));
        assert!(html.contains("integrity check"));
        assert!(html.contains("not released"));
        assert!(!html.contains("cryptographically valid"));
        assert!(html.contains("data-openpgp-reader-states=\"refused\""));
        assert!(html.contains("href=\"/settings?section=openpgp\""));
        assert!(!html.contains("data-openpgp-reader-states=\"assessed\""));
    }

    #[test]
    fn unavailable_processing_keeps_key_service_and_format_uncertainty() {
        let html = render(&ReaderState::Refused(ProtectedError::Unavailable));
        for category in ["keys", "services", "format"] {
            assert!(
                html.contains(category),
                "unavailable processing must retain uncertainty"
            );
        }
        assert!(html.contains("content has not been displayed"));
        assert!(!html.contains("No usable decryption key"));
        assert!(!html.contains("failed its integrity check"));
        assert!(!html.contains("cryptographically valid"));
    }

    #[test]
    fn successful_decryption_explains_osmap_execution_and_browser_https_delivery() {
        let assessed = |decrypted, signature| {
            ReaderState::Assessed(ProtectionState {
                decrypted_on_mail_host: decrypted,
                signature,
                signer_identity: SignerIdentityState::Unknown,
                signer_primary_fingerprint: None,
                key_validity: None,
            })
        };
        for signature in [SignatureValidity::Unsigned, SignatureValidity::Valid] {
            let html = render(&assessed(true, signature));
            assert!(html.contains("<summary><strong>Decrypted on mail host</strong>"));
            assert!(
                html.contains("this OSMAP server"),
                "successful decryption must identify the OSMAP execution server"
            );
            assert!(
                html.contains("browser") && html.contains("HTTPS"),
                "successful decryption must explain delivery to the browser over HTTPS"
            );
            for unsupported_claim in [
                "Decrypted on this device",
                "Decrypted in your browser",
                "Decrypted on the authoritative mail server",
                "zero-access",
                "zero-knowledge",
            ] {
                assert!(!html.contains(unsupported_claim));
            }
        }
        for state in [
            assessed(false, SignatureValidity::Valid),
            ReaderState::Refused(ProtectedError::Locked),
        ] {
            let html = render(&state);
            assert!(!html.contains("<summary><strong>Decrypted on mail host</strong>"));
            assert!(!html.contains("this OSMAP server"));
            assert!(!html.contains("HTTPS"));
        }
    }
}
