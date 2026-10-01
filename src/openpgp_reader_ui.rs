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
        ProtectedError::Locked => "The mailbox key is locked. Unlock the mailbox agent through its operator-controlled key workflow, then reload this message.",
        ProtectedError::MissingKey => "No usable decryption key is available for this account. The encrypted content has not been displayed.",
        ProtectedError::UnknownSigner => "The signing key is unavailable. The signature could not be verified and protected content has not been displayed.",
        ProtectedError::ExpiredKey => "The configured sender key has expired. Its signature was not accepted and protected content has not been displayed.",
        ProtectedError::RevokedKey => "The configured sender key is revoked. Its signature was not accepted and protected content has not been displayed.",
        ProtectedError::IntegrityFailure => "Encrypted content failed its integrity check. No decrypted content has been displayed.",
        ProtectedError::SignatureFailure => "The message signature could not be validated. Protected content has not been displayed.",
        ProtectedError::UnsupportedCrypto | ProtectedError::UnsupportedProtectionLayer | ProtectedError::UnsupportedTextEncoding | ProtectedError::Mime(_) => "This message uses an unsupported or invalid protection format. Protected content has not been displayed.",
        _ => "OpenPGP processing is unavailable. Protected content has not been displayed. You can reload the message when the mailbox capability is available.",
    }
}

pub fn render(state: &ReaderState) -> String {
    let (summary, signature, identity, decrypted, key, fingerprint, explanation) = match state {
        ReaderState::Assessed(p) => (
            if p.decrypted_on_mail_host { "Decrypted on mail host" } else if p.signature == SignatureValidity::Valid { "Signature verified" } else { "No OpenPGP protection" },
            if p.signature == SignatureValidity::Valid { "cryptographically valid" } else { "unsigned" },
            match p.signer_identity {
                SignerIdentityState::ConfirmedBinding => "matches the confirmed sender binding",
                SignerIdentityState::Mismatch => "does not match the confirmed sender binding",
                SignerIdentityState::Unknown => "identity binding unknown",
                SignerIdentityState::NotApplicable => "not applicable",
            },
            if p.decrypted_on_mail_host { "yes" } else { "no" },
            match p.key_validity {
                Some(KeyValidity::Current) => "current",
                Some(KeyValidity::Expired) => "expired",
                Some(KeyValidity::Revoked) => "revoked",
                _ => "not established",
            },
            p.signer_primary_fingerprint.as_deref().unwrap_or("not established"),
            "A verified signature and a confirmed sender binding are separate checks. Message content still passes protected rendering.",
        ),
        ReaderState::Refused(error) => ("OpenPGP processing refused", "not accepted", "not established", "not released", "not established", "not established", refusal_description(*error)),
    };
    format!(concat!(
        "<details class=\"openpgp-reader-states\" aria-label=\"OpenPGP reader states\" data-openpgp-reader-states=\"assessed\"><summary><strong>{}</strong><span>{}</span></summary>",
        "<p>{}</p><dl class=\"openpgp-state-list\"><dt>Decrypted on mail host</dt><dd>{}</dd><dt>Signature</dt><dd>{}</dd><dt>Signer identity</dt><dd>{}</dd><dt>Signer fingerprint</dt><dd>{}</dd><dt>Key validity</dt><dd>{}</dd></dl>",
        "<p class=\"muted openpgp-boundary-note\">Verified signatures do not make content safe. Active content and remote images remain blocked.</p></details>"
    ), crate::http_support::escape_html(summary), crate::http_support::escape_html(signature), crate::http_support::escape_html(explanation), decrypted, signature, identity, crate::http_support::escape_html(fingerprint), key)
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
    }
    #[test]
    fn refused_content_is_not_reported_as_successful_decryption() {
        let html = render(&ReaderState::Refused(ProtectedError::IntegrityFailure));
        assert!(html.contains("integrity check"));
        assert!(html.contains("not released"));
        assert!(!html.contains("cryptographically valid"));
    }
}
