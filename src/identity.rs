//! Validated account and mailbox identity boundaries.
//!
//! OSMAP receives identity strings from external auth, persisted session
//! records, and browser flows. This module centralizes the conservative shape
//! required before those strings are reused for sessions, TOTP lookup, audit,
//! or outbound mail.

use std::fmt;

/// Conservative upper bound for an internal account identity.
pub const CANONICAL_USERNAME_MAX_LEN: usize = 320;

/// A validated internal account identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalUsername(String);

impl CanonicalUsername {
    /// Validates an identity before it is reused across security boundaries.
    pub fn parse(value: impl Into<String>) -> Result<Self, IdentityValidationError> {
        let value = value.into();
        validate_identity_text("canonical_username", &value, CANONICAL_USERNAME_MAX_LEN)?;

        if value.chars().any(char::is_whitespace) {
            return Err(IdentityValidationError::UnsafeSyntax {
                field: "canonical_username",
            });
        }

        if value.chars().any(|ch| matches!(ch, '<' | '>' | ',' | ':')) {
            return Err(IdentityValidationError::UnsafeSyntax {
                field: "canonical_username",
            });
        }

        Ok(Self(value))
    }

    /// Returns the validated identity as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the validated identity as an owned string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for CanonicalUsername {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A validated outbound mailbox identity suitable for envelope and From use.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MailboxIdentity(String);

impl MailboxIdentity {
    /// Validates a conservative addr-spec mailbox identity.
    pub fn parse(value: impl Into<String>) -> Result<Self, IdentityValidationError> {
        let value = value.into();
        validate_identity_text("mailbox_identity", &value, CANONICAL_USERNAME_MAX_LEN)?;

        if value.chars().any(char::is_whitespace) {
            return Err(IdentityValidationError::UnsafeSyntax {
                field: "mailbox_identity",
            });
        }

        let mut parts = value.split('@');
        let local = parts.next().unwrap_or_default();
        let domain = parts.next().unwrap_or_default();
        if local.is_empty() || domain.is_empty() || parts.next().is_some() {
            return Err(IdentityValidationError::UnsafeSyntax {
                field: "mailbox_identity",
            });
        }

        if !local.chars().all(is_allowed_email_local_char)
            || !domain.chars().all(is_allowed_email_domain_char)
            || !domain.contains('.')
        {
            return Err(IdentityValidationError::UnsafeSyntax {
                field: "mailbox_identity",
            });
        }

        Ok(Self(value))
    }

    /// Returns the validated mailbox identity as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validation errors for identity boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityValidationError {
    Empty { field: &'static str },
    TooLong { field: &'static str, max_len: usize },
    ControlCharacter { field: &'static str },
    LeadingOrTrailingWhitespace { field: &'static str },
    UnsafeSyntax { field: &'static str },
}

impl IdentityValidationError {
    /// Returns a stable short reason for logs and error conversion.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Empty { .. } => "identity must not be empty",
            Self::TooLong { .. } => "identity exceeded maximum length",
            Self::ControlCharacter { .. } => "identity contains control characters",
            Self::LeadingOrTrailingWhitespace { .. } => {
                "identity contains leading or trailing whitespace"
            }
            Self::UnsafeSyntax { .. } => "identity contains unsafe syntax",
        }
    }
}

fn validate_identity_text(
    field: &'static str,
    value: &str,
    max_len: usize,
) -> Result<(), IdentityValidationError> {
    if value.is_empty() {
        return Err(IdentityValidationError::Empty { field });
    }

    if value.len() > max_len {
        return Err(IdentityValidationError::TooLong { field, max_len });
    }

    if value.trim() != value {
        return Err(IdentityValidationError::LeadingOrTrailingWhitespace { field });
    }

    if value.chars().any(char::is_control) {
        return Err(IdentityValidationError::ControlCharacter { field });
    }

    Ok(())
}

fn is_allowed_email_local_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '/'
                | '='
                | '?'
                | '^'
                | '_'
                | '`'
                | '{'
                | '|'
                | '}'
                | '~'
                | '.'
        )
}

fn is_allowed_email_domain_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_username_rejects_hostile_identity_values() {
        for value in [
            "alice@example.test\r\nBcc: attacker@example.test",
            "alice@example.test\nBcc: attacker@example.test",
            "Alice <alice@example.test>",
            "alice@example.test, attacker@example.test",
            " alice@example.test",
            "alice@example.test ",
            "alice@example.test\t",
        ] {
            assert!(CanonicalUsername::parse(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn canonical_username_accepts_simple_mailbox_identity() {
        let username = CanonicalUsername::parse("alice@example.test")
            .expect("simple canonical username should be accepted");

        assert_eq!(username.as_str(), "alice@example.test");
    }

    #[test]
    fn mailbox_identity_requires_conservative_addr_spec() {
        let mailbox = MailboxIdentity::parse("alice@example.test")
            .expect("simple mailbox should be accepted");
        assert_eq!(mailbox.as_str(), "alice@example.test");

        for value in [
            "Alice <alice@example.test>",
            "alice@example.test, attacker@example.test",
            "alice@example.test\r\nBcc: attacker@example.test",
            "alice@example.test ",
            "alice",
        ] {
            assert!(MailboxIdentity::parse(value).is_err(), "{value:?}");
        }
    }
}
