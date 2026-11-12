//! Bounded mailbox-list parsing for authoring and original reply headers.
//! Supports bare addresses and display names (including quoted commas), not
//! groups, comments, quoted local parts, domain literals or SMTPUTF8 addresses.
use crate::identity::MailboxIdentity;
use crate::send::{ComposeError, ComposePolicy};

fn invalid(reason: &'static str) -> ComposeError {
    ComposeError {
        reason: reason.into(),
    }
}

pub fn parse_address_list(policy: ComposePolicy, value: &str) -> Result<Vec<String>, ComposeError> {
    if value.len()
        > policy
            .max_recipients
            .saturating_mul(policy.recipient_max_len.saturating_add(256))
    {
        return Err(invalid("recipient field exceeded its bounded length"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid("recipient contained control characters"));
    }
    let mut addresses = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut angle = false;
    let mut start = 0;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted {
            match character {
                '\\' => escaped = true,
                '"' => quoted = false,
                _ => {}
            }
            continue;
        }
        match character {
            '"' if !angle => quoted = true,
            '<' if !angle => angle = true,
            '>' if angle => angle = false,
            '"' | '<' | '>' | '(' | ')' | ':' | ';' => {
                return Err(invalid(
                    "recipient used unsupported or ambiguous mailbox syntax",
                ))
            }
            ',' if !angle => {
                append(policy, &value[start..index], &mut addresses)?;
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    if quoted || escaped || angle {
        return Err(invalid("recipient used incomplete mailbox syntax"));
    }
    append(policy, &value[start..], &mut addresses)?;
    Ok(addresses)
}

fn append(
    policy: ComposePolicy,
    value: &str,
    addresses: &mut Vec<String>,
) -> Result<(), ComposeError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(());
    }
    if addresses.len() >= policy.max_recipients {
        return Err(invalid("recipient count exceeded maximum"));
    }
    let address = match value.split_once('<') {
        Some((display, rest)) => {
            if display.len() > 256 {
                return Err(invalid("recipient display name exceeded maximum length"));
            }
            let Some((address, suffix)) = rest.split_once('>') else {
                return Err(invalid("recipient address was incomplete"));
            };
            if !suffix.trim().is_empty() || address.contains(['<', '>']) {
                return Err(invalid("recipient used ambiguous mailbox syntax"));
            }
            address.trim()
        }
        None => value,
    };
    validate_address(policy, address)?;
    addresses.push(address.into());
    Ok(())
}

pub fn validate_address(policy: ComposePolicy, value: &str) -> Result<(), ComposeError> {
    if value.len() > policy.recipient_max_len {
        return Err(invalid("recipient exceeded maximum length"));
    }
    MailboxIdentity::parse(value)
        .map_err(|_| invalid("recipient must be a supported simple mailbox address"))?;
    let Some((local, domain)) = value.split_once('@') else {
        return Err(invalid("recipient mailbox was incomplete"));
    };
    if local.len() > 64
        || local.split('.').any(str::is_empty)
        || domain.len() > 253
        || domain.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        })
    {
        return Err(invalid(
            "recipient mailbox components were outside supported bounds",
        ));
    }
    Ok(())
}

/// Domain names compare without case; preserve local-part case because its
/// equivalence is controlled by the receiving mail system, not this client.
pub fn comparison_key(address: &str) -> String {
    match address.split_once('@') {
        Some((local, domain)) => format!("{local}@{}", domain.to_ascii_lowercase()),
        None => address.to_string(),
    }
}

pub fn deduplicate<'a>(addresses: impl IntoIterator<Item = &'a String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    addresses
        .into_iter()
        .filter(|address| seen.insert(comparison_key(address)))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoted_display_names_unicode_and_multiple_fields_preserve_mailboxes() {
        assert_eq!(parse_address_list(ComposePolicy::default(), "\"Last, First\" <first@example.test>, André <second@example.test>, bare@example.test").unwrap(),
            ["first@example.test", "second@example.test", "bare@example.test"]);
        let input = [
            "first@example.test".into(),
            "first@EXAMPLE.test".into(),
            "First@example.test".into(),
        ];
        assert_eq!(
            deduplicate(&input),
            ["first@example.test", "First@example.test"]
        );
    }
    #[test]
    fn unsupported_ambiguous_and_unbounded_addresses_are_refused_without_echo() {
        for value in [
            "missing",
            "a@example.test\r\nBcc: hidden@example.test",
            "Team: a@example.test;",
            "a@example.test (comment)",
            "\"unclosed <a@example.test>",
            "Name <a@example.test> extra",
            "Name <a@example.test><b@example.test>",
            "Name <a@example.test",
            "Name a@example.test>",
            "a..b@example.test",
            "a@-example.test",
            "a@example..test",
            "\"local\"@example.test",
            "a@[127.0.0.1]",
            "é@example.test",
        ] {
            let error = parse_address_list(ComposePolicy::default(), value)
                .expect_err("unsupported address");
            assert!(!error.reason.contains("@"));
        }
        let too_many = vec!["a@example.test"; 17].join(",");
        assert!(parse_address_list(ComposePolicy::default(), &too_many).is_err());
        assert!(parse_address_list(
            ComposePolicy::default(),
            &format!("{}@example.test", "a".repeat(65))
        )
        .is_err());
    }
}
