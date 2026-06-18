//! Typed HTML values for the browser rendering boundary.
//!
//! `EscapedHtml` is created only by escaping untrusted text. `TrustedHtml`
//! represents complete template or sanitizer output and is the only HTML body
//! type accepted by the HTTP response builder.

use std::fmt;
use std::ops::Deref;

/// Text escaped for safe insertion into an HTML text or quoted-attribute
/// context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscapedHtml(String);

impl EscapedHtml {
    /// Escapes HTML-significant characters in an untrusted string.
    pub fn new(value: &str) -> Self {
        let mut escaped = String::with_capacity(value.len());
        for ch in value.chars() {
            match ch {
                '&' => escaped.push_str("&amp;"),
                '<' => escaped.push_str("&lt;"),
                '>' => escaped.push_str("&gt;"),
                '"' => escaped.push_str("&quot;"),
                '\'' => escaped.push_str("&#39;"),
                _ => escaped.push(ch),
            }
        }
        Self(escaped)
    }

    /// Borrows the escaped HTML text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EscapedHtml {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Deref for EscapedHtml {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

/// HTML that has crossed an explicit trusted-template or sanitizer boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedHtml(String);

impl TrustedHtml {
    /// Marks complete server-owned template output as trusted HTML.
    ///
    /// This is crate-private so external callers cannot turn arbitrary input
    /// into a response body without going through an OSMAP renderer.
    pub(crate) fn from_template(value: String) -> Self {
        Self(value)
    }

    /// Marks dedicated allow-list sanitizer output as trusted HTML.
    pub(crate) fn from_sanitized(value: String) -> Self {
        Self(value)
    }

    /// Borrows the trusted HTML.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&'static str> for TrustedHtml {
    fn from(value: &'static str) -> Self {
        Self(value.to_string())
    }
}

impl fmt::Display for TrustedHtml {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Deref for TrustedHtml {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl PartialEq<&str> for TrustedHtml {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaped_html_encodes_all_html_significant_characters() {
        let escaped = EscapedHtml::new("<tag a=\"x\" b='y'>&");

        assert_eq!(
            escaped.as_str(),
            "&lt;tag a=&quot;x&quot; b=&#39;y&#39;&gt;&amp;"
        );
    }
}
