//! Structured logging for the early OSMAP prototype.
//!
//! This logger intentionally keeps the output simple and dependency-light. The
//! goal is to establish a reviewable event shape before later phases add auth or
//! mail-specific events.

use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{LogFormat, LogLevel};

/// Categorizes events so later audit and operator logs can be separated without
/// inventing ad hoc strings all over the codebase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventCategory {
    Bootstrap,
    Config,
    State,
    Http,
    Auth,
    Session,
    Mailbox,
    Submission,
}

impl EventCategory {
    /// Returns the canonical string representation used in log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Config => "config",
            Self::State => "state",
            Self::Http => "http",
            Self::Auth => "auth",
            Self::Session => "session",
            Self::Mailbox => "mailbox",
            Self::Submission => "submission",
        }
    }
}

/// A structured log event with a fixed category and bounded field shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEvent {
    pub level: LogLevel,
    pub category: EventCategory,
    pub action: &'static str,
    pub message: String,
    pub fields: Vec<LogField>,
}

impl LogEvent {
    /// Creates a new structured log event.
    pub fn new(
        level: LogLevel,
        category: EventCategory,
        action: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            level,
            category,
            action,
            message: message.into(),
            fields: Vec::new(),
        }
    }

    /// Adds a field to the event without exposing formatting rules at call
    /// sites.
    pub fn with_field(mut self, key: &'static str, value: impl Into<String>) -> Self {
        let value = value.into();
        let (key, value) = if key == "session_id" {
            ("session_ref", audit_session_ref(&value))
        } else {
            (key, value)
        };

        self.fields.push(LogField { key, value });
        self
    }
}

/// A single key/value pair carried on a structured log event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogField {
    pub key: &'static str,
    pub value: String,
}

/// Builds a deterministic audit-only session reference from an internal
/// session lookup key.
///
/// This value is deliberately domain-separated from the persisted session ID
/// derivation and is truncated for correlation only. It must not be accepted as
/// a cookie, session filename, or session lookup key.
pub fn audit_session_ref(session_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"osmap-audit-session-ref-v1");
    digest.update([0]);
    digest.update(session_id.as_bytes());
    let digest = digest.finalize();

    format!("asr-{}", hex_lower(&digest[..16]))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }

    output
}

/// Emits operator-readable structured log lines to standard error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logger {
    format: LogFormat,
    minimum_level: LogLevel,
}

impl Logger {
    /// Builds a new logger from the configured format and minimum level.
    pub fn new(format: LogFormat, minimum_level: LogLevel) -> Self {
        Self {
            format,
            minimum_level,
        }
    }

    /// Returns whether an event should be emitted at the current minimum level.
    pub fn should_emit(&self, level: LogLevel) -> bool {
        level >= self.minimum_level
    }

    /// Renders an event and emits it to standard error if it passes the current
    /// minimum level.
    pub fn emit(&self, event: &LogEvent) {
        if self.should_emit(event.level) {
            eprintln!("{}", self.render(event));
        }
    }

    /// Renders an event into a single stable line.
    pub fn render(&self, event: &LogEvent) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.render_with_timestamp(event, timestamp)
    }

    /// Renders an event with a caller-supplied timestamp so tests can be
    /// deterministic.
    pub fn render_with_timestamp(&self, event: &LogEvent, timestamp: u64) -> String {
        match self.format {
            LogFormat::Text => render_text_line(timestamp, event),
        }
    }
}

/// Renders a log line in the project's current text format.
fn render_text_line(timestamp: u64, event: &LogEvent) -> String {
    let timestamp_text = format_unix_timestamp_utc(timestamp);
    let mut line = format!(
        "ts={} ts_unix={} level={} category={} action={} msg={}",
        quote_value(&timestamp_text),
        timestamp,
        event.level.as_str(),
        event.category.as_str(),
        event.action,
        quote_value(&event.message),
    );

    for field in &event.fields {
        let _ = write!(line, " {}={}", field.key, quote_value(&field.value));
    }

    line
}

fn format_unix_timestamp_utc(timestamp: u64) -> String {
    const SECONDS_PER_DAY: u64 = 86_400;

    let days = (timestamp / SECONDS_PER_DAY) as i128;
    let seconds_of_day = timestamp % SECONDS_PER_DAY;
    let (year, month, day) = civil_from_unix_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_unix_days(days_since_unix_epoch: i128) -> (i128, u32, u32) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };

    (year, month as u32, day as u32)
}

/// Quotes field values conservatively so spaces and punctuation remain
/// readable without introducing ambiguous ad hoc formatting.
fn quote_value(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_events_below_the_minimum_level() {
        let logger = Logger::new(LogFormat::Text, LogLevel::Warn);

        assert!(!logger.should_emit(LogLevel::Info));
        assert!(logger.should_emit(LogLevel::Warn));
        assert!(logger.should_emit(LogLevel::Error));
    }

    #[test]
    fn renders_stable_text_lines() {
        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);
        let event = LogEvent::new(
            LogLevel::Info,
            EventCategory::Bootstrap,
            "startup",
            "bootstrap completed",
        )
        .with_field("env", "development")
        .with_field("listen_addr", "127.0.0.1:8080");

        let line = logger.render_with_timestamp(&event, 12345);

        assert_eq!(
            line,
            "ts=\"1970-01-01T03:25:45Z\" ts_unix=12345 level=info category=bootstrap action=startup msg=\"bootstrap completed\" env=\"development\" listen_addr=\"127.0.0.1:8080\""
        );
    }

    #[test]
    fn renders_unix_epoch_as_utc_rfc3339_timestamp() {
        assert_eq!(format_unix_timestamp_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_timestamp_utc(12_345), "1970-01-01T03:25:45Z");
        assert_eq!(
            format_unix_timestamp_utc(1_735_689_600),
            "2025-01-01T00:00:00Z"
        );
    }
}

#[cfg(test)]
mod audit_redaction_tests {
    use super::{audit_session_ref, EventCategory, LogEvent, Logger};
    use crate::config::{LogFormat, LogLevel};

    #[test]
    fn converts_raw_session_id_field_to_audit_session_ref() {
        let session_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let event = LogEvent::new(
            LogLevel::Info,
            EventCategory::Session,
            "session_validated",
            "browser session validated",
        )
        .with_field("session_id", session_id);

        assert_eq!(event.fields[0].key, "session_ref");
        assert_eq!(event.fields[0].value, audit_session_ref(session_id));
        assert_ne!(event.fields[0].value, session_id);

        let rendered =
            Logger::new(LogFormat::Text, LogLevel::Info).render_with_timestamp(&event, 1234);
        assert!(rendered.contains("session_ref=\"asr-"));
        assert!(!rendered.contains("session_id=\""));
        assert!(!rendered.contains(session_id));
    }

    #[test]
    fn audit_session_ref_is_deterministic_and_domain_separated() {
        let session_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let first = audit_session_ref(session_id);
        let second = audit_session_ref(session_id);

        assert_eq!(first, second);
        assert!(first.starts_with("asr-"));
        assert_eq!(first.len(), 36);
        assert_ne!(first, session_id);
    }
}
