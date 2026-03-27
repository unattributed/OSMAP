//! Structured logging for the early OSMAP prototype.
//!
//! This logger intentionally keeps the output simple and dependency-light. The
//! goal is to establish a reviewable event shape before later phases add auth or
//! mail-specific events.

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
        self.fields.push(LogField {
            key,
            value: value.into(),
        });
        self
    }
}

/// A single key/value pair carried on a structured log event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogField {
    pub key: &'static str,
    pub value: String,
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
    let mut line = format!(
        "ts={} level={} category={} action={} msg={}",
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
            "ts=12345 level=info category=bootstrap action=startup msg=\"bootstrap completed\" env=\"development\" listen_addr=\"127.0.0.1:8080\""
        );
    }
}
