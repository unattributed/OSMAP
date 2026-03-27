//! Error types used by the early repository skeleton.
//!
//! A tiny handwritten error surface is sufficient for WP0 and avoids pulling in
//! convenience crates before we have proven they are necessary.

use std::error::Error;
use std::fmt;

/// Represents failures that can occur while bootstrapping the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapError {
    /// A required configuration field was empty or semantically invalid.
    InvalidConfig { field: &'static str, reason: String },
    /// A configuration field contained a value outside the accepted set.
    UnsupportedValue {
        field: &'static str,
        value: String,
        expected: &'static str,
    },
    /// A filesystem path was expected to be absolute but was not.
    PathMustBeAbsolute { field: &'static str, value: String },
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field, reason } => {
                write!(f, "invalid configuration for {field}: {reason}")
            }
            Self::UnsupportedValue {
                field,
                value,
                expected,
            } => {
                write!(
                    f,
                    "invalid configuration for {field}: unsupported value {value:?}, expected {expected}"
                )
            }
            Self::PathMustBeAbsolute { field, value } => {
                write!(
                    f,
                    "invalid configuration for {field}: path must be absolute, got {value:?}"
                )
            }
        }
    }
}

impl Error for BootstrapError {}
