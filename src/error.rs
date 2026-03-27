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
    InvalidConfig {
        field: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field, reason } => {
                write!(f, "invalid configuration for {field}: {reason}")
            }
        }
    }
}

impl Error for BootstrapError {}
