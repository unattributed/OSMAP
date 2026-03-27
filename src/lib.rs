//! Core library modules for the OSMAP proof-of-concept skeleton.
//!
//! The Phase 6 bootstrap intentionally keeps the code small and explicit. The
//! goal is to prove a maintainable starting point before any mail-specific or
//! browser-facing complexity is added.

pub mod auth;
pub mod bootstrap;
pub mod config;
pub mod error;
pub mod logging;
pub mod mailbox;
pub mod session;
pub mod state;
pub mod totp;
