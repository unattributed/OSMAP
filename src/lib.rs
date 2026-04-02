//! Core library modules for the OSMAP proof-of-concept skeleton.
//!
//! The Phase 6 bootstrap intentionally keeps the code small and explicit. The
//! goal is to prove a maintainable starting point before any mail-specific or
//! browser-facing complexity is added.

pub mod attachment;
pub mod auth;
pub mod bootstrap;
pub mod config;
pub mod error;
pub mod http;
pub mod http_form;
pub mod http_parse;
pub mod http_support;
pub mod http_ui;
pub mod logging;
pub mod mailbox;
pub mod mailbox_helper;
pub mod mime;
pub mod openbsd;
pub mod rendering;
pub mod rendering_html;
pub mod send;
pub mod session;
pub mod settings;
pub mod state;
pub mod throttle;
pub mod totp;
