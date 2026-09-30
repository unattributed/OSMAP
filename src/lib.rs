//! Core library modules for the OSMAP proof-of-concept skeleton.
//!
//! The Phase 6 bootstrap intentionally keeps the code small and explicit. The
//! goal is to prove a maintainable starting point before any mail-specific or
//! browser-facing complexity is added.

pub mod appearance;
pub mod attachment;
pub mod auth;
pub mod bootstrap;
mod charset;
pub mod compose_format;
mod compose_result_ui;
pub mod composition_preferences;
pub mod config;
pub mod contacts;
pub mod draft;
pub mod draft_content;
mod draft_list;
pub mod error;
pub mod html;
pub mod http;
pub mod http_form;
pub mod http_parse;
pub mod http_support;
pub mod http_ui;
pub mod identity;
pub mod identity_preferences;
pub mod logging;
pub mod mail_address;
pub mod mail_list;
pub mod mail_navigation;
pub mod mailbox;
pub mod mailbox_helper;
pub mod message_metadata;
pub mod mime;
pub mod openbsd;
pub mod openpgp_helper_client;
mod private_account_file;
pub mod reading_preferences;
pub mod rendering;
pub mod rendering_html;
pub mod reply_thread;
pub mod send;
pub mod session;
pub mod settings;
pub mod signature;
pub mod snooze;
pub mod state;
pub mod throttle;
pub mod totp;

mod send_journal;
mod send_recovery;

mod reader_neighbours;

mod notifications;
mod signature_ui;

mod label_selection_ui;
pub mod labels;
mod labels_ui;
