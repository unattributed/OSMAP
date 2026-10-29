//! Core library modules for the OSMAP proof-of-concept skeleton.
//!
//! The Phase 6 bootstrap intentionally keeps the code small and explicit. The
//! goal is to prove a maintainable starting point before any mail-specific or
//! browser-facing complexity is added.

pub mod account_admission;
#[cfg(unix)]
pub mod account_admission_runtime;
#[cfg(unix)]
pub mod account_guarded_mutation;
pub mod account_mutation;
#[cfg(unix)]
pub(crate) mod account_mutation_budget;
#[cfg(unix)]
pub mod account_mutation_client;
mod account_mutation_continuity;
#[cfg(unix)]
pub mod account_recovery;
#[cfg(unix)]
pub mod account_recovery_operator;
pub mod after_archive;
pub mod appearance;
pub mod archive_event;
pub mod attachment;
pub mod auth;
pub mod authenticator;
pub mod autosave;
pub mod bin_folder;
pub mod bootstrap;
mod charset;
pub mod compose_format;
mod compose_result_ui;
pub mod composition_preferences;
pub mod config;
pub mod contacts;
pub mod conversation;
pub mod documents;
pub mod documents_doveadm;
pub mod draft;
pub mod draft_content;
mod draft_list;
pub mod draft_location;
pub mod error;
pub mod html;
pub mod http;
pub mod http_form;
pub mod http_parse;
pub mod http_support;
pub mod http_ui;
pub mod identity;
pub mod identity_preferences;
pub mod key_management;
pub mod logging;
pub mod mail_address;
pub mod mail_list;
pub mod mail_navigation;
pub mod mailbox;
pub mod mailbox_helper;
pub mod mailbox_status;
pub mod mark_read;
pub mod message_metadata;
pub mod mime;
pub mod openbsd;
pub mod openpgp_helper_client;
pub mod password_change;
pub mod password_change_rate;
#[cfg(test)]
#[path = "password_change_tests.rs"]
mod password_change_tests;
mod private_account_file;
pub mod reading_preferences;
pub mod recovery_contact;
pub mod rendering;
pub mod rendering_html;
pub mod reply_thread;
pub mod send;
pub mod sent_copy;
pub mod sent_location;
pub mod session;
pub mod settings;
pub mod signature;
pub mod snooze;
pub mod state;
pub mod throttle;
pub mod timezone;
pub mod totp;

mod send_journal;
mod send_recovery;

mod reader_neighbours;

pub mod notification_preferences;
mod notifications;
mod signature_ui;

mod label_selection_ui;
pub mod labels;
mod labels_ui;

pub mod folder_create;
mod folder_create_backend;
pub mod folder_disposition;
pub mod folder_metadata;
mod folder_metadata_backend;
pub mod folder_rename;
mod folder_rename_backend;
mod folder_subtree;
mod folder_subtree_recovery;
pub mod openpgp_bindings;
pub mod openpgp_crypto;
#[cfg(unix)]
mod openpgp_crypto_process;
pub mod openpgp_crypto_protocol;
#[cfg(unix)]
pub mod openpgp_crypto_runtime;
pub mod openpgp_inventory;
#[cfg(unix)]
mod openpgp_inventory_process;
pub mod openpgp_inventory_protocol;
#[cfg(unix)]
pub mod openpgp_inventory_runtime;
#[cfg(unix)]
pub mod openpgp_public_admin;
#[cfg(unix)]
pub mod openpgp_public_admin_protocol;
#[cfg(unix)]
pub mod openpgp_public_admin_runtime;
pub mod pgp_mime;
pub mod protected_message;

pub mod openpgp_reader_ui;
pub mod protected_message_gateway;

pub mod protected_submission;

pub mod sender_authority;

#[cfg(all(test, unix))]
mod native_stored_issuer_fixture;

pub mod folder_delete;
mod folder_delete_backend;

pub(crate) mod account_password_admission;
pub(crate) mod account_password_backend;
#[cfg(unix)]
pub(crate) mod account_password_connection;
pub(crate) mod account_password_mail;
pub(crate) mod account_password_native;
#[cfg(unix)]
pub(crate) mod account_password_peer;
// Retain the superseded private-ingress adapter for its existing scoped tests.
// The stock password-service entry does not select these components.
#[allow(dead_code)]
pub(crate) mod account_password_policy;
#[allow(dead_code)]
pub(crate) mod account_password_policy_endpoint;
#[cfg(unix)]
pub(crate) mod account_password_process;
pub(crate) mod account_password_service;
pub(crate) mod account_password_state;
#[cfg(all(test, unix))]
mod native_factory_stored_issuer_fixture;

#[cfg(unix)]
pub(crate) mod account_password_runtime;
#[cfg(unix)]
#[allow(dead_code)] // Superseded private submission topology; not stock authority.
pub(crate) mod account_password_topology;

#[cfg(unix)]
pub(crate) mod account_password_imap;

#[cfg(unix)]
pub mod account_password_fstat;
#[cfg(unix)]
pub mod account_password_server;

#[cfg(unix)]
pub(crate) mod account_password_confinement;
#[cfg(unix)]
pub(crate) mod account_password_custody;

#[cfg(all(unix, any(test, target_os = "openbsd")))]
mod account_password_metadata;
