//! OpenBSD-native runtime confinement planning and activation.
//!
//! The current implementation keeps this layer explicit and reviewable:
//! - build a concrete filesystem and promise plan from validated config
//! - emit that plan in operator-visible logs
//! - enforce it only when the operator explicitly enables it
//! - stay honest about platform boundaries in non-OpenBSD environments

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::config::{AppConfig, LogLevel, OpenbsdConfinementMode};
use crate::logging::{EventCategory, LogEvent, Logger};

/// The promise set used while `unveil(2)` calls are still permitted.
const OPENBSD_SERVE_PROMISES_BEFORE_LOCK: &str =
    "stdio rpath wpath cpath fattr inet proc exec unveil";

/// The narrower promise set kept after the filesystem view is locked.
const OPENBSD_SERVE_PROMISES_AFTER_LOCK: &str = "stdio rpath wpath cpath fattr inet proc exec";

/// The promise set used while `unveil(2)` calls are still permitted in the
/// browser-facing runtime when it also connects to the local mailbox helper.
const OPENBSD_SERVE_WITH_HELPER_PROMISES_BEFORE_LOCK: &str =
    "stdio rpath wpath cpath fattr inet unix proc exec unveil";

/// The narrower promise set kept after the filesystem view is locked in the
/// browser-facing runtime when it also connects to the local mailbox helper.
const OPENBSD_SERVE_WITH_HELPER_PROMISES_AFTER_LOCK: &str =
    "stdio rpath wpath cpath fattr inet unix proc exec";

/// The promise set used while `unveil(2)` calls are still permitted in the
/// local mailbox-helper runtime.
const OPENBSD_HELPER_PROMISES_BEFORE_LOCK: &str =
    "stdio rpath wpath cpath fattr unix proc exec unveil";

/// The narrower promise set kept after the filesystem view is locked in the
/// local mailbox-helper runtime.
const OPENBSD_HELPER_PROMISES_AFTER_LOCK: &str = "stdio rpath wpath cpath fattr unix proc exec";

/// One unveiled path plus the permissions granted to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenbsdUnveilRule {
    pub path: PathBuf,
    pub permissions: String,
}

/// A concrete confinement plan derived from the current runtime shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenbsdConfinementPlan {
    pub promises_before_lock: &'static str,
    pub promises_after_lock: &'static str,
    pub unveil_rules: Vec<OpenbsdUnveilRule>,
}

impl OpenbsdConfinementPlan {
    /// Builds the current confinement plan from validated runtime configuration.
    pub fn from_config(config: &AppConfig) -> Self {
        let mut rules = BTreeMap::<PathBuf, String>::new();
        match config.run_mode {
            crate::config::AppRunMode::Serve => {
                // The browser runtime owns sessions, runtime sockets, cache,
                // and TOTP secrets. Those explicit mutable paths remain
                // writable instead of widening the tree above them.
                add_rule(&mut rules, &config.state_root, "rwc");
                add_rule(&mut rules, &config.state_layout.runtime_dir, "rwc");
                add_rule(&mut rules, &config.state_layout.session_dir, "rwc");
                add_rule(&mut rules, &config.state_layout.settings_dir, "rwc");
                add_rule(&mut rules, &config.state_layout.audit_dir, "rwc");
                add_rule(&mut rules, &config.state_layout.cache_dir, "rwc");
                add_rule(&mut rules, &config.state_layout.totp_secret_dir, "rwc");

                add_rule(&mut rules, Path::new("/usr/local/bin/doveadm"), "x");
                add_rule(&mut rules, Path::new("/usr/sbin/sendmail"), "x");
                add_rule(&mut rules, Path::new("/usr/local/sbin/sendmail"), "x");
                add_rule(&mut rules, Path::new("/usr/lib"), "rx");
                add_rule(&mut rules, Path::new("/usr/libexec"), "rx");
                add_rule(&mut rules, Path::new("/usr/local/lib"), "rx");
                add_rule(&mut rules, Path::new("/etc/dovecot"), "r");
                add_rule(&mut rules, Path::new("/etc/mail"), "r");
                add_rule(&mut rules, Path::new("/etc/mailer.conf"), "r");
                add_rule(&mut rules, Path::new("/var/spool/postfix"), "rwc");
                add_rule(&mut rules, Path::new("/var/spool/smtpd"), "rwc");
                add_rule(&mut rules, Path::new("/dev/null"), "rw");

                if let Some(auth_socket_path) = &config.doveadm_auth_socket_path {
                    add_rule(&mut rules, auth_socket_path, "rw");
                    add_parent_dir_rules(&mut rules, auth_socket_path);
                }

                let use_direct_mailbox_backends = config.mailbox_helper_socket_path.is_none();
                if use_direct_mailbox_backends {
                    if let Some(userdb_socket_path) = &config.doveadm_userdb_socket_path {
                        add_rule(&mut rules, userdb_socket_path, "rw");
                        add_parent_dir_rules(&mut rules, userdb_socket_path);
                    }
                }

                if let Some(mailbox_helper_socket_path) = &config.mailbox_helper_socket_path {
                    // The web-facing runtime only connects to the local
                    // helper socket, so it keeps a narrower connect-only view
                    // of that path.
                    add_rule(&mut rules, mailbox_helper_socket_path, "rw");
                    add_parent_dir_rules(&mut rules, mailbox_helper_socket_path);
                }

                Self {
                    promises_before_lock: if config.mailbox_helper_socket_path.is_some() {
                        OPENBSD_SERVE_WITH_HELPER_PROMISES_BEFORE_LOCK
                    } else {
                        OPENBSD_SERVE_PROMISES_BEFORE_LOCK
                    },
                    promises_after_lock: if config.mailbox_helper_socket_path.is_some() {
                        OPENBSD_SERVE_WITH_HELPER_PROMISES_AFTER_LOCK
                    } else {
                        OPENBSD_SERVE_PROMISES_AFTER_LOCK
                    },
                    unveil_rules: rules
                        .into_iter()
                        .map(|(path, permissions)| OpenbsdUnveilRule { path, permissions })
                        .collect(),
                }
            }
            crate::config::AppRunMode::MailboxHelper => {
                // The local helper only needs its own runtime socket plus the
                // current doveadm and Dovecot surfaces required for bounded
                // mailbox reads.
                add_rule(&mut rules, &config.state_root, "rwc");
                add_rule(&mut rules, &config.state_layout.runtime_dir, "rwc");
                add_rule(&mut rules, Path::new("/usr/local/bin/doveadm"), "x");
                add_rule(&mut rules, Path::new("/usr/lib"), "rx");
                add_rule(&mut rules, Path::new("/usr/libexec"), "rx");
                add_rule(&mut rules, Path::new("/usr/local/lib"), "rx");
                add_rule(&mut rules, Path::new("/etc/dovecot"), "r");
                add_rule(&mut rules, Path::new("/dev/null"), "rw");

                if let Some(userdb_socket_path) = &config.doveadm_userdb_socket_path {
                    add_rule(&mut rules, userdb_socket_path, "rw");
                    add_parent_dir_rules(&mut rules, userdb_socket_path);
                }
                if let Some(mailbox_helper_socket_path) = &config.mailbox_helper_socket_path {
                    // The helper binds and recreates its own Unix-domain
                    // socket, so the explicit socket path must retain create
                    // permission in helper mode instead of the narrower
                    // connect-only view used by the web runtime.
                    add_rule(&mut rules, mailbox_helper_socket_path, "rwc");
                    add_parent_dir_rules(&mut rules, mailbox_helper_socket_path);
                }

                Self {
                    promises_before_lock: OPENBSD_HELPER_PROMISES_BEFORE_LOCK,
                    promises_after_lock: OPENBSD_HELPER_PROMISES_AFTER_LOCK,
                    unveil_rules: rules
                        .into_iter()
                        .map(|(path, permissions)| OpenbsdUnveilRule { path, permissions })
                        .collect(),
                }
            }
            crate::config::AppRunMode::Bootstrap => Self {
                promises_before_lock: OPENBSD_SERVE_PROMISES_BEFORE_LOCK,
                promises_after_lock: OPENBSD_SERVE_PROMISES_AFTER_LOCK,
                unveil_rules: Vec::new(),
            },
        }
    }
}

/// Applies the current OpenBSD confinement mode for the serve runtime.
pub fn apply_runtime_confinement(config: &AppConfig, logger: &Logger) -> Result<(), String> {
    match config.openbsd_confinement_mode {
        OpenbsdConfinementMode::Disabled => Ok(()),
        OpenbsdConfinementMode::LogOnly => {
            let plan = OpenbsdConfinementPlan::from_config(config);
            logger.emit(&build_plan_event(config, &plan, "plan_logged"));
            Ok(())
        }
        OpenbsdConfinementMode::Enforce => {
            let plan = OpenbsdConfinementPlan::from_config(config);
            logger.emit(&build_plan_event(config, &plan, "plan_enforcing"));

            #[cfg(target_os = "openbsd")]
            {
                imp::apply_plan(&plan)?;
                logger.emit(
                    &LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Bootstrap,
                        "openbsd_confinement_enabled",
                        "OpenBSD runtime confinement enabled",
                    )
                    .with_field(
                        "openbsd_confinement_mode",
                        config.openbsd_confinement_mode.as_str(),
                    )
                    .with_field("unveil_rule_count", plan.unveil_rules.len().to_string())
                    .with_field("promises_after_lock", plan.promises_after_lock),
                );
                Ok(())
            }

            #[cfg(not(target_os = "openbsd"))]
            {
                Err(
                    "OpenBSD confinement enforcement was requested on a non-OpenBSD platform"
                        .to_string(),
                )
            }
        }
    }
}

/// Adds one unveil rule while preserving the strongest permissions per path.
fn add_rule(rules: &mut BTreeMap<PathBuf, String>, path: &Path, permissions: &str) {
    let entry = rules.entry(path.to_path_buf()).or_default();
    for permission in permissions.chars() {
        if !entry.contains(permission) {
            entry.push(permission);
        }
    }
}

/// Adds read-only unveil rules for parent directories of an explicit helper path.
fn add_parent_dir_rules(rules: &mut BTreeMap<PathBuf, String>, path: &Path) {
    let mut current = path.parent();
    while let Some(parent) = current {
        if parent == Path::new("/") {
            break;
        }
        add_rule(rules, parent, "r");
        current = parent.parent();
    }
}

/// Builds the operator-visible summary event for the current confinement plan.
fn build_plan_event(
    config: &AppConfig,
    plan: &OpenbsdConfinementPlan,
    action: &'static str,
) -> LogEvent {
    let unveiled_paths = plan
        .unveil_rules
        .iter()
        .map(|rule| format!("{}:{}", rule.path.display(), rule.permissions))
        .collect::<Vec<_>>()
        .join(",");

    LogEvent::new(
        LogLevel::Info,
        EventCategory::Bootstrap,
        action,
        "OpenBSD runtime confinement plan prepared",
    )
    .with_field(
        "openbsd_confinement_mode",
        config.openbsd_confinement_mode.as_str(),
    )
    .with_field("promises_before_lock", plan.promises_before_lock)
    .with_field("promises_after_lock", plan.promises_after_lock)
    .with_field("unveil_rule_count", plan.unveil_rules.len().to_string())
    .with_field("unveiled_paths", unveiled_paths)
}

#[cfg(target_os = "openbsd")]
mod imp {
    use std::ffi::CString;
    use std::io;
    use std::os::raw::{c_char, c_int};

    use super::{OpenbsdConfinementPlan, OpenbsdUnveilRule};

    unsafe extern "C" {
        fn pledge(promises: *const c_char, execpromises: *const c_char) -> c_int;
        fn unveil(path: *const c_char, permissions: *const c_char) -> c_int;
    }

    /// Applies the current plan by reducing promises, unveiling paths, locking
    /// the view, and then dropping the `unveil` promise.
    pub fn apply_plan(plan: &OpenbsdConfinementPlan) -> Result<(), String> {
        pledge_raw(plan.promises_before_lock)?;

        for rule in &plan.unveil_rules {
            unveil_rule(rule)?;
        }

        lock_unveil()?;
        pledge_raw(plan.promises_after_lock)?;
        Ok(())
    }

    /// Calls pledge with the supplied promise string and no execpromises so
    /// helper processes can start unpledged after `execve(2)`.
    fn pledge_raw(promises: &str) -> Result<(), String> {
        let promises = CString::new(promises)
            .map_err(|_| "pledge promise string contained interior NUL".to_string())?;
        let result = unsafe { pledge(promises.as_ptr(), std::ptr::null()) };
        if result == -1 {
            return Err(format!("pledge failed: {}", io::Error::last_os_error()));
        }

        Ok(())
    }

    /// Applies one unveil rule using the exact path and permission set chosen
    /// by the current confinement plan.
    fn unveil_rule(rule: &OpenbsdUnveilRule) -> Result<(), String> {
        let path = CString::new(rule.path.as_os_str().as_encoded_bytes().to_vec())
            .map_err(|_| format!("unveil path {:?} contained interior NUL", rule.path))?;
        let permissions = CString::new(rule.permissions.clone())
            .map_err(|_| "unveil permission string contained interior NUL".to_string())?;

        let result = unsafe { unveil(path.as_ptr(), permissions.as_ptr()) };
        if result == -1 {
            return Err(format!(
                "unveil failed for {} with permissions {}: {}",
                rule.path.display(),
                rule.permissions,
                io::Error::last_os_error(),
            ));
        }

        Ok(())
    }

    /// Locks the current unveil table so later code cannot widen filesystem
    /// visibility accidentally.
    fn lock_unveil() -> Result<(), String> {
        let result = unsafe { unveil(std::ptr::null(), std::ptr::null()) };
        if result == -1 {
            return Err(format!(
                "unveil lock failed: {}",
                io::Error::last_os_error()
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppRunMode, LogFormat, RuntimeEnvironment};
    use crate::state::StateLayout;

    fn config_fixture(mode: OpenbsdConfinementMode) -> AppConfig {
        AppConfig {
            run_mode: AppRunMode::Serve,
            environment: RuntimeEnvironment::Production,
            listen_addr: "127.0.0.1:8080".to_string(),
            doveadm_auth_socket_path: None,
            doveadm_userdb_socket_path: None,
            mailbox_helper_socket_path: None,
            state_root: PathBuf::from("/var/lib/osmap"),
            log_level: LogLevel::Info,
            log_format: LogFormat::Text,
            state_layout: StateLayout::new(
                PathBuf::from("/var/lib/osmap"),
                PathBuf::from("/var/lib/osmap/run"),
                PathBuf::from("/var/lib/osmap/sessions"),
                PathBuf::from("/var/lib/osmap/settings"),
                PathBuf::from("/var/lib/osmap/audit"),
                PathBuf::from("/var/lib/osmap/cache"),
                PathBuf::from("/var/lib/osmap/secrets/totp"),
            )
            .expect("layout should be valid"),
            session_lifetime_seconds: 43200,
            totp_allowed_skew_steps: 1,
            login_throttle_max_failures: 5,
            login_throttle_remote_max_failures: 12,
            login_throttle_window_seconds: 300,
            login_throttle_lockout_seconds: 900,
            submission_throttle_max_submissions: 10,
            submission_throttle_remote_max_submissions: 25,
            submission_throttle_window_seconds: 300,
            submission_throttle_lockout_seconds: 900,
            message_move_throttle_max_moves: 20,
            message_move_throttle_remote_max_moves: 60,
            message_move_throttle_window_seconds: 300,
            message_move_throttle_lockout_seconds: 900,
            openbsd_confinement_mode: mode,
        }
    }

    #[test]
    fn builds_concrete_plan_from_runtime_config() {
        let plan =
            OpenbsdConfinementPlan::from_config(&config_fixture(OpenbsdConfinementMode::LogOnly));

        assert_eq!(
            plan.promises_before_lock,
            OPENBSD_SERVE_PROMISES_BEFORE_LOCK
        );
        assert_eq!(plan.promises_after_lock, OPENBSD_SERVE_PROMISES_AFTER_LOCK);
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/usr/local/bin/doveadm")
                && rule.permissions.contains('x')));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/lib/osmap/sessions")
                && rule.permissions.contains('w')));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/lib/osmap/settings")
                && rule.permissions.contains('w')));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/usr/local/sbin/sendmail")
                && rule.permissions.contains('x')));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/dovecot")));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/log/dovecot.log")));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var")));
    }

    #[test]
    fn adds_explicit_auth_socket_and_parent_dirs_when_configured() {
        let mut config = config_fixture(OpenbsdConfinementMode::LogOnly);
        config.doveadm_auth_socket_path = Some(PathBuf::from("/var/run/osmap/dovecot-auth"));

        let plan = OpenbsdConfinementPlan::from_config(&config);

        assert!(plan.unveil_rules.iter().any(|rule| {
            rule.path == Path::new("/var/run/osmap/dovecot-auth")
                && rule.permissions.contains('r')
                && rule.permissions.contains('w')
        }));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/run/osmap") && rule.permissions == "r"));
    }

    #[test]
    fn applies_log_only_mode_without_platform_specific_failure() {
        let config = config_fixture(OpenbsdConfinementMode::LogOnly);
        let logger = Logger::new(LogFormat::Text, LogLevel::Info);

        assert!(apply_runtime_confinement(&config, &logger).is_ok());
    }

    #[test]
    fn adds_explicit_userdb_socket_and_parent_dirs_when_configured() {
        let mut config = config_fixture(OpenbsdConfinementMode::LogOnly);
        config.doveadm_userdb_socket_path = Some(PathBuf::from("/var/run/osmap-userdb"));

        let plan = OpenbsdConfinementPlan::from_config(&config);

        assert!(plan.unveil_rules.iter().any(|rule| {
            rule.path == Path::new("/var/run/osmap-userdb")
                && rule.permissions.contains('r')
                && rule.permissions.contains('w')
        }));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/run") && rule.permissions == "r"));
    }

    #[test]
    fn adds_mailbox_helper_socket_and_parent_dirs_when_configured() {
        let mut config = config_fixture(OpenbsdConfinementMode::LogOnly);
        config.mailbox_helper_socket_path =
            Some(PathBuf::from("/var/lib/osmap/run/mailbox-helper.sock"));

        let plan = OpenbsdConfinementPlan::from_config(&config);

        assert!(plan.unveil_rules.iter().any(|rule| {
            rule.path == Path::new("/var/lib/osmap/run/mailbox-helper.sock")
                && rule.permissions.contains('r')
                && rule.permissions.contains('w')
        }));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/lib/osmap/run")
                && rule.permissions.contains('r')));
    }

    #[test]
    fn helper_mode_uses_unix_promises_and_skips_sendmail_paths() {
        let mut config = config_fixture(OpenbsdConfinementMode::LogOnly);
        config.run_mode = AppRunMode::MailboxHelper;
        config.mailbox_helper_socket_path =
            Some(PathBuf::from("/var/lib/osmap/run/mailbox-helper.sock"));
        config.doveadm_userdb_socket_path = Some(PathBuf::from("/var/run/osmap-userdb"));

        let plan = OpenbsdConfinementPlan::from_config(&config);

        assert_eq!(
            plan.promises_before_lock,
            OPENBSD_HELPER_PROMISES_BEFORE_LOCK
        );
        assert_eq!(plan.promises_after_lock, OPENBSD_HELPER_PROMISES_AFTER_LOCK);
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/usr/sbin/sendmail")));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/spool/postfix")));
        assert!(plan.unveil_rules.iter().any(|rule| {
            rule.path == Path::new("/var/run/osmap-userdb")
                && rule.permissions.contains('r')
                && rule.permissions.contains('w')
        }));
        assert!(plan.unveil_rules.iter().any(|rule| {
            rule.path == Path::new("/var/lib/osmap/run/mailbox-helper.sock")
                && rule.permissions.contains('r')
                && rule.permissions.contains('w')
        }));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/dovecot")));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/log/dovecot.log")));
    }

    #[test]
    fn serve_mode_with_helper_socket_uses_unix_promises_and_skips_userdb_socket() {
        let mut config = config_fixture(OpenbsdConfinementMode::LogOnly);
        config.mailbox_helper_socket_path =
            Some(PathBuf::from("/var/lib/osmap/run/mailbox-helper.sock"));
        config.doveadm_userdb_socket_path = Some(PathBuf::from("/var/run/osmap-userdb"));

        let plan = OpenbsdConfinementPlan::from_config(&config);

        assert_eq!(
            plan.promises_before_lock,
            OPENBSD_SERVE_WITH_HELPER_PROMISES_BEFORE_LOCK
        );
        assert_eq!(
            plan.promises_after_lock,
            OPENBSD_SERVE_WITH_HELPER_PROMISES_AFTER_LOCK
        );
        assert!(plan.unveil_rules.iter().any(|rule| {
            rule.path == Path::new("/var/lib/osmap/run/mailbox-helper.sock")
                && rule.permissions.contains('r')
                && rule.permissions.contains('w')
        }));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/run/osmap-userdb")));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/dovecot")));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/log/dovecot.log")));
    }
}
