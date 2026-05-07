//! Defines the mutable-state layout for the early OSMAP prototype.
//!
//! The Phase 6 state model keeps mutable runtime data under one explicit root so
//! later deployment and confinement work can reason about the filesystem
//! boundary clearly.

use std::path::PathBuf;

use crate::error::BootstrapError;

/// Describes where the application keeps mutable runtime data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateLayout {
    pub root_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub session_dir: PathBuf,
    pub settings_dir: PathBuf,
    pub draft_dir: PathBuf,
    pub audit_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub totp_secret_dir: PathBuf,
}

/// Input paths for building a validated state layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateLayoutPaths {
    pub root_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub session_dir: PathBuf,
    pub settings_dir: PathBuf,
    pub draft_dir: PathBuf,
    pub audit_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub totp_secret_dir: PathBuf,
}

impl StateLayout {
    /// Builds the state layout from a root directory and explicit subpaths.
    pub fn new(paths: StateLayoutPaths) -> Result<Self, BootstrapError> {
        validate_child_path("OSMAP_RUNTIME_DIR", &paths.root_dir, &paths.runtime_dir)?;
        validate_child_path("OSMAP_SESSION_DIR", &paths.root_dir, &paths.session_dir)?;
        validate_child_path("OSMAP_SETTINGS_DIR", &paths.root_dir, &paths.settings_dir)?;
        validate_child_path("OSMAP_DRAFT_DIR", &paths.root_dir, &paths.draft_dir)?;
        validate_child_path("OSMAP_AUDIT_DIR", &paths.root_dir, &paths.audit_dir)?;
        validate_child_path("OSMAP_CACHE_DIR", &paths.root_dir, &paths.cache_dir)?;
        validate_child_path(
            "OSMAP_TOTP_SECRET_DIR",
            &paths.root_dir,
            &paths.totp_secret_dir,
        )?;

        Ok(Self {
            root_dir: paths.root_dir,
            runtime_dir: paths.runtime_dir,
            session_dir: paths.session_dir,
            settings_dir: paths.settings_dir,
            draft_dir: paths.draft_dir,
            audit_dir: paths.audit_dir,
            cache_dir: paths.cache_dir,
            totp_secret_dir: paths.totp_secret_dir,
        })
    }
}

/// Keeps mutable state paths rooted in or under the configured state tree.
fn validate_child_path(
    field: &'static str,
    root_dir: &PathBuf,
    child_dir: &PathBuf,
) -> Result<(), BootstrapError> {
    if child_dir == root_dir || child_dir.starts_with(root_dir) {
        return Ok(());
    }

    Err(BootstrapError::InvalidConfig {
        field,
        reason: format!(
            "path must stay within the configured state root {:?}",
            root_dir
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_state_children_under_root() {
        let layout = StateLayout::new(StateLayoutPaths {
            root_dir: PathBuf::from("/var/lib/osmap"),
            runtime_dir: PathBuf::from("/var/lib/osmap/run"),
            session_dir: PathBuf::from("/var/lib/osmap/sessions"),
            settings_dir: PathBuf::from("/var/lib/osmap/settings"),
            draft_dir: PathBuf::from("/var/lib/osmap/drafts"),
            audit_dir: PathBuf::from("/var/lib/osmap/audit"),
            cache_dir: PathBuf::from("/var/lib/osmap/cache"),
            totp_secret_dir: PathBuf::from("/var/lib/osmap/secrets/totp"),
        })
        .expect("state children under the root should be accepted");

        assert_eq!(layout.runtime_dir, PathBuf::from("/var/lib/osmap/run"));
        assert_eq!(
            layout.settings_dir,
            PathBuf::from("/var/lib/osmap/settings")
        );
        assert_eq!(layout.draft_dir, PathBuf::from("/var/lib/osmap/drafts"));
        assert_eq!(
            layout.totp_secret_dir,
            PathBuf::from("/var/lib/osmap/secrets/totp")
        );
    }

    #[test]
    fn rejects_state_paths_outside_root() {
        let error = StateLayout::new(StateLayoutPaths {
            root_dir: PathBuf::from("/var/lib/osmap"),
            runtime_dir: PathBuf::from("/var/run/osmap"),
            session_dir: PathBuf::from("/var/lib/osmap/sessions"),
            settings_dir: PathBuf::from("/var/lib/osmap/settings"),
            draft_dir: PathBuf::from("/var/lib/osmap/drafts"),
            audit_dir: PathBuf::from("/var/lib/osmap/audit"),
            cache_dir: PathBuf::from("/var/lib/osmap/cache"),
            totp_secret_dir: PathBuf::from("/var/lib/osmap/secrets/totp"),
        })
        .expect_err("state paths outside the root must fail");

        assert_eq!(
            error,
            BootstrapError::InvalidConfig {
                field: "OSMAP_RUNTIME_DIR",
                reason: "path must stay within the configured state root \"/var/lib/osmap\""
                    .to_string(),
            }
        );
    }
}
