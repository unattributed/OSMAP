//! Paired account runtime authority; configured failure never means legacy mode.
use super::*;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) enum AccountRuntimeCapability {
    Disabled,
    ConfiguredUnavailable,
    Ready(Arc<ReadyAccountRuntime>),
}
pub(crate) struct ReadyAccountRuntime {
    admission: crate::account_admission_runtime::Client,
    mutation: crate::account_mutation_client::Client,
}
impl std::fmt::Debug for AccountRuntimeCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Disabled => "AccountRuntime(Disabled)",
            Self::ConfiguredUnavailable => "AccountRuntime(ConfiguredUnavailable)",
            Self::Ready(_) => "AccountRuntime(Ready)",
        })
    }
}
impl PartialEq for AccountRuntimeCapability {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Disabled, Self::Disabled)
            | (Self::ConfiguredUnavailable, Self::ConfiguredUnavailable) => true,
            (Self::Ready(a), Self::Ready(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}
impl Eq for AccountRuntimeCapability {}
impl ReadyAccountRuntime {
    pub(super) fn admission(&self) -> &crate::account_admission_runtime::Client {
        &self.admission
    }
    pub(super) fn mutation(&self) -> &crate::account_mutation_client::Client {
        &self.mutation
    }
}
impl AccountRuntimeCapability {
    fn paired(
        admission: crate::account_admission_runtime::Client,
        mutation: crate::account_mutation_client::Client,
    ) -> Self {
        if !mutation.purpose_separated_from(&admission) {
            return Self::ConfiguredUnavailable;
        }
        Self::Ready(Arc::new(ReadyAccountRuntime {
            admission,
            mutation,
        }))
    }
    pub(super) fn from_config(config: Option<&crate::config::AccountRuntimeConfig>) -> Self {
        let Some(config) = config else {
            return Self::Disabled;
        };
        // Each constructor refuses before private material access while its
        // independent native qualification remains closed. Errors never erase
        // configured intent or fall back to legacy authentication/session mode.
        let Ok(admission) = crate::account_admission_runtime::Client::from_operator_files(
            &config.admission_socket,
            &config.admission_key_file,
            config.admission_helper_uid,
        ) else {
            return Self::ConfiguredUnavailable;
        };
        let Ok(mutation) =
            crate::account_mutation_client::Client::from_operator_files_with_session_proof(
                &config.mutation_socket,
                &config.mutation_key_file,
                &config.session_proof_key_file,
                config.mutation_helper_uid,
            )
        else {
            return Self::ConfiguredUnavailable;
        };
        Self::paired(admission, mutation)
    }
    pub(super) fn ready(&self) -> Option<&ReadyAccountRuntime> {
        match self {
            Self::Ready(value) => Some(value),
            _ => None,
        }
    }
    #[cfg(test)]
    pub(crate) fn fixture(
        admission: crate::account_admission_runtime::Client,
        mutation: crate::account_mutation_client::Client,
    ) -> Self {
        Self::paired(admission, mutation)
    }
}

pub(super) struct UnavailableAccountAuthority;
impl crate::account_admission::EpochAuthority for UnavailableAccountAuthority {
    fn admit(&self, _: &str, _: u64) -> Result<(), crate::account_admission::Error> {
        Err(crate::account_admission::Error::Unavailable)
    }
}
impl crate::auth::PrimaryCredentialBackend for UnavailableAccountAuthority {
    fn verify_primary(
        &self,
        _: &AuthenticationContext,
        _: &str,
        _: &str,
    ) -> Result<crate::auth::PrimaryAuthVerdict, crate::auth::PrimaryAuthBackendError> {
        Err(crate::auth::PrimaryAuthBackendError {
            backend: "account-helper",
            reason: "configured account services unavailable".into(),
        })
    }
}
impl RuntimeBrowserGateway {
    #[cfg(test)]
    pub(crate) fn with_account_fixture_clients(
        mut self,
        admission: crate::account_admission_runtime::Client,
        mutation: crate::account_mutation_client::Client,
    ) -> Self {
        self.account_runtime = AccountRuntimeCapability::fixture(admission, mutation);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};

    struct Fixture {
        root: PathBuf,
        listeners: Vec<UnixListener>,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "osmap-paired-account-{}",
                crate::draft::generate_draft_id().unwrap()
            ));
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let mut listeners = Vec::new();
            for name in ["admission.sock", "mutation.sock"] {
                let path = root.join(name);
                let listener = UnixListener::bind(&path).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
                listener.set_nonblocking(true).unwrap();
                listeners.push(listener);
            }
            Self { root, listeners }
        }
        fn pair(&self, admission: u8, mutation: u8, proof: u8) -> AccountRuntimeCapability {
            for (name, byte) in [
                ("admission.key", admission),
                ("mutation.key", mutation),
                ("proof.key", proof),
            ] {
                let path = self.root.join(name);
                std::fs::write(&path, [byte; 32]).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            let uid = crate::openbsd::effective_uid();
            AccountRuntimeCapability::fixture(
                crate::account_admission_runtime::Client::paired_fixture_files(
                    &self.root.join("admission.sock"),
                    &self.root.join("admission.key"),
                    uid,
                )
                .unwrap(),
                crate::account_mutation_client::Client::stored_fixture_files(
                    &self.root.join("mutation.sock"),
                    &self.root.join("mutation.key"),
                    &self.root.join("proof.key"),
                    uid,
                )
                .unwrap(),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.listeners.clear();
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }
    #[test]
    fn runtime_account_ready_requires_two_real_clients_and_three_distinct_purpose_keys() {
        let f = Fixture::new();
        let ready = f.pair(29, 17, 19);
        assert!(ready.ready().is_some());
        assert_eq!(ready, ready.clone());
        assert_eq!(format!("{ready:?}"), "AccountRuntime(Ready)");
        let uid = crate::openbsd::effective_uid();
        let unproved = crate::account_mutation_client::Client::guarded_fixture_files(
            &f.root.join("mutation.sock"),
            &f.root.join("mutation.key"),
            uid,
        )
        .unwrap();
        assert_eq!(
            AccountRuntimeCapability::fixture(ready.ready().unwrap().admission().clone(), unproved),
            AccountRuntimeCapability::ConfiguredUnavailable
        );
        std::fs::write(f.root.join("proof.key"), [17_u8; 32]).unwrap();
        assert!(
            crate::account_mutation_client::Client::stored_fixture_files(
                &f.root.join("mutation.sock"),
                &f.root.join("mutation.key"),
                &f.root.join("proof.key"),
                uid
            )
            .is_err()
        );
        for (admission, mutation, proof) in [(17, 17, 19), (19, 17, 19)] {
            assert_eq!(
                f.pair(admission, mutation, proof),
                AccountRuntimeCapability::ConfiguredUnavailable
            );
        }
        for listener in &f.listeners {
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }
    #[test]
    fn runtime_account_configured_failure_and_ready_reject_legacy_session_without_rewrite() {
        let f = Fixture::new();
        let context = AuthenticationContext {
            request_id: "paired-session".into(),
            remote_addr: "127.0.0.1".into(),
            user_agent: "public fixture".into(),
        };
        let gateway = RuntimeBrowserGateway::for_test(&f.root);
        let issued = gateway
            .build_session_service()
            .issue(&context, "alice@example.test", RequiredSecondFactor::Totp)
            .unwrap();
        let path =
            FileSessionStore::new(f.root.join("sessions")).session_path(&issued.record.session_id);
        let token = issued.token.as_str();
        assert!(matches!(
            gateway.validate_session(&context, token).decision,
            BrowserSessionDecision::Valid { .. }
        ));
        let before = std::fs::read(&path).unwrap();
        for capability in [
            AccountRuntimeCapability::ConfiguredUnavailable,
            f.pair(29, 17, 19),
        ] {
            let mut gateway = gateway.clone();
            gateway.account_runtime = capability;
            assert!(matches!(
                gateway.validate_session(&context, token).decision,
                BrowserSessionDecision::Invalid
            ));
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
        for listener in &f.listeners {
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }
}
