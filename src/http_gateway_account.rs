//! Paired account runtime authority; configured failure never means legacy mode.
use super::*;
use std::path::Path;
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
    pub(crate) fn confinement_clients(
        &self,
    ) -> Option<(
        &crate::account_admission_runtime::Client,
        &crate::account_mutation_client::Client,
    )> {
        self.ready()
            .map(|ready| (ready.admission(), ready.mutation()))
    }
    /// Only the actual Serve enforcer supplies this capability. Disabled or
    /// log-only startup retains full protected checks on every exchange.
    pub(crate) fn after_confinement(
        self,
        seal: Option<&Arc<crate::openbsd::ServeAccountSeal>>,
    ) -> Self {
        if let (Self::Ready(ready), Some(seal)) = (&self, seal) {
            if ready.admission.finalize_serve(seal.clone()).is_err()
                || ready.mutation.finalize_serve(seal.clone()).is_err()
            {
                return Self::ConfiguredUnavailable;
            }
        }
        self
    }
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
        // A native-local pair selects only the fixed root-owned Rust service.
        // Partial/foreign pairs retain the independently closed legacy route;
        // any constructor refusal preserves configured intent with no fallback.
        let native_local = Self::native_local_pair(config);
        let admission = if native_local {
            crate::account_admission_runtime::Client::from_native_local_operator_files(
                &config.admission_key_file,
            )
        } else {
            crate::account_admission_runtime::Client::from_operator_files(
                &config.admission_socket,
                &config.admission_key_file,
                config.admission_helper_uid,
            )
        };
        let Ok(admission) = admission else {
            return Self::ConfiguredUnavailable;
        };
        let mutation = if native_local {
            crate::account_mutation_client::Client::from_native_local_operator_files(
                &config.mutation_key_file,
                &config.session_proof_key_file,
            )
        } else {
            crate::account_mutation_client::Client::from_operator_files_with_session_proof(
                &config.mutation_socket,
                &config.mutation_key_file,
                &config.session_proof_key_file,
                config.mutation_helper_uid,
            )
        };
        let Ok(mutation) = mutation else {
            return Self::ConfiguredUnavailable;
        };
        Self::paired(admission, mutation)
    }
    fn native_local_pair(config: &crate::config::AccountRuntimeConfig) -> bool {
        config.admission_socket == Path::new(crate::config::LOCAL_ACCOUNT_ADMISSION_SOCKET)
            && config.mutation_socket == Path::new(crate::config::LOCAL_ACCOUNT_MUTATION_SOCKET)
            && config.admission_helper_uid == 0
            && config.mutation_helper_uid == 0
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
    pub(super) fn uses_account_runtime(&self, account: &str) -> bool {
        self.account_rollout
            .as_deref()
            .is_none_or(|selected| selected == account)
    }

    pub(super) fn ready_account_runtime(&self, account: &str) -> Option<&ReadyAccountRuntime> {
        self.uses_account_runtime(account)
            .then(|| self.account_runtime.ready())
            .flatten()
    }

    pub(crate) fn prepare_account_runtime(config: &AppConfig) -> AccountRuntimeCapability {
        AccountRuntimeCapability::from_config(config.account_runtime.as_ref())
    }
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

    #[test]
    fn account_rollout_preserves_unrelated_sessions_and_refuses_selected_pre_epoch() {
        let f = Fixture::new();
        let context = AuthenticationContext {
            request_id: "scoped-session".into(),
            remote_addr: "127.0.0.1".into(),
            user_agent: "public fixture".into(),
        };
        let legacy = RuntimeBrowserGateway::for_test(&f.root);
        let alice = legacy
            .build_session_service()
            .issue(&context, "alice@example.test", RequiredSecondFactor::Totp)
            .unwrap();
        let bob = legacy
            .build_session_service()
            .issue(&context, "bob@example.test", RequiredSecondFactor::Totp)
            .unwrap();
        let alice_path =
            FileSessionStore::new(f.root.join("sessions")).session_path(&alice.record.session_id);
        let before = std::fs::read(&alice_path).unwrap();
        for capability in [
            AccountRuntimeCapability::ConfiguredUnavailable,
            AccountRuntimeCapability::Disabled,
            f.pair(29, 17, 19),
        ] {
            let ready = capability.ready().is_some();
            let mut gateway = legacy.clone();
            gateway.account_runtime = capability;
            gateway.account_rollout = Some("alice@example.test".into());
            assert!(matches!(
                gateway
                    .validate_session(&context, alice.token.as_str())
                    .decision,
                BrowserSessionDecision::Invalid
            ));
            assert_eq!(std::fs::read(&alice_path).unwrap(), before);
            assert!(matches!(
                gateway
                    .validate_session(&context, bob.token.as_str())
                    .decision,
                BrowserSessionDecision::Valid { .. }
            ));
            // An epoch-bearing record cannot silently downgrade to legacy.
            assert!(gateway
                .build_session_service()
                .issue_with_epoch(
                    &context,
                    "bob@example.test",
                    RequiredSecondFactor::Totp,
                    Some(7)
                )
                .is_err());
            let mut alice_record = alice.record.clone();
            alice_record.account_epoch = Some(7);
            let selected = ValidatedSession {
                record: alice_record,
                audit_event: alice.audit_event.clone(),
            };
            assert_eq!(
                BrowserGateway::password_change_available(&gateway, &selected),
                ready
            );
            let mut bob_record = bob.record.clone();
            bob_record.account_epoch = Some(7);
            let unrelated = ValidatedSession {
                record: bob_record,
                audit_event: bob.audit_event.clone(),
            };
            assert!(!BrowserGateway::password_change_available(
                &gateway, &unrelated
            ));
            assert_eq!(
                BrowserGateway::password_changed_at(&gateway, &unrelated),
                None
            );
            let request = crate::password_change::Request::new(
                "public old passphrase",
                "public new passphrase",
                "public new passphrase",
                "123456",
            )
            .unwrap();
            assert!(matches!(
                gateway
                    .prepare_password_change(&context, &unrelated, request)
                    .authorization,
                Err(crate::password_change::Error::Unavailable)
            ));
            if ready {
                use crate::openpgp_inventory_runtime::{now, read_frame, write_frame};
                use std::time::{Duration, Instant};
                let listener = f.listeners[0].try_clone().unwrap();
                let server = std::thread::spawn(move || {
                    // Actual selected issuance, validation and history each
                    // require their own MAC-bound admission exchange.
                    for _ in 0..3 {
                        let deadline = Instant::now() + Duration::from_secs(3);
                        let mut stream = loop {
                            match listener.accept() {
                                Ok((stream, _)) => break stream,
                                Err(error)
                                    if error.kind() == std::io::ErrorKind::WouldBlock
                                        && Instant::now() < deadline =>
                                {
                                    std::thread::sleep(Duration::from_millis(1))
                                }
                                Err(error) => panic!("bounded scoped admission failed: {error}"),
                            }
                        };
                        let raw =
                            read_frame(&mut stream, crate::account_admission::MAX_FRAME, deadline)
                                .unwrap();
                        let request = crate::account_admission::Verifier::default()
                            .request(&raw, &[29; 32], now().unwrap())
                            .unwrap();
                        assert_eq!(request.account(), "alice@example.test");
                        assert!(matches!(
                            request.operation(),
                            crate::account_admission::Operation::Admit { epoch: 7 }
                        ));
                        let reply = request
                            .response_with_status(
                                Some(7),
                                Some("20261004170001".into()),
                                &[29; 32],
                                now().unwrap(),
                            )
                            .unwrap();
                        write_frame(&mut stream, &reply, deadline).unwrap();
                    }
                });
                let issued = gateway
                    .build_session_service()
                    .issue_with_epoch(
                        &context,
                        "alice@example.test",
                        RequiredSecondFactor::Totp,
                        Some(7),
                    )
                    .unwrap();
                let validated = gateway.validate_session(&context, issued.token.as_str());
                let BrowserSessionDecision::Valid { validated_session } = validated.decision else {
                    panic!("selected bound session refused");
                };
                assert_eq!(
                    BrowserGateway::password_changed_at(&gateway, &validated_session),
                    Some("20261004170001".into())
                );
                server.join().unwrap();
            } else {
                assert!(gateway
                    .build_session_service()
                    .issue_with_epoch(
                        &context,
                        "alice@example.test",
                        RequiredSecondFactor::Totp,
                        Some(7),
                    )
                    .is_err());
            }
        }
        assert_eq!(std::fs::read(&alice_path).unwrap(), before);
        for listener in &f.listeners {
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }

    #[test]
    fn password_status_runtime_delegates_authenticated_time_and_preserves_storage() {
        use crate::openpgp_inventory_runtime::{now, read_frame, write_frame};
        use std::time::{Duration, Instant};
        for expected in [Some("20261004170001".to_owned()), None] {
            let f = Fixture::new();
            let mut gateway = RuntimeBrowserGateway::for_test(&f.root);
            gateway.account_runtime = f.pair(29, 17, 19);
            let context = AuthenticationContext {
                request_id: "public-status".into(),
                remote_addr: "127.0.0.1".into(),
                user_agent: "public fixture".into(),
            };
            let issued = RuntimeBrowserGateway::for_test(&f.root)
                .build_session_service()
                .issue(&context, "alice@example.test", RequiredSecondFactor::Totp)
                .unwrap();
            let path = FileSessionStore::new(f.root.join("sessions"))
                .session_path(&issued.record.session_id);
            let before = std::fs::read(&path).unwrap();
            let mut record = issued.record;
            record.account_epoch = Some(7);
            let session = ValidatedSession {
                record,
                audit_event: issued.audit_event,
            };
            let listener = f.listeners[0].try_clone().unwrap();
            let reply_stamp = expected.clone();
            let server = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(3);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(1))
                        }
                        Err(error) => panic!("bounded status accept failed: {error}"),
                    }
                };
                let raw =
                    read_frame(&mut stream, crate::account_admission::MAX_FRAME, deadline).unwrap();
                let request = crate::account_admission::Verifier::default()
                    .request(&raw, &[29; 32], now().unwrap())
                    .unwrap();
                assert_eq!(request.account(), "alice@example.test");
                assert!(matches!(
                    request.operation(),
                    crate::account_admission::Operation::Admit { epoch: 7 }
                ));
                let reply = request
                    .response_with_status(Some(7), reply_stamp, &[29; 32], now().unwrap())
                    .unwrap();
                write_frame(&mut stream, &reply, deadline).unwrap();
            });
            let actual = BrowserGateway::password_changed_at(&gateway, &session);
            assert_eq!(actual, expected);
            server.join().unwrap();
            assert_eq!(std::fs::read(path).unwrap(), before);
            assert_eq!(
                f.listeners[1].accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            for authentication in [false, true] {
                let html = crate::http_ui::render_security_page(
                    "alice@example.test",
                    "public-csrf",
                    &BrowserSessionListDecision::Denied {
                        public_reason: "public".into(),
                    },
                    None,
                    authentication,
                    true,
                    actual.as_deref(),
                );
                assert_eq!(
                    html.as_str().contains("2026-10-04 17:00:01 UTC"),
                    actual.is_some()
                );
                assert_eq!(
                    html.as_str().contains("Last change unknown"),
                    actual.is_none()
                );
            }
        }
    }

    // Run as one disposable libtest process, never in a shared test runner.
    // Actual pledge/unveil is irreversible. The root is printed before seal
    // and intentionally retained for the external owner's bounded cleanup.
    #[cfg(target_os = "openbsd")]
    #[test]
    #[ignore = "requires isolated OpenBSD process and externally owned fixture cleanup"]
    fn native_serve_account_seal_keeps_hidden_ancestry_and_actual_typed_exchanges() {
        use crate::openpgp_inventory_runtime::{now, read_frame, validate_socket, write_frame};
        use std::time::{Duration, Instant};
        let mut fixture = std::mem::ManuallyDrop::new(Fixture::new());
        println!("serve_account_fixture_root={}", fixture.root.display());
        let at = now().unwrap();
        let mutation_request = crate::account_mutation::tests::issue_timed(
            "public-old-value",
            "public-new-passphrase",
            3,
            at,
            at,
        )
        .unwrap();
        let stopped_request = crate::account_mutation::tests::issue_timed(
            "public-old-value",
            "public-new-passphrase",
            3,
            at,
            at,
        )
        .unwrap();
        let mut config = AppConfig::from_env_map(&std::collections::BTreeMap::from([
            ("OSMAP_RUN_MODE".into(), "serve".into()),
            (
                "OSMAP_STATE_DIR".into(),
                fixture.root.join("state").to_str().unwrap().into(),
            ),
            ("OSMAP_OPENBSD_CONFINEMENT_MODE".into(), "enforce".into()),
        ]))
        .unwrap();
        config.account_runtime = Some(crate::config::AccountRuntimeConfig {
            rollout_account: None,
            admission_socket: fixture.root.join("admission.sock"),
            admission_key_file: fixture.root.join("admission.key"),
            admission_helper_uid: crate::openbsd::effective_uid(),
            mutation_socket: fixture.root.join("mutation.sock"),
            mutation_key_file: fixture.root.join("mutation.key"),
            session_proof_key_file: fixture.root.join("proof.key"),
            mutation_helper_uid: crate::openbsd::effective_uid(),
        });
        for path in [
            &config.state_root,
            &config.state_layout.runtime_dir,
            &config.state_layout.session_dir,
            &config.state_layout.settings_dir,
            &config.state_layout.draft_dir,
            &config.state_layout.audit_dir,
            &config.state_layout.cache_dir,
            &config.state_layout.totp_secret_dir,
        ] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        // Finish the owned namespace before capturing exact parent identity.
        let paired = fixture.pair(29, 17, 19);
        assert!(paired.ready().is_some());
        let mut servers = Vec::new();
        for (index, listener) in fixture.listeners.iter().enumerate() {
            let listener = listener.try_clone().unwrap();
            servers.push(std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("bounded fixture accept failed: {error}"),
                    }
                };
                assert_eq!(
                    crate::openbsd::unix_stream_peer_uid(&stream).unwrap(),
                    crate::openbsd::effective_uid()
                );
                let raw =
                    read_frame(&mut stream, crate::account_mutation::MAX_FRAME, deadline).unwrap();
                let reply = if index == 0 {
                    crate::account_admission::Verifier::default()
                        .request(&raw, &[29; 32], now().unwrap())
                        .unwrap()
                        .response(Some(7), &[29; 32], now().unwrap())
                        .unwrap()
                } else {
                    crate::account_mutation::Verifier::default()
                        .request(&raw, &[17; 32], now().unwrap())
                        .unwrap()
                        .response(
                            crate::account_mutation::Outcome::KnownRefused,
                            &[17; 32],
                            now().unwrap(),
                        )
                        .unwrap()
                };
                write_frame(&mut stream, &reply, deadline).unwrap();
            }));
        }
        let logger = crate::logging::Logger::new(
            crate::config::LogFormat::Text,
            crate::config::LogLevel::Error,
        );
        let seal = crate::openbsd::apply_runtime_confinement_for_accounts(
            &config,
            &logger,
            paired.confinement_clients(),
        )
        .unwrap()
        .unwrap();
        // Historical full pathname checks fail with the unchanged exact leaf
        // grants; the real capability is what permits the successor checks.
        assert!(std::fs::symlink_metadata(&fixture.root).is_err());
        assert!(validate_socket(
            &fixture.root.join("admission.sock"),
            crate::openbsd::effective_uid()
        )
        .is_err());
        let paired = paired.after_confinement(Some(&seal));
        let gateway = RuntimeBrowserGateway::from_config_with_account(&config, paired);
        let ready = gateway.account_runtime.ready().unwrap();
        assert_eq!(
            ready
                .admission
                .authenticate_before(
                    "alice@example.test",
                    "public credential",
                    Instant::now() + Duration::from_secs(2)
                )
                .unwrap()
                .unwrap()
                .epoch,
            7
        );
        assert_eq!(
            ready
                .mutation
                .execute(mutation_request, Instant::now() + Duration::from_secs(2))
                .unwrap()
                .outcome(),
            &crate::account_mutation::Outcome::KnownRefused
        );
        for server in servers {
            server.join().unwrap();
        }
        fixture.listeners.clear();
        assert!(ready
            .admission
            .authenticate_before(
                "alice@example.test",
                "public credential",
                Instant::now() + Duration::from_millis(200)
            )
            .is_err());
        assert!(ready
            .mutation
            .execute(stopped_request, Instant::now() + Duration::from_millis(200))
            .is_err());
        // Exact keys are read-only under Serve: no test-only path broadening.
        assert!(std::fs::write(fixture.root.join("proof.key"), [20; 32]).is_err());
        println!("serve_account_hidden_ancestry_typed_exchange_stopped_refusal=PASS");
    }
    #[test]
    fn native_local_runtime_route_requires_entire_fixed_pair_and_root_helpers() {
        let base = crate::config::AccountRuntimeConfig {
            rollout_account: None,
            admission_socket: crate::config::LOCAL_ACCOUNT_ADMISSION_SOCKET.into(),
            admission_key_file: "/nonexistent/native-admission.key".into(),
            admission_helper_uid: 0,
            mutation_socket: crate::config::LOCAL_ACCOUNT_MUTATION_SOCKET.into(),
            mutation_key_file: "/nonexistent/native-mutation.key".into(),
            session_proof_key_file: "/nonexistent/native-session-proof.key".into(),
            mutation_helper_uid: 0,
        };
        assert!(AccountRuntimeCapability::native_local_pair(&base));
        for case in 0..6 {
            let mut config = base.clone();
            match case {
                0 => config.admission_socket = "/private/foreign-admission.sock".into(),
                1 => config.mutation_socket = "/private/foreign-mutation.sock".into(),
                2 => config.admission_helper_uid = 1003,
                3 => config.mutation_helper_uid = 1004,
                4 => config.admission_helper_uid = u32::MAX,
                _ => config.mutation_socket = config.admission_socket.clone(),
            }
            assert!(!AccountRuntimeCapability::native_local_pair(&config));
            assert_eq!(
                AccountRuntimeCapability::from_config(Some(&config)),
                AccountRuntimeCapability::ConfiguredUnavailable
            );
        }
        // Eligible metadata does not bypass native context or key custody, and
        // refusal retains configured intent instead of falling back to legacy.
        assert_eq!(
            AccountRuntimeCapability::from_config(Some(&base)),
            AccountRuntimeCapability::ConfiguredUnavailable
        );
        assert_eq!(
            AccountRuntimeCapability::from_config(None),
            AccountRuntimeCapability::Disabled
        );
    }
}
