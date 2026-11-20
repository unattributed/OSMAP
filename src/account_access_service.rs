//! Browser recovery actions in the existing native account service. Fixed
//! root-owned configuration supplies already registered recovery contacts.
//! Initial enrollment uses an administrator-authorized pending SQL record and
//! the same email proof and enrollment flow, without inventing a prior factor.
use crate::access_recovery::{self as recovery, EligibleAccount};
use crate::access_recovery_protocol::{self as protocol, Action, Authority, Request, Response};
use crate::account_factor_replacement::{Coordinator, Error as FactorError, Paths};
use crate::account_password_backend::{Backend, CreationRegistration};
use crate::account_password_state::Store as EpochStore;
use crate::auth::CommandExecutor;
use crate::browser_access::{AccessCookie, AccessError, AccessOutcome, AccessView};
use crate::totp::{SystemTimeProvider, TimeProvider};
use crate::totp_enrollment::{
    EnrollmentBinding, EnrollmentError, EnrollmentStore, PendingEnrollment,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const CONFIG: &str = crate::account_access_config::PATH;
const ROOT: &str = "/var/db/osmap-account/access-recovery";
const EPOCH: &str = "/var/db/osmap-account/epoch";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contact {
    account: String,
    email: String,
    revision: u64,
    verified_at: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u8,
    contacts: Vec<Contact>,
    #[serde(default)]
    initial_setup: bool,
}

pub(crate) struct NativeAccess {
    config: Config,
    config_sha256: String,
    paths: crate::account_recovery_operator::RuntimePaths,
    uid: u32,
    gid: u32,
    root: PathBuf,
    selected: Option<String>,
    session_idle_seconds: u64,
    epoch_root: PathBuf,
    operator_uid: u32,
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn config_bytes() -> Result<Option<Vec<u8>>, AccessError> {
    crate::account_access_config::read().map_err(|failure| {
        eprintln!(
            "account_access_service stage=config_read check={:?} errno={:?}",
            failure.stage, failure.errno
        );
        AccessError::Unavailable
    })
}
impl NativeAccess {
    /// Called before the native parent is sealed. Absence leaves the existing
    /// account service operational and recovery explicitly unavailable.
    pub(crate) fn from_operator() -> Result<Option<Self>, AccessError> {
        let Some(bytes) = config_bytes()? else {
            return Ok(None);
        };
        let config: Config =
            serde_json::from_slice(&bytes).map_err(|_| AccessError::Unavailable)?;
        if config.version != 1 || config.contacts.len() > 64 {
            return Err(AccessError::Unavailable);
        }
        let mut accounts = BTreeSet::new();
        for c in &config.contacts {
            if crate::account_admission::valid_account(&c.account).is_err()
                || crate::mail_address::validate_address(
                    crate::send::ComposePolicy::default(),
                    &c.email,
                )
                .is_err()
                || !c.email.is_ascii()
                || c.email == c.account
                || c.email.chars().any(char::is_control)
                || c.revision == 0
                || c.verified_at == 0
                || !accounts.insert(c.account.clone())
            {
                return Err(AccessError::Unavailable);
            }
        }
        let (paths, uid, gid, selected, session_idle_seconds) =
            crate::account_recovery_operator::browser_recovery_paths()
                .map_err(|_| AccessError::Unavailable)?;
        // Installation prepares these existing private directories. Validate
        // them before irreversible confinement or a recovery dispatch; first
        // use must never discover a missing archive after account containment.
        use std::os::unix::fs::MetadataExt as _;
        for (path, owner, group) in [
            (Path::new(ROOT), 0, None),
            (paths.session_directory.as_path(), uid, Some(gid)),
            (paths.factor_directory.as_path(), uid, Some(gid)),
            (paths.revoked_directory.as_path(), uid, Some(gid)),
        ] {
            let metadata = std::fs::symlink_metadata(path).map_err(|_| AccessError::Unavailable)?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != owner
                || metadata.mode() & 0o7777 != 0o700
                || group.is_some_and(|v| v != metadata.gid())
            {
                return Err(AccessError::Unavailable);
            }
        }
        if config.initial_setup {
            crate::initial_factor::InitialFactor::new(crate::initial_factor::Paths {
                factors: paths.factor_directory.clone(),
                replay: paths.replay_directory.clone(),
                runtime_uid: uid,
                runtime_gid: gid,
            })
            .check_paths()
            .map_err(|_| AccessError::Unavailable)?;
            let contact_dir = paths.settings_directory.join("recovery-contact-v1");
            let metadata =
                std::fs::symlink_metadata(&contact_dir).map_err(|_| AccessError::Unavailable)?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != uid
                || metadata.gid() != gid
                || metadata.mode() & 0o7777 != 0o700
            {
                return Err(AccessError::Unavailable);
            }
        }
        Ok(Some(Self {
            config,
            config_sha256: sha(&bytes),
            paths,
            uid,
            gid,
            root: ROOT.into(),
            selected,
            session_idle_seconds,
            epoch_root: EPOCH.into(),
            operator_uid: 0,
        }))
    }
    /// Only paths parsed from the fixed root-owned service environment enter
    /// the native unveil table. The Web process receives no new path authority.
    pub(crate) fn rules(&self) -> Vec<(PathBuf, &'static str)> {
        let mut rules = vec![
            (CONFIG.into(), "r"),
            ("/etc/osmap/osmap-serve.env".into(), "r"),
            (self.root.clone(), "rwc"),
            (self.paths.session_directory.clone(), "rwc"),
            (self.paths.factor_directory.clone(), "rwc"),
            (self.paths.revoked_directory.clone(), "rwc"),
        ];
        if self.config.initial_setup {
            rules.push((self.paths.replay_directory.clone(), "rwc"));
        }
        // Exact metadata visibility for descriptor/custody ancestor checks;
        // empty permissions reveal no sibling contents or recursive file reads.
        rules.push((
            self.paths.settings_directory.join("recovery-contact-v1"),
            if self.config.initial_setup {
                "rwc"
            } else {
                "r"
            },
        ));
        let parents = rules
            .iter()
            .flat_map(|(path, _)| path.ancestors().skip(1).map(Path::to_path_buf))
            .collect::<BTreeSet<_>>();
        rules.extend(parents.into_iter().map(|path| (path, "")));
        rules
    }
    fn allowed(&self, account: &str, accounts: &BTreeSet<String>) -> bool {
        accounts.contains(account)
            && self
                .selected
                .as_deref()
                .is_none_or(|selected| selected == account)
    }
    fn factor(&self) -> Coordinator {
        Coordinator::new(Paths {
            epoch: self.epoch_root.clone(),
            cases: self.root.join("factor-cases"),
            sessions: self.paths.session_directory.clone(),
            factors: self.paths.factor_directory.clone(),
            archive: self.paths.revoked_directory.clone(),
            operator_uid: self.operator_uid,
            runtime_uid: self.uid,
            runtime_gid: self.gid,
        })
    }
    fn initial_factor(&self) -> crate::initial_factor::InitialFactor {
        crate::initial_factor::InitialFactor::new(crate::initial_factor::Paths {
            factors: self.paths.factor_directory.clone(),
            replay: self.paths.replay_directory.clone(),
            runtime_uid: self.uid,
            runtime_gid: self.gid,
        })
    }
    fn enrollment(&self) -> EnrollmentStore {
        EnrollmentStore::new(self.root.join("enrollments"))
    }
    fn recovery(&self) -> recovery::Store {
        recovery::Store::new(self.root.join("proofs"))
    }
    fn check(&self) -> Result<(), AccessError> {
        let (paths, selected, idle) =
            crate::account_recovery_operator::browser_recovery_fence(self.gid)
                .map_err(|_| {
                    eprintln!("account_access_service stage=fence_read result=unavailable native_errno=not_observed");
                    AccessError::Unavailable
                })?;
        if paths != self.paths || selected != self.selected || idle != self.session_idle_seconds {
            eprintln!("account_access_service stage=fence_binding result=unavailable");
            return Err(AccessError::Unavailable);
        }
        if config_bytes()?.is_none_or(|b| sha(&b) != self.config_sha256) {
            eprintln!("account_access_service stage=config_hash result=unavailable");
            Err(AccessError::Unavailable)
        } else {
            Ok(())
        }
    }
    #[allow(clippy::too_many_arguments)] // Authenticated frame and existing native dependencies.
    pub(crate) fn exchange<E: CommandExecutor, P: CommandExecutor>(
        configured: Option<&Self>,
        raw: &[u8],
        key: &[u8],
        epochs: &EpochStore,
        accounts: &BTreeSet<String>,
        backend: &Backend<E>,
        primary: &P,
        stock_peer: &crate::account_password_peer::StockPeer,
        deadline: Instant,
    ) -> Result<Vec<u8>, crate::account_password_connection::Error> {
        use crate::account_password_connection::Error as ConnectionError;
        let now = SystemTimeProvider.unix_timestamp();
        let parsed = Request::parse(raw, key, now).map_err(|_| ConnectionError::Authentication)?;
        let outcome = match configured {
            None => Err(AccessError::Unavailable),
            Some(service) => service.check().and_then(|_| {
                let request = protocol::ReplayStore::new(service.root.join("rpc-replay"))
                    .verify_and_consume(raw, key, now)
                    .map_err(|_| AccessError::Refused)?;
                let remaining = request
                    .expires()
                    .checked_sub(now)
                    .ok_or(AccessError::Expired)?;
                let deadline = deadline.min(Instant::now() + Duration::from_secs(remaining));
                service.execute(
                    &request,
                    epochs,
                    accounts,
                    backend,
                    primary,
                    &|budget| {
                        stock_peer
                            .recheck(budget)
                            .map_err(|_| AccessError::Unavailable)
                    },
                    now,
                    deadline,
                )
            }),
        };
        Response::issue(&parsed, outcome, key, SystemTimeProvider.unix_timestamp())
            .and_then(|r| r.bytes())
            .map_err(|_| ConnectionError::Unavailable)
    }
    fn binding(
        &self,
        account: &str,
        session_id: &str,
        epoch: u64,
        deadline: Instant,
    ) -> Result<EnrollmentBinding, AccessError> {
        let (current, factor) = self
            .factor()
            .snapshot(account, deadline)
            .map_err(factor_error)?;
        if current != epoch {
            return Err(AccessError::Conflict);
        }
        Ok(EnrollmentBinding {
            account: account.into(),
            session_id: session_id.into(),
            epoch,
            factor: recovery::FactorBinding::Existing(factor),
        })
    }
    fn grant_binding(
        &self,
        grant: &recovery::GrantBinding,
        token: &str,
        deadline: Instant,
    ) -> Result<EnrollmentBinding, AccessError> {
        match (&grant.purpose, &grant.factor) {
            (recovery::Purpose::AccountRecoverySetup, recovery::FactorBinding::Existing(_)) => self
                .binding(
                    &grant.account,
                    &sha(token.as_bytes()),
                    grant.epoch,
                    deadline,
                ),
            (
                recovery::Purpose::InitialAccountSetup,
                factor @ recovery::FactorBinding::Absent { .. },
            ) if self.config.initial_setup && grant.epoch == 0 => {
                self.initial_factor()
                    .check_absent(&grant.account, deadline)
                    .map_err(|_| AccessError::Refused)?;
                Ok(EnrollmentBinding {
                    account: grant.account.clone(),
                    session_id: sha(token.as_bytes()),
                    epoch: 0,
                    factor: factor.clone(),
                })
            }
            _ => Err(AccessError::Refused),
        }
    }
    fn begin(
        &self,
        binding: EnrollmentBinding,
        now: u64,
        deadline: Instant,
    ) -> Result<PendingEnrollment, AccessError> {
        let store = self.enrollment();
        let revision = store
            .revision(&binding.account, deadline)
            .map_err(enrollment_error)?;
        store
            .begin(binding, revision, now, deadline)
            .map_err(enrollment_error)
    }
    #[allow(clippy::too_many_arguments)] // Fixed privileged dependencies and one original request budget.
    fn execute<E: CommandExecutor, P: CommandExecutor>(
        &self,
        request: &Request,
        epochs: &EpochStore,
        accounts: &BTreeSet<String>,
        backend: &Backend<E>,
        primary: &P,
        cache_zero: &impl Fn(Instant) -> Result<(), AccessError>,
        now: u64,
        deadline: Instant,
    ) -> Result<AccessOutcome, AccessError> {
        if let Authority::Session {
            account,
            epoch,
            session_id,
        } = request.authority()
        {
            if !self.allowed(account, accounts) {
                return Err(AccessError::Refused);
            }
            crate::session::validate_recovery_session(
                &self.paths.session_directory,
                self.uid,
                self.gid,
                account,
                *epoch,
                session_id,
                request.csrf(),
                now,
                self.session_idle_seconds,
                deadline,
            )
            .map_err(|_| AccessError::Refused)?;
        }
        let csrf = request.csrf();
        let authority = Eligible {
            service: self,
            accounts,
            epochs,
            backend,
        };
        let unchanged = |view| {
            Ok(AccessOutcome {
                view,
                grant_cookie: AccessCookie::Unchanged,
            })
        };
        match (request.authority(), request.action()) {
            (Authority::Unauthenticated {}, Action::View {}) => {
                unchanged(AccessView::RecoveryEmail { csrf: csrf.into() })
            }
            (Authority::Unauthenticated {}, Action::Start { email }) => {
                // The same minimum response floor applies to known, unknown,
                // processed and delivery-refused requests. SMTP is separately
                // bounded; response shape never discloses the recipient.
                let began = Instant::now();
                let floor = began + Duration::from_secs(11);
                if floor >= deadline {
                    return Err(AccessError::Expired);
                }
                let result = self.recovery().start(
                    recovery::Start {
                        account: email,
                        source: request.source(),
                        flow: csrf,
                        now,
                        deadline,
                    },
                    &authority,
                    &crate::access_recovery_mail::NativeSmtp,
                );
                // A source-only throttle is independent of account existence
                // and must not occupy a native worker for the response floor.
                if matches!(&result, Ok(started) if started.source_limited) {
                    return Err(AccessError::Throttled);
                }
                if Instant::now() < floor {
                    std::thread::sleep(floor.duration_since(Instant::now()));
                }
                let started = result.map_err(recovery_error)?;
                unchanged(AccessView::RecoveryCode {
                    csrf: csrf.into(),
                    challenge_id: started.challenge_id,
                })
            }
            (Authority::Unauthenticated {}, Action::Verify { challenge_id, code }) => {
                let grant = self
                    .recovery()
                    .verify_challenge(
                        challenge_id,
                        csrf,
                        request.source(),
                        code,
                        now,
                        deadline,
                        &authority,
                    )
                    .map_err(recovery_error)?;
                let binding = self.grant_binding(&grant.binding, grant.token(), deadline)?;
                let enrollment = self.begin(binding, now, deadline)?;
                Ok(AccessOutcome {
                    view: AccessView::RecoverySetup {
                        csrf: csrf.into(),
                        enrollment,
                    },
                    grant_cookie: AccessCookie::Set(grant.token().into()),
                })
            }
            (
                Authority::Session {
                    account,
                    epoch,
                    session_id,
                },
                Action::View {},
            ) => {
                if !self.allowed(account, accounts) {
                    return Err(AccessError::Refused);
                }
                let binding = self.binding(account, session_id, *epoch, deadline)?;
                match self
                    .enrollment()
                    .pending(&binding, now, deadline)
                    .map_err(enrollment_error)?
                {
                    Some(enrollment) => unchanged(AccessView::TotpReplacement {
                        account: account.clone(),
                        csrf: csrf.into(),
                        enrollment,
                    }),
                    None => unchanged(AccessView::TotpResetStart {
                        account: account.clone(),
                        csrf: csrf.into(),
                    }),
                }
            }
            (
                Authority::Session {
                    account,
                    epoch,
                    session_id,
                },
                Action::BeginReset { password, totp },
            ) => {
                if !self.allowed(account, accounts) {
                    return Err(AccessError::Refused);
                }
                let binding = self.binding(account, session_id, *epoch, deadline)?;
                let rate = crate::password_change_rate::Store::new(self.root.join("stepup-rate"));
                let permit = rate
                    .admit(account, request.source(), now)
                    .map_err(|_| AccessError::Throttled)?;
                let password_ok =
                    crate::account_password_mail::primary(primary, account, password, deadline)
                        .map_err(|_| AccessError::Unavailable)?;
                let factor_ok = self
                    .factor()
                    .verify_current_code(account, totp, now, deadline)
                    .map_err(factor_error)?;
                if !password_ok || !factor_ok {
                    permit
                        .failed(SystemTimeProvider.unix_timestamp())
                        .map_err(|_| AccessError::Unavailable)?;
                    return Err(AccessError::Refused);
                }
                permit.confirm().map_err(|_| AccessError::Unavailable)?;
                let current = self.binding(account, session_id, *epoch, deadline)?;
                if current != binding {
                    return Err(AccessError::Conflict);
                }
                unchanged(AccessView::TotpReplacement {
                    account: account.clone(),
                    csrf: csrf.into(),
                    enrollment: self.begin(binding, now, deadline)?,
                })
            }
            (Authority::Grant { token }, Action::View {}) => {
                let grant = self
                    .recovery()
                    .lookup_grant(token, csrf, now, deadline, &authority)
                    .map_err(recovery_error)?;
                let binding = self.grant_binding(&grant, token, deadline)?;
                let enrollment = self
                    .enrollment()
                    .pending(&binding, now, deadline)
                    .map_err(enrollment_error)?
                    .ok_or(AccessError::Expired)?;
                unchanged(AccessView::RecoverySetup {
                    csrf: csrf.into(),
                    enrollment,
                })
            }
            (
                Authority::Session {
                    account,
                    epoch,
                    session_id,
                },
                Action::Confirm {
                    enrollment_id,
                    revision,
                    code,
                    password: None,
                    confirmation: None,
                },
            ) => {
                if !self.allowed(account, accounts) {
                    return Err(AccessError::Refused);
                }
                let binding = self.binding(account, session_id, *epoch, deadline)?;
                let verified = self
                    .enrollment()
                    .verify(&binding, enrollment_id, *revision, code, now, deadline)
                    .map_err(enrollment_error)?;
                self.factor()
                    .replace_session(
                        verified,
                        csrf,
                        self.session_idle_seconds,
                        now,
                        deadline,
                        |_| Ok(None),
                    )
                    .map_err(factor_error)?;
                Ok(AccessOutcome {
                    view: AccessView::Complete,
                    grant_cookie: AccessCookie::Clear,
                })
            }
            (
                Authority::Grant { token },
                Action::Confirm {
                    enrollment_id,
                    revision,
                    code,
                    password: Some(password),
                    confirmation: Some(confirmation),
                },
            ) => {
                if !crate::password_change::valid_new_password(password, confirmation) {
                    return Err(AccessError::Refused);
                }
                let grant = self
                    .recovery()
                    .lookup_grant(token, csrf, now, deadline, &authority)
                    .map_err(recovery_error)?;
                let binding = self.grant_binding(&grant, token, deadline)?;
                if grant.purpose == recovery::Purpose::InitialAccountSetup {
                    let pending = backend
                        .pending_initial(&grant.account, deadline)
                        .map_err(|_| AccessError::Unavailable)?
                        .ok_or(AccessError::Refused)?;
                    let recovery_email = pending.email.clone();
                    cache_zero(deadline)?;
                    let verified = self
                        .enrollment()
                        .verify(&binding, enrollment_id, *revision, code, now, deadline)
                        .map_err(enrollment_error)?;
                    self.recovery()
                        .consume_grant(token, csrf, now, deadline, &authority, |current| {
                            backend
                                .activate_initial(
                                    pending,
                                    current,
                                    password,
                                    confirmation,
                                    deadline,
                                    || {
                                        epochs.provision_initial(&current.account, deadline)
                                            .map_err(|_| {
                                                eprintln!("account_access_service stage=initial_epoch result=unconfirmed resources=retained");
                                                crate::account_password_backend::Error::Refused
                                            })?;
                                        crate::recovery_contact::RecoveryContactStore::new(
                                            self.paths.settings_directory.join("recovery-contact-v1"),
                                        ).install_initial_native(
                                            &recovery_email, current, now, self.uid, self.gid, deadline,
                                        ).map_err(|_| {
                                            eprintln!("account_access_service stage=initial_contact result=unconfirmed resources=retained");
                                            crate::account_password_backend::Error::Refused
                                        })?;
                                        self.initial_factor()
                                            .install(
                                                &current.account,
                                                verified.secret_base32(),
                                                verified.accepted_counter(),
                                                deadline,
                                            )
                                            .map(|_| ())
                                            .map_err(|error| {
                                                eprintln!("account_access_service stage=initial_factor result=unconfirmed code={} resources=retained", error.code());
                                                crate::account_password_backend::Error::Refused
                                            })
                                    },
                                )
                                .map_err(|_| {
                                    eprintln!("account_access_service stage=initial_activation result=unconfirmed native_cause=not_observed resources=retained automatic_retry=false");
                                    recovery::Error::Unconfirmed
                                })?;
                            cache_zero(deadline).map_err(|_| recovery::Error::Unconfirmed)?;
                            if !crate::account_password_mail::primary(
                                primary, &current.account, password, deadline,
                            )
                            .map_err(|_| recovery::Error::Unconfirmed)? {
                                return Err(recovery::Error::Unconfirmed);
                            }
                            Ok(())
                        })
                        .map_err(recovery_error)?;
                    return Ok(AccessOutcome {
                        view: AccessView::Complete,
                        grant_cookie: AccessCookie::Clear,
                    });
                }
                let snapshot = backend
                    .read(&grant.account, deadline)
                    .map_err(|_| AccessError::Unavailable)?;
                let verified = self
                    .enrollment()
                    .verify(&binding, enrollment_id, *revision, code, now, deadline)
                    .map_err(enrollment_error)?;
                self.recovery()
                    .consume_grant(token, csrf, now, deadline, &authority, |grant| {
                        self.factor()
                            .replace(verified, now, deadline, |record_stamp| {
                                eprintln!("account_access_service stage=password_write result=dispatch");
                                let receipt = backend
                                    .reset_after_recovery(
                                        snapshot,
                                        grant,
                                        password,
                                        confirmation,
                                        deadline,
                                        || Ok(()),
                                    )
                                    .map_err(|_| {
                                        eprintln!("account_access_service stage=password_write result=unconfirmed");
                                        FactorError::PasswordReset
                                    })?;
                                record_stamp(receipt.changed_at()).inspect_err(|_| {
                                    eprintln!("account_access_service stage=password_receipt result=unavailable");
                                })?;
                                eprintln!("account_access_service stage=password_receipt result=recorded");
                                // Stock Dovecot uses the same protected cache-zero
                                // witness as ordinary password changes, not FLUSH.
                                cache_zero(deadline).map_err(|_| {
                                    eprintln!("account_access_service stage=cache_zero result=unavailable");
                                    FactorError::PasswordReset
                                })?;
                                eprintln!("account_access_service stage=cache_zero result=confirmed");
                                if !crate::account_password_mail::primary(
                                    primary,
                                    &grant.account,
                                    password,
                                    deadline,
                                )
                                .map_err(|_| {
                                    eprintln!("account_access_service stage=password_auth result=unavailable");
                                    FactorError::PasswordReset
                                })?
                                {
                                    eprintln!("account_access_service stage=password_auth result=refused");
                                    return Err(FactorError::PasswordReset);
                                }
                                eprintln!("account_access_service stage=password_auth result=confirmed");
                                Ok(Some(receipt.changed_at().into()))
                            })
                            .map_err(|_| recovery::Error::Unconfirmed)?;
                        Ok(())
                    })
                    .map_err(recovery_error)?;
                Ok(AccessOutcome {
                    view: AccessView::Complete,
                    grant_cookie: AccessCookie::Clear,
                })
            }
            _ => Err(AccessError::Refused),
        }
    }
}
struct Eligible<'a, E> {
    service: &'a NativeAccess,
    accounts: &'a BTreeSet<String>,
    epochs: &'a EpochStore,
    backend: &'a Backend<E>,
}
impl<E: CommandExecutor> recovery::Authority for Eligible<'_, E> {
    fn eligible(
        &self,
        account: &str,
        deadline: Instant,
    ) -> Result<Option<EligibleAccount>, recovery::Error> {
        // Initial setup cannot authorize an account that the ordinary native
        // authentication/session path will refuse. The same fixed rollout and
        // root-service roster apply to both recovery purposes.
        if !self.service.allowed(account, self.accounts) {
            return Ok(None);
        }
        let Some(contact) = self
            .service
            .config
            .contacts
            .iter()
            .find(|c| c.account == account)
        else {
            // A failed registered-contact check never reaches this branch.
            // Only the separately enabled native pending-account authority may
            // authorize first enrollment without a prior factor.
            if !self.service.config.initial_setup {
                return Ok(None);
            }
            let registration = self
                .backend
                .creation_registration(account, deadline)
                .map_err(|_| recovery::Error::Unavailable)?;
            let operation = match registration {
                None | Some(CreationRegistration::Inconsistent) => return Ok(None),
                Some(CreationRegistration::Complete(operation)) => {
                    let Some(registered) = self
                        .backend
                        .completed_initial_contact(account, &operation, deadline)
                        .map_err(|_| recovery::Error::Unavailable)?
                    else {
                        return Ok(None);
                    };
                    let contact = Contact {
                        account: registered.account,
                        email: registered.email,
                        revision: registered.revision,
                        verified_at: registered.verified_at,
                    };
                    return registered_eligible(
                        self.service,
                        account,
                        &contact,
                        self.epochs,
                        deadline,
                    );
                }
                Some(CreationRegistration::Pending(operation)) => operation,
            };
            let Some(pending) = self
                .backend
                .pending_initial(account, deadline)
                .map_err(|_| recovery::Error::Unavailable)?
                .filter(|pending| pending.operation == operation)
            else {
                return Ok(None);
            };
            if self
                .service
                .initial_factor()
                .check_absent(account, deadline)
                .is_err()
            {
                return Ok(None);
            }
            return Ok(Some(EligibleAccount {
                purpose: recovery::Purpose::InitialAccountSetup,
                epoch: 0,
                verified_email: pending.email,
                contact_revision: pending.revision,
                verified_at: pending.approved_at,
                factor: recovery::FactorBinding::Absent {
                    provision_operation: pending.operation,
                    revision: pending.revision,
                },
            }));
        };
        registered_eligible(self.service, account, contact, self.epochs, deadline)
    }
}
fn registered_eligible(
    service: &NativeAccess,
    account: &str,
    contact: &Contact,
    epochs: &EpochStore,
    deadline: Instant,
) -> Result<Option<EligibleAccount>, recovery::Error> {
    let current = crate::recovery_contact::RecoveryContactStore::new(
        service.paths.settings_directory.join("recovery-contact-v1"),
    )
    .registered_consistency(
        account,
        SystemTimeProvider.unix_timestamp(),
        &contact.email,
        service.uid,
        service.gid,
    );
    match current {
        Ok(true) => {}
        Ok(false) => return Ok(None),
        Err(_) => {
            eprintln!("account_recovery stage=eligibility code=CONTACT_UNAVAILABLE");
            return Ok(None);
        }
    }
    let status = match epochs
        .lock_before(account, deadline)
        .and_then(|guard| guard.admission(None))
    {
        Ok(status) => status,
        Err(_) => return Ok(None),
    };
    let (epoch, factor) = match service.factor().snapshot(account, deadline) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if epoch != status.epoch {
        return Ok(None);
    }
    Ok(Some(EligibleAccount {
        purpose: recovery::Purpose::AccountRecoverySetup,
        epoch,
        verified_email: contact.email.clone(),
        contact_revision: contact.revision,
        verified_at: contact.verified_at,
        factor: recovery::FactorBinding::Existing(factor),
    }))
}
fn recovery_error(e: recovery::Error) -> AccessError {
    match e {
        recovery::Error::Expired => AccessError::Expired,
        recovery::Error::Busy => AccessError::Throttled,
        recovery::Error::Unavailable => AccessError::Unavailable,
        recovery::Error::Unconfirmed => AccessError::Unconfirmed,
        _ => AccessError::Refused,
    }
}
fn enrollment_error(e: EnrollmentError) -> AccessError {
    match e {
        EnrollmentError::Expired => AccessError::Expired,
        EnrollmentError::AttemptsExhausted => AccessError::Throttled,
        EnrollmentError::Unavailable => AccessError::Unavailable,
        _ => AccessError::Refused,
    }
}
fn factor_error(e: FactorError) -> AccessError {
    match e {
        FactorError::Refused | FactorError::Replay => AccessError::Refused,
        FactorError::Expired => AccessError::Expired,
        FactorError::FactorChanged => AccessError::Conflict,
        FactorError::StateUnavailable => AccessError::Unavailable,
        _ => AccessError::Unconfirmed,
    }
}

#[cfg(test)]
#[path = "account_access_service_tests.rs"]
mod tests;
