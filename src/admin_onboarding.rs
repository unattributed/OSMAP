//! First-user setup in the existing service-held account writer. A setup bearer
//! never authorizes admin operations or a mailbox session. SQL remains disabled
//! until the owner proved a factor and the native installer confirmed custody.
use super::*;
use crate::admin_config::OnboardingConfig;
use crate::admin_transport::SetupPage;
use crate::initial_enrollment::{FailureStage, Store};
use std::time::Instant;

fn value(text: &str) -> String {
    format!("CONVERT(0x{} USING utf8mb4)", upper_hex(text.as_bytes()))
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

impl<E, T, P> Service<E, T, P>
where
    E: CommandExecutor + Clone + Send + Sync + 'static,
    T: TimeProvider + Clone,
    P: PasswordVerifier,
{
    fn initial_store(&self) -> Store {
        Store::new(self.authority.root.join("initial-enrollment"))
    }
    fn initial_config(&self, account: &str) -> Result<&OnboardingConfig, CreateFailure> {
        crate::account_admission::valid_account(account).map_err(|_| CreateFailure::Invalid)?;
        let domain = account.split_once('@').ok_or(CreateFailure::Invalid)?.1;
        let writer = self.writer.as_ref().ok_or(CreateFailure::WriterDisabled)?;
        if !writer.domains.iter().any(|d| d == domain) {
            return Err(CreateFailure::Denied);
        }
        writer
            .onboarding
            .as_ref()
            .ok_or(CreateFailure::WriterDisabled)
    }
    pub(super) fn initial_setup_absent(&self, account: &str) -> Result<(), CreateFailure> {
        let config = self.initial_config(account)?;
        crate::initial_factor_service::check_absent(&config.factor_socket, account, deadline())
            .map_err(|_| CreateFailure::Unavailable)
    }
    /// Return only a confirmed pending operation; no SQL row or active flag is
    /// enrollment authority. The protected one-use invitation is also required.
    fn initial_pending(&self, account: &str) -> Result<(String, String), CreateFailure> {
        self.initial_config(account)?;
        let writer = self.writer.as_ref().ok_or(CreateFailure::WriterDisabled)?;
        let actors = writer
            .administrators
            .iter()
            .map(|a| value(a))
            .collect::<Vec<_>>()
            .join(",");
        let query=format!("SELECT o.request_id,o.credential_digest FROM mailbox m JOIN osmap_admin_operations o ON BINARY o.username=BINARY m.username JOIN domain d ON BINARY d.domain=BINARY m.domain JOIN alias a ON BINARY a.address=BINARY m.username JOIN admin actor ON BINARY actor.username=BINARY o.actor JOIN osmap_admin_writer w ON w.id=1 WHERE BINARY m.username=BINARY {} AND m.active=0 AND m.smtp_active=0 AND BINARY o.credential_digest=BINARY SHA2(m.password,256) AND o.kind='mailbox.create' AND d.active=1 AND d.backupmx=0 AND a.active=1 AND BINARY a.goto=BINARY m.username AND BINARY a.domain=BINARY m.domain AND actor.active=1 AND o.actor IN ({actors}) AND ((actor.superadmin=1 AND EXISTS(SELECT 1 FROM domain_admins g WHERE BINARY g.username=BINARY actor.username AND g.active=1 AND g.domain='ALL')) OR (actor.superadmin=0 AND EXISTS(SELECT 1 FROM domain_admins g WHERE BINARY g.username=BINARY actor.username AND g.active=1 AND BINARY g.domain=BINARY m.domain) AND NOT EXISTS(SELECT 1 FROM domain_admins g WHERE BINARY g.username=BINARY actor.username AND g.active=1 AND g.domain='ALL'))) AND w.mode='lab_writer' AND BINARY w.holder=BINARY {} AND w.epoch={} LIMIT 2;\n",value(account),value(&writer.holder),writer.epoch);
        let result = self.writer_sql(&query, false)?;
        let fields = result
            .trim_end_matches('\n')
            .split('\t')
            .collect::<Vec<_>>();
        if fields.len() != 2
            || fields
                .iter()
                .any(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(CreateFailure::Denied);
        }
        Ok((fields[0].into(), fields[1].into()))
    }
    pub(super) fn issue_initial_setup(
        &self,
        account: &str,
        contact: &str,
        operation: &str,
    ) -> Result<(), CreateFailure> {
        let config = self.initial_config(account)?;
        let writer = self.writer.as_ref().ok_or(CreateFailure::WriterDisabled)?;
        let contact_domain = contact.rsplit_once('@').ok_or(CreateFailure::Invalid)?.1;
        // A newly hosted mailbox cannot be its own independent contact, nor
        // may another account in this writer's managed domains vouch for it.
        if writer
            .domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(contact_domain))
        {
            return Err(CreateFailure::Invalid);
        }
        let (current, _) = self.initial_pending(account)?;
        if current != operation {
            return Err(CreateFailure::Unconfirmed);
        }
        self.initial_setup_absent(account)?;
        let now = self.clock.unix_timestamp();
        let invitation = self
            .initial_store()
            .provision(account, contact, operation, now, deadline())
            .map_err(|_| CreateFailure::Unconfirmed)?;
        match crate::access_recovery_mail::NativeSmtp.deliver_initial(
            account,
            contact,
            &invitation.token,
            &config.setup_origin,
            &config.sender,
            deadline(),
        ) {
            crate::recovery_contact::RecoveryContactDelivery::Accepted => Ok(()),
            _ => Err(CreateFailure::Unconfirmed),
        }
    }
    pub(crate) fn redeem_initial_setup(
        &self,
        account: &str,
        invitation: &str,
    ) -> Result<SetupPage, CreateFailure> {
        self.initial_pending(account)?;
        self.initial_setup_absent(account)?;
        let now = self.clock.unix_timestamp();
        let store = self.initial_store();
        let grant = store
            .redeem(account, invitation, now, deadline())
            .map_err(|_| CreateFailure::Denied)?;
        let pending = store
            .pending(account, &grant.token, now, deadline())
            .map_err(|_| CreateFailure::Denied)?;
        Ok(SetupPage::from_pending(
            account.into(),
            Some(grant.token),
            pending,
        ))
    }
    pub(crate) fn view_initial_setup(
        &self,
        account: &str,
        grant: &str,
    ) -> Result<SetupPage, CreateFailure> {
        self.initial_pending(account)?;
        let now = self.clock.unix_timestamp();
        let pending = self
            .initial_store()
            .pending(account, grant, now, deadline())
            .map_err(|_| CreateFailure::Denied)?;
        Ok(SetupPage::from_pending(account.into(), None, pending))
    }
    pub(crate) fn complete_initial_setup(
        &self,
        account: &str,
        grant: &str,
        password: &str,
        confirmation: &str,
        totp: &str,
        enrollment_id: &str,
    ) -> Result<(), CreateFailure> {
        if !crate::password_change::valid_new_password(password, confirmation) {
            return Err(CreateFailure::Invalid);
        }
        let config = self.initial_config(account)?;
        let (operation, old_digest) = self.initial_pending(account)?;
        self.initial_setup_absent(account)?;
        let now = self.clock.unix_timestamp();
        let store = self.initial_store();
        let candidate = store
            .pending(account, grant, now, deadline())
            .map_err(|_| CreateFailure::Denied)?;
        let proof = store
            .confirm(
                account,
                grant,
                enrollment_id,
                candidate.revision,
                totp,
                now,
                deadline(),
            )
            .map_err(|_| CreateFailure::Denied)?;
        if proof.operation_id() != operation {
            return Err(CreateFailure::Unconfirmed);
        }
        // Any failure from this point leaves the invitation consumed and SQL
        // disabled unless activation itself is uncertain. Never auto-retry it.
        let hash = self.initial_password_hash(password).map_err(|_| {
            activation_failed(&store, account, &operation, FailureStage::PasswordHash)
        })?;
        let factor_digest = crate::initial_factor_service::install(
            &config.factor_socket,
            account,
            proof.secret_base32(),
            proof.accepted_counter(),
            deadline(),
        )
        .map_err(|_| activation_failed(&store, account, &operation, FailureStage::FactorInstall))?;
        let writer = self.writer.as_ref().ok_or(CreateFailure::Unconfirmed)?;
        let query = activation_sql(writer, account, &operation, &old_digest, &hash);
        if self.writer_sql(&query, true).map_err(|_| {
            activation_failed(&store, account, &operation, FailureStage::SqlActivation)
        })? != "activated\n"
        {
            return Err(activation_failed(
                &store,
                account,
                &operation,
                FailureStage::SqlActivation,
            ));
        }
        let readback=format!("SELECT COUNT(*) FROM mailbox m JOIN osmap_admin_operations o ON BINARY o.username=BINARY m.username WHERE BINARY m.username=BINARY {} AND m.active=1 AND m.smtp_active=1 AND BINARY m.password=BINARY {} AND o.request_id={} AND BINARY o.credential_digest=BINARY SHA2(m.password,256);\n",value(account),value(&hash),value(&operation));
        if self.writer_sql(&readback, true).map_err(|_| {
            activation_failed(&store, account, &operation, FailureStage::SqlReadback)
        })? != "1\n"
        {
            return Err(activation_failed(
                &store,
                account,
                &operation,
                FailureStage::SqlReadback,
            ));
        }
        store
            .finish(account, &operation, &factor_digest, deadline())
            .map_err(|_| {
                activation_failed(&store, account, &operation, FailureStage::CompletionReceipt)
            })
    }
}

fn activation_failed(
    store: &Store,
    account: &str,
    operation: &str,
    stage: FailureStage,
) -> CreateFailure {
    let retained = store
        .record_failure(account, operation, stage, deadline())
        .is_ok();
    eprintln!("INITIAL_SETUP_UNCONFIRMED stage={stage:?} native_cause=not_observed observation=dependency_response_not_confirmed diagnostic_retained={retained} resources=retained automatic_retry=false");
    CreateFailure::Unconfirmed
}

fn activation_sql(
    writer: &crate::admin_config::WriterConfig,
    account: &str,
    operation: &str,
    old_digest: &str,
    hash: &str,
) -> String {
    let domain = account.split_once('@').map(|(_, d)| d).unwrap_or("");
    let actors = writer
        .administrators
        .iter()
        .map(|a| value(a))
        .collect::<Vec<_>>()
        .join(",");
    format!(concat!(
        "SET SESSION innodb_lock_wait_timeout=3; START TRANSACTION;\n",
        "SET @h=NULL,@e=NULL,@mode=NULL; SELECT holder,epoch,mode INTO @h,@e,@mode FROM osmap_admin_writer WHERE id=1 FOR UPDATE;\n",
        "SET @domain=NULL; SELECT domain INTO @domain FROM domain WHERE BINARY domain=BINARY {domain} AND active=1 AND backupmx=0 FOR UPDATE;\n",
        "SET @actor=NULL; SELECT actor INTO @actor FROM osmap_admin_operations WHERE request_id={operation} AND BINARY username=BINARY {account} AND actor IN ({actors}) FOR UPDATE;\n",
        "SET @admin=NULL,@system=NULL; SELECT username,superadmin INTO @admin,@system FROM admin WHERE BINARY username=BINARY @actor AND active=1 FOR UPDATE;\n",
        "SET @all=NULL,@grant=NULL; SELECT domain INTO @all FROM domain_admins WHERE BINARY username=BINARY @actor AND domain='ALL' AND active=1 FOR UPDATE; SELECT domain INTO @grant FROM domain_admins WHERE BINARY username=BINARY @actor AND BINARY domain=BINARY {domain} AND active=1 FOR UPDATE;\n",
        "SET @alias=NULL; SELECT address INTO @alias FROM alias WHERE BINARY address=BINARY {account} AND BINARY goto=BINARY {account} AND BINARY domain=BINARY {domain} AND active=1 FOR UPDATE;\n",
        "UPDATE mailbox m JOIN osmap_admin_operations o ON BINARY o.username=BINARY m.username SET m.password={hash},m.active=1,m.smtp_active=1,m.modified=UTC_TIMESTAMP() WHERE BINARY m.username=BINARY {account} AND BINARY m.domain=BINARY {domain} AND o.request_id={operation} AND BINARY o.credential_digest=BINARY {old_digest} AND BINARY SHA2(m.password,256)=BINARY {old_digest} AND m.active=0 AND m.smtp_active=0 AND @domain IS NOT NULL AND @admin IS NOT NULL AND @alias IS NOT NULL AND ((@system=1 AND @all IS NOT NULL) OR (@system=0 AND @all IS NULL AND @grant IS NOT NULL)) AND @mode='lab_writer' AND BINARY @h=BINARY {holder} AND @e={epoch}; SET @updated=ROW_COUNT();\n",
        "UPDATE osmap_admin_operations SET credential_digest=SHA2({hash},256) WHERE request_id={operation} AND @updated=1; SET @journal=ROW_COUNT(); UPDATE osmap_admin_writer SET revision=revision+1 WHERE id=1 AND @updated=1 AND @journal=1; SET @writer=ROW_COUNT();\n",
        "SET @finish=IF(@updated=1 AND @journal=1 AND @writer=1,'COMMIT','ROLLBACK'); PREPARE osmap_finish FROM @finish; EXECUTE osmap_finish; SELECT IF(@finish='COMMIT','activated','refused');\n"
    ),domain=value(domain),operation=value(operation),account=value(account),actors=actors,hash=value(hash),old_digest=value(old_digest),holder=value(&writer.holder),epoch=writer.epoch)
}
