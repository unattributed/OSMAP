//! Closed parent plan for the fixed Rust password service. No caller paths,
//! recursive root/etc visibility, or synthetic confinement-success flag.
use crate::account_password_custody::{Custody, Unavailable};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::sync::Arc;
use std::time::Instant;

// Current parent policy remains strict. Only a future SQL exec selects errno
// disposition; other child roles retain strict current and exec policies.
pub(crate) const STOCK_PARENT_PROMISES: &str =
    "stdio rpath wpath cpath fattr flock unix proc exec prot_exec id getpw ps tty";
pub(crate) const STOCK_PARENT_EXEC_PROMISES: &str =
    "stdio rpath wpath cpath fattr flock unix proc exec prot_exec id getpw ps tty error";

pub(crate) struct ParentPlan {
    rules: Vec<(CString, CString)>,
    promises: CString,
    exec_promises: CString,
    custody: Arc<Custody>,
    seal: Option<crate::openbsd::PasswordParentSeal>,
    legacy_metadata: bool,
}
impl ParentPlan {
    #[allow(dead_code)] // Historical private-ingress parent; stock uses prepare_stock.
    pub(crate) fn prepare(deadline: Instant) -> Result<Self, Unavailable> {
        if !crate::openbsd::password_native_authority() || Instant::now() >= deadline {
            return Err(Unavailable);
        }
        crate::account_password_native::verify_metadata_graph(deadline).map_err(|_| Unavailable)?;
        let mut rules = BTreeMap::<String, String>::new();
        let mut add = |path: &str, permissions: &str| {
            let actual = rules.entry(path.to_owned()).or_default();
            for p in permissions.chars() {
                if !actual.contains(p) {
                    actual.push(p);
                }
            }
        };
        for (path, permissions) in
            crate::account_password_native::parent_rules(deadline).map_err(|_| Unavailable)?
        {
            add(&path, permissions);
        }
        for path in [
            "/etc/osmap/account-admission.json",
            "/etc/osmap/account-admission.key",
            "/etc/osmap/account-runtime/config.json",
            "/etc/osmap/account-runtime/mutation.key",
            "/etc/osmap/account-runtime/session-proof.key",
            "/etc/osmap/account-runtime/imap-publication.json",
            "/etc/osmap/account-runtime/imap-policy.key",
            "/etc/osmap/account-submission/dovecot.conf",
            "/etc/osmap/account-submission/registration.json",
            "/etc/pf.conf",
            "/etc/postfix/main.cf",
            "/etc/postfix/master.cf",
        ] {
            add(path, "r");
        }
        for path in [
            "/var/db/osmap-account/epoch",
            "/var/run/osmap-account-admission",
            "/var/run/osmap-account-mutation",
            "/var/run/osmap-account",
        ] {
            add(path, "rwc");
        }
        // Only these two fixed leaves may be atomically replaced; no
        // directory-wide write/read or initial admission creation.
        add(crate::account_password_topology::REGISTRATION, "rwc");
        add(crate::account_password_topology::REGISTRATION_NEXT, "rwc");
        // Fixed root directory's own metadata is rechecked by OperatorFiles.
        // Empty permissions reveal that vnode without recursive read access.
        add("/etc/osmap/account-runtime", "");
        for path in [
            "/bin/ps",
            "/usr/bin/fstat",
            "/sbin/pfctl",
            "/usr/local/sbin/postconf",
            "/usr/local/bin/doveconf",
            "/usr/local/sbin/dovecot",
            "/usr/local/libexec/dovecot/imap",
            "/usr/local/libexec/dovecot/submission-login",
            "/usr/local/libexec/dovecot/ipc",
            "/usr/local/libexec/osmap/account-passwd",
        ] {
            add(path, "rx");
        }
        // Exact fixed private source leaves and accepting-service executables.
        // No caller-selected path or directory write permission.
        for path in crate::account_password_peer::PRIMARY_CONFIGURATION_PATHS {
            add(path, "r");
        }
        add("/usr/local/libexec/dovecot/auth", "r");
        // Fixed include wildcard enumeration only; no directory writes.
        add("/etc/dovecot/conf.d", "r");
        add("/usr/local/libexec/dovecot/anvil", "r");
        // PF's fixed query utility needs only the kernel PF control device.
        add("/dev/pf", "rw");
        let paths = rules.keys().map(String::as_str).collect::<Vec<_>>();
        let custody = Custody::capture(&paths, deadline)?;
        let rules = rules
            .into_iter()
            .map(|(path, access)| {
                Ok((
                    CString::new(path).map_err(|_| Unavailable)?,
                    CString::new(access).map_err(|_| Unavailable)?,
                ))
            })
            .collect::<Result<Vec<_>, Unavailable>>()?;
        Ok(Self {
            rules,
            // setpw/id needed by fixed child role drops; recvfd only for exact
            // IMAP descriptor registration. Children install narrower plans.
            promises: CString::new("stdio rpath wpath cpath fattr flock unix inet recvfd proc exec prot_exec id getpw ps pf tty").map_err(|_| Unavailable)?,
            exec_promises: CString::new("stdio rpath wpath cpath fattr flock unix inet recvfd proc exec prot_exec id getpw ps pf tty error").map_err(|_| Unavailable)?,
            custody, seal: None, legacy_metadata: true,
        })
    }
    #[allow(dead_code)] // Preserve the existing caller interface without an emitted trace.
    pub(crate) fn prepare_stock(deadline: Instant) -> Result<Self, Unavailable> {
        let mut trace = crate::account_password_fstat::StartupTrace::new(
            crate::account_password_fstat::StartupOperation::ParentPrepare,
        );
        Self::prepare_stock_with_trace(deadline, &mut trace)
    }
    pub(crate) fn prepare_stock_with_trace(
        deadline: Instant,
        trace: &mut crate::account_password_fstat::StartupTrace,
    ) -> Result<Self, Unavailable> {
        if !crate::openbsd::password_native_authority() {
            trace.category(crate::account_password_fstat::StartupCategory::Invalid);
            return Err(Unavailable);
        }
        if Instant::now() >= deadline {
            trace.metadata("metadata_parent_graph_deadline");
            trace.metadata_error(crate::account_admission::Error::Unavailable);
            return Err(Unavailable);
        }
        let mut rules = BTreeMap::<String, String>::new();
        let mut add = |path: &str, access: &str| {
            let actual = rules.entry(path.to_owned()).or_default();
            for p in access.chars() {
                if !actual.contains(p) {
                    actual.push(p);
                }
            }
        };
        for (path, access) in
            crate::account_password_native::stock_parent_rules_with_trace(deadline, trace)
                .map_err(|_| Unavailable)?
        {
            add(&path, access);
        }
        for path in [
            "/etc/osmap/account-admission.json",
            "/etc/osmap/account-admission.key",
            "/etc/osmap/account-runtime/config.json",
            "/etc/osmap/account-runtime/mutation.key",
            "/etc/osmap/account-runtime/session-proof.key",
            "/var/dovecot/master.pid",
            "/etc/dovecot/dovecot-sql.conf.ext",
        ] {
            add(path, "r");
        }
        for path in [
            "/var/db/osmap-account/epoch",
            "/var/run/osmap-account-admission",
            "/var/run/osmap-account-mutation",
        ] {
            add(path, "rwc");
        }
        add("/etc/osmap/account-runtime", "");
        add("/usr/local/libexec/osmap/account-passwd", "r");
        for path in
            crate::account_password_peer::stock_configuration_paths(deadline).map_err(|_| {
                trace.metadata("metadata_parent_configuration_unknown");
                trace.metadata_error(crate::account_admission::Error::Unavailable);
                Unavailable
            })?
        {
            add(path, "r");
        }
        add("/usr/local/libexec/dovecot/auth", "r");
        add("/usr/local/bin/doveconf", "r");
        add("/usr/local/sbin/dovecot", "r");
        // Startup retains this fixed executable pin even when no IMAP control
        // path is selected; read custody only, no IMAP spawn authority.
        add("/usr/local/libexec/dovecot/imap", "r");
        add("/etc/dovecot/conf.d", "r");
        let paths = rules.keys().map(String::as_str).collect::<Vec<_>>();
        let custody = Custody::capture(&paths, deadline).inspect_err(|_| {
            trace.metadata("metadata_parent_custody_unknown");
            trace.metadata_error(crate::account_admission::Error::Unavailable);
        })?;
        let rules = rules
            .into_iter()
            .map(|(path, access)| {
                Ok((
                    CString::new(path).map_err(|_| Unavailable)?,
                    CString::new(access).map_err(|_| Unavailable)?,
                ))
            })
            .collect::<Result<_, Unavailable>>()?;
        Ok(Self {
            rules,
            promises: CString::new(STOCK_PARENT_PROMISES).map_err(|_| Unavailable)?,
            exec_promises: CString::new(STOCK_PARENT_EXEC_PROMISES).map_err(|_| Unavailable)?,
            custody,
            seal: None,
            legacy_metadata: false,
        })
    }
    pub(crate) fn rules(&self) -> &[(CString, CString)] {
        &self.rules
    }
    pub(crate) fn promises(&self) -> &CStr {
        &self.promises
    }
    pub(crate) fn exec_promises(&self) -> &CStr {
        &self.exec_promises
    }
    pub(crate) fn recheck(&self, deadline: Instant) -> Result<(), Unavailable> {
        if self
            .seal
            .as_ref()
            .is_some_and(|seal| !seal.is_current_process())
        {
            return Err(Unavailable);
        }
        self.custody.recheck(deadline)?;
        if self.legacy_metadata {
            crate::account_password_native::verify_metadata_graph(deadline)
                .map_err(|_| Unavailable)?;
        }
        Ok(())
    }
    pub(crate) fn activate(
        &mut self,
        seal: crate::openbsd::PasswordParentSeal,
    ) -> Result<(), Unavailable> {
        if self.seal.is_some() {
            return Err(Unavailable);
        }
        self.custody.activate(&seal)?;
        self.seal = Some(seal);
        Ok(())
    }
}
