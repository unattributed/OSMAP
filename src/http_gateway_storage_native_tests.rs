//! Installed report/rendering and one generated Documents lifecycle.
//! No owner session is fabricated, loaded or persisted; this is not login/HTTP UAT.
use super::*;

#[test]
#[ignore = "operator-run existing sealed helper exact Documents lookup; read-only"]
fn native_installed_documents_readonly_lookup() -> Result<(), &'static str> {
    use crate::documents::Backend;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    if crate::openbsd::effective_uid() != 1001 {
        return Err("installed Web identity required");
    }
    let account =
        std::env::var("OSMAP_STORAGE_REPORT_ACCOUNT").map_err(|_| "explicit account required")?;
    let canonical = crate::identity::CanonicalUsername::parse(&account)
        .map_err(|_| "canonical account required")?;
    if canonical.as_str() != account {
        return Err("canonical account required");
    }
    let epoch_text =
        std::env::var("OSMAP_READINESS_EPOCH").map_err(|_| "current account epoch required")?;
    let epoch = epoch_text
        .parse::<u64>()
        .ok()
        .filter(|epoch| epoch.to_string() == epoch_text)
        .ok_or("canonical account epoch required")?;
    let config =
        AppConfig::from_process_env().map_err(|_| "installed configuration unavailable")?;
    let gateway = RuntimeBrowserGateway::from_config(&config);
    if !gateway.uses_account_runtime(&account) {
        return Err("installed account authority required");
    }
    gateway
        .account_runtime
        .ready()
        .ok_or("installed account authority unavailable")?
        .admission()
        .admit_before(&account, epoch, deadline)
        .map_err(|_| "installed signed account admission unavailable")?;
    let backend = crate::mailbox_helper::MailboxHelperDocumentsBackend::new(
        gateway
            .mailbox_helper_socket_path
            .as_ref()
            .ok_or("installed helper socket unavailable")?,
        gateway
            .mailbox_helper_grant_key_path
            .as_ref()
            .ok_or("installed helper grant unavailable")?,
        crate::mailbox_helper::MailboxHelperPolicy::default(),
    )
    .with_helper_uid(
        gateway
            .mailbox_helper_peer_uid
            .ok_or("installed helper identity unavailable")?,
    );
    let id = crate::draft::generate_draft_id().map_err(|_| "lookup selector unavailable")?;
    match backend.inspect(&account, &id) {
        Ok(locations) if locations.is_empty() && std::time::Instant::now() < deadline => {
            println!("INSTALLED_DOCUMENTS_READONLY_LOOKUP=PASS ACCOUNT_ADMISSION=PASS LIVE_SEALED_HELPER=USED RESERVED_MAILBOXES=2 WRITES=NOT_DISPATCHED OWNER_SESSION=NOT_USED OWNER_HTTP=NOT_RUN");
            Ok(())
        }
        Ok(_) => Err("read-only lookup returned an unexpected location or exceeded its deadline"),
        Err(error) => {
            eprintln!("INSTALLED_DOCUMENTS_READONLY_LOOKUP=REFUSED result={error:?} WRITES=NOT_DISPATCHED");
            Err("read-only lookup refused; retain helper fixed-stage diagnostic")
        }
    }
}

#[test]
#[ignore = "operator-run installed helper storage report as Web UID; no credentials or mutations"]
fn native_installed_mail_storage_report() -> Result<(), &'static str> {
    let began = std::time::Instant::now();
    if crate::openbsd::effective_uid() != 1001 {
        return Err("existing Web identity required");
    }
    let account =
        std::env::var("OSMAP_STORAGE_REPORT_ACCOUNT").map_err(|_| "explicit account required")?;
    let canonical = crate::identity::CanonicalUsername::parse(&account)
        .map_err(|_| "canonical account required")?;
    if canonical.as_str() != account {
        return Err("canonical account required");
    }
    let expected_bytes: u64 = std::env::var("OSMAP_STORAGE_REPORT_EXPECTED_BYTES")
        .map_err(|_| "fresh message-byte expectation required")?
        .parse()
        .map_err(|_| "numeric message-byte expectation required")?;
    if expected_bytes == 0 {
        return Err("nonempty native observation required; empty-account coverage is separate");
    }
    let expected_limit = std::env::var("OSMAP_STORAGE_REPORT_EXPECTED_LIMIT")
        .map_err(|_| "explicit configured-limit expectation required")?;
    let expected_limit = if expected_limit == "none" {
        None
    } else {
        Some(
            expected_limit
                .parse::<u64>()
                .map_err(|_| "numeric limit or none required")?,
        )
    };
    let config =
        AppConfig::from_process_env().map_err(|_| "installed configuration unavailable")?;
    let gateway = RuntimeBrowserGateway::from_config(&config);
    let epoch: u64 = std::env::var("OSMAP_READINESS_EPOCH")
        .map_err(|_| "current account epoch required")?
        .parse()
        .map_err(|_| "numeric account epoch required")?;
    if !gateway.uses_account_runtime(&account) {
        return Err("installed account authority required");
    }
    gateway
        .account_runtime
        .ready()
        .ok_or("installed account authority unavailable")?
        .admission()
        .admit_before(
            &account,
            epoch,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
        )
        .map_err(|_| "installed signed account admission unavailable")?;
    // This is the same Runtime factory/Store chain used by mail_storage_report.
    // A SessionRecord is unnecessary because the only selector is the account.
    let report = gateway
        .document_store()
        .map_err(|_| "installed helper configuration unavailable")?
        .storage_report(&account)
        .map_err(|_| "installed authenticated storage report unavailable")?;
    if report.account != account
        || report.message_bytes != expected_bytes
        || report.configured_limit_bytes != expected_limit
    {
        return Err("installed report differs from fresh native expectations");
    }
    let owned = crate::storage_ui::StorageView::from_reads(&account, None, None)
        .with_report(Some(report.clone()));
    let mut foreign_report = report;
    foreign_report.account = "foreign-storage-observer@example.invalid".into();
    let foreign = crate::storage_ui::StorageView::from_reads(&account, None, None)
        .with_report(Some(foreign_report));
    let keys = crate::key_management::State::unavailable(&account);
    let activity = crate::http::BrowserSessionListDecision::Denied {
        public_reason: "session observation not performed".into(),
    };
    let model = crate::http_ui::SettingsPageModel {
        canonical_username: &account,
        csrf_token: "diagnostic-render-only",
        success_message: None,
        error_message: None,
        html_display_preference: crate::rendering::HtmlDisplayPreference::default(),
        archive_mailbox_name: None,
    };
    for (view, measured) in [(&owned, true), (&foreign, false)] {
        let dashboard = crate::http_ui::render_mailboxes_page_with_storage(
            &account,
            "diagnostic-render-only",
            &[],
            (None, None),
            None,
            None,
            &activity,
            false,
            crate::http_ui::WelcomeAccountState {
                openpgp: &keys,
                defaults: None,
                storage: Some(view),
                notices: None,
            },
        );
        let general = crate::http_ui::render_general_page_with_mark_read(
            &model,
            &crate::appearance::AppearanceSettings::default(),
            None,
            None,
            None,
            None,
            crate::http_ui::GeneralPageState {
                storage: Some(view),
                ..Default::default()
            },
        );
        for html in [dashboard.as_str(), general.as_str()] {
            let rail = html
                .split_once("<section class=\"rail-storage\"")
                .and_then(|(_, rest)| rest.split_once("</section>"))
                .map(|(rail, _)| rail)
                .ok_or("native storage navigation missing")?;
            if html.len() > 512 * 1024
                || html.contains(&format!("{expected_bytes} bytes")) != measured
                || html.contains("Enforcement has not been verified") != measured
                || html.contains("Enforced account quota measured")
                || html.contains("restore within 30 days")
            {
                return Err("native storage page projection refused");
            }
            if measured {
                if rail.contains("Usage unavailable") || !rail.contains("Messages:") {
                    return Err("native storage navigation contradicts measured report");
                }
                let label = match expected_limit {
                    None => "Not reported by the mail server".into(),
                    Some(0) => ">Unlimited<".into(),
                    Some(bytes) => format!("{bytes} bytes"),
                };
                if !html.contains(&label) {
                    return Err("native configured allowance projection refused");
                }
            }
        }
    }
    if began.elapsed() > std::time::Duration::from_secs(20) {
        return Err("native report deadline exceeded");
    }
    println!("INSTALLED_STORAGE_REPORT=PASS RUNTIME_HELPER=PASS ACCOUNT_ADMISSION=PASS OWNED_PAGE_RENDERERS=2 OWNED_RAILS=2 FOREIGN_PAGE_REFUSALS=2 OWNER_SESSION=NOT_USED OWNER_HTTP=NOT_RUN WRITES=NOT_DISPATCHED QUOTA_AUTHORITY=NOT_CLAIMED");
    Ok(())
}

#[test]
#[ignore = "operator-run installed Web UID Documents lifecycle; mutates only one generated test ID"]
fn native_installed_documents_lifecycle() -> Result<(), &'static str> {
    use crate::documents::{Error, Index, State};
    use sha2::{Digest, Sha256};

    fn checked<T>(
        stage: &'static str,
        id: &str,
        result: Result<T, Error>,
    ) -> Result<T, &'static str> {
        result.map_err(|error| {
            eprintln!("INSTALLED_DOCUMENTS_FAILURE stage={stage} id={id} result={error:?} automatic_retry=NONE state=RETAINED");
            "installed Documents stage failed; retain known state for inspection"
        })
    }
    fn preserves(index: &Index, original: &Index, generated: &str) -> bool {
        index.folders == original.folders
            && index
                .documents
                .iter()
                .filter(|document| document.id != generated)
                .cloned()
                .collect::<Vec<_>>()
                == original.documents
    }

    let began = std::time::Instant::now();
    let deadline = began + std::time::Duration::from_secs(90);
    if crate::openbsd::effective_uid() != 1001 {
        return Err("installed Web identity required");
    }
    let account = std::env::var("OSMAP_STORAGE_REPORT_ACCOUNT")
        .map_err(|_| "explicit Documents account required")?;
    let canonical = crate::identity::CanonicalUsername::parse(&account)
        .map_err(|_| "canonical Documents account required")?;
    if canonical.as_str() != account {
        return Err("canonical Documents account required");
    }
    let mutation_account = std::env::var("OSMAP_DOCUMENTS_NATIVE_MUTATION_ACCOUNT")
        .map_err(|_| "separate explicit Documents mutation account required")?;
    let mutation_canonical = crate::identity::CanonicalUsername::parse(&mutation_account)
        .map_err(|_| "canonical Documents mutation account required")?;
    if mutation_canonical.as_str() != mutation_account || mutation_account != account {
        return Err("explicit mutation account must exactly match the canonical report account");
    }
    let epoch_text =
        std::env::var("OSMAP_READINESS_EPOCH").map_err(|_| "current account epoch required")?;
    let epoch = epoch_text
        .parse::<u64>()
        .ok()
        .filter(|epoch| epoch.to_string() == epoch_text)
        .ok_or("canonical account epoch required")?;
    let config =
        AppConfig::from_process_env().map_err(|_| "installed configuration unavailable")?;
    let gateway = RuntimeBrowserGateway::from_config(&config);
    if !gateway.uses_account_runtime(&account) {
        return Err("installed account authority required");
    }
    let admit = || -> Result<(), &'static str> {
        if std::time::Instant::now() >= deadline {
            return Err("installed Documents deadline reached; no next mutation dispatched");
        }
        gateway
            .account_runtime
            .ready()
            .ok_or("installed account authority unavailable")?
            .admission()
            .admit_before(
                &account,
                epoch,
                deadline.min(std::time::Instant::now() + std::time::Duration::from_secs(10)),
            )
            .map(|_| ())
            .map_err(|_| {
                "installed signed account admission unavailable; no next mutation dispatched"
            })
    };
    admit()?;
    let store = gateway
        .document_store()
        .map_err(|_| "installed Documents helper configuration unavailable")?;
    if !checked("quota-ready", "NONE", store.quota_ready(&account))? {
        return Err("installed finite shared quota authority is unavailable; no upload dispatched");
    }
    let quota = checked("quota-status", "NONE", store.quota_status(&account))?
        .ok_or("installed finite quota observation required; no upload dispatched")?;
    if quota.limit_bytes != 209_715_200 || quota.used_bytes >= quota.limit_bytes {
        return Err("installed 200 MiB quota with free capacity required; no upload dispatched");
    }
    let original = checked("original-index", "NONE", store.load(&account))?;
    checked(
        "original-index-validation",
        "NONE",
        original.storage_summary(&account),
    )?;
    let nonce =
        crate::draft::generate_draft_id().map_err(|_| "native Documents test name unavailable")?;
    let name = format!("osmap-s08-native-{nonce}.bin");
    if original
        .documents
        .iter()
        .any(|document| document.name == name)
    {
        return Err("generated Documents name already exists; no upload dispatched");
    }
    let body: Vec<u8> = (0..4096).map(|value| ((value * 17) % 256) as u8).collect();
    let digest = format!("{:x}", Sha256::digest(&body));
    let now = || crate::totp::TimeProvider::unix_timestamp(&SystemTimeProvider);
    admit()?;
    let uploaded = match store.upload(
        &account,
        original.revision,
        &name,
        "application/octet-stream",
        &body,
        now(),
    ) {
        Ok(index) => index,
        Err(error) => {
            // Upload mints its ID inside the Store. An uncertain result permits
            // only this read-only lookup; never replay upload or edit metadata.
            let retained = store.load(&account);
            let ids: Vec<_> = retained
                .as_ref()
                .ok()
                .into_iter()
                .flat_map(|index| index.documents.iter())
                .filter(|document| {
                    document.name == name
                        && !original.documents.iter().any(|old| old.id == document.id)
                })
                .map(|document| document.id.as_str())
                .collect();
            let id = if ids.len() == 1 {
                ids[0]
            } else {
                "UNAVAILABLE"
            };
            eprintln!("INSTALLED_DOCUMENTS_FAILURE stage=upload id={id} result={error:?} automatic_retry=NONE state=RETAINED");
            return Err(
                "installed Documents upload did not confirm; inspect retained state without replay",
            );
        }
    };
    let added: Vec<_> = uploaded
        .documents
        .iter()
        .filter(|document| !original.documents.iter().any(|old| old.id == document.id))
        .collect();
    if added.len() != 1 || !preserves(&uploaded, &original, &added[0].id) {
        return Err("installed upload changed unexpected metadata; retain state");
    }
    let generated = added[0];
    let id = generated.id.clone();
    println!("INSTALLED_DOCUMENTS_GENERATED id={id} bytes=4096");
    if generated.name != name
        || generated.size != body.len() as u64
        || generated.sha256 != digest
        || generated.state != State::Available
        || !generated.folder.is_empty()
    {
        return Err("installed generated document metadata refused; retain known ID");
    }
    let reopened = gateway
        .document_store()
        .map_err(|_| "installed Documents reopen unavailable; retain known ID")?;
    if checked("reopened-download", &id, reopened.download(&account, &id))?
        != (name.clone(), body.clone())
    {
        return Err("installed reopened document byte mismatch; retain known ID");
    }
    admit()?;
    let binned = checked(
        "bin",
        &id,
        reopened.bin(&account, uploaded.revision, &id, now()),
    )?;
    if !preserves(&binned, &original, &id)
        || binned
            .documents
            .iter()
            .find(|document| document.id == id)
            .map(|document| document.state)
            != Some(State::InBin)
    {
        return Err("installed Bin metadata refused; retain known ID");
    }
    if reopened.download(&account, &id) != Err(Error::NotFound) {
        return Err("installed Bin document remained downloadable; retain known ID");
    }
    admit()?;
    let restored = checked(
        "restore",
        &id,
        reopened.restore(&account, binned.revision, &id, now()),
    )?;
    if !preserves(&restored, &original, &id)
        || checked("restored-download", &id, reopened.download(&account, &id))? != (name, body)
    {
        return Err("installed restored bytes or original metadata changed; retain known ID");
    }
    admit()?;
    let binned = checked(
        "cleanup-bin",
        &id,
        reopened.bin(&account, restored.revision, &id, now()),
    )?;
    if !preserves(&binned, &original, &id) {
        return Err("installed cleanup Bin changed original metadata; retain known ID");
    }
    admit()?;
    let deleted = checked(
        "cleanup-delete",
        &id,
        reopened.delete_confirmed(&account, binned.revision, &id, now()),
    )?;
    let final_store = gateway
        .document_store()
        .map_err(|_| "installed final Store unavailable")?;
    let final_index = checked("cleanup-readback", &id, final_store.load(&account))?;
    if final_index != deleted
        || final_index.documents != original.documents
        || final_index.folders != original.folders
        || final_index.revision <= original.revision
        || final_store.download(&account, &id) != Err(Error::NotFound)
    {
        return Err("installed generated-ID cleanup or original metadata preservation unconfirmed");
    }
    let final_quota = checked("final-quota", &id, final_store.quota_status(&account))?
        .ok_or("installed final quota observation unavailable")?;
    if final_quota.limit_bytes != 209_715_200 || final_quota.used_bytes > final_quota.limit_bytes {
        return Err("installed final finite quota differs from admitted authority");
    }
    if std::time::Instant::now() > deadline {
        return Err("installed Documents lifecycle deadline exceeded");
    }
    println!("INSTALLED_DOCUMENTS_LIFECYCLE=PASS RUNTIME_HELPER=PASS ACCOUNT_ADMISSION=PASS WEB_UID=1001 HARD_LIMIT_BYTES=209715200 EXACT_BINARY_DOWNLOAD=PASS BIN_REFUSAL=PASS RESTORE=PASS GENERATED_ID_CLEANUP=PASS ORIGINAL_RECORDS_AND_FOLDERS=PRESERVED OWNER_SESSION=NOT_USED OWNER_HTTP=NOT_RUN");
    Ok(())
}
