//! Installed read-only report + Runtime factory + page-renderer composition.
//! No owner session is fabricated, loaded or persisted; this is not login/HTTP UAT.
use super::*;

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
            if html.len() > 512 * 1024
                || html.contains(&format!("{expected_bytes} bytes")) != measured
                || html.contains("Enforcement has not been verified") != measured
                || html.contains("Enforced account quota measured")
                || html.contains("restore within 30 days")
            {
                return Err("native storage page projection refused");
            }
            if measured {
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
    println!("INSTALLED_STORAGE_REPORT=PASS RUNTIME_HELPER=PASS OWNED_PAGE_RENDERERS=2 FOREIGN_PAGE_REFUSALS=2 OWNER_SESSION=NOT_USED OWNER_HTTP=NOT_RUN WRITES=NOT_DISPATCHED QUOTA_AUTHORITY=NOT_CLAIMED");
    Ok(())
}
