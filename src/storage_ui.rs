//! Read-only account storage presentation. Document payload is not added to
//! shared quota: Dovecot already counts its stored document messages there.
use crate::documents::{Index, MailStorageReport, QuotaStatus, StorageSummary};

#[derive(Debug)]
pub(crate) struct StorageView {
    account: String,
    quota: Option<QuotaStatus>,
    documents: Option<StorageSummary>,
    report: Option<MailStorageReport>,
}

impl StorageView {
    /// Quota must come from the existing enforcement-qualified account read.
    /// An advisory limit or message-size estimate is not a substitute.
    pub(crate) fn from_reads(
        account: &str,
        quota: Option<QuotaStatus>,
        index: Option<&Index>,
    ) -> Self {
        let valid_account = crate::identity::CanonicalUsername::parse(account).is_ok();
        Self {
            account: account.to_owned(),
            quota: quota.filter(|quota| valid_account && quota.limit_bytes > 0),
            documents: valid_account
                .then(|| index.and_then(|index| index.storage_summary(account).ok()))
                .flatten(),
            report: None,
        }
    }

    /// Reporting is deliberately separate from the authority used for writes.
    pub(crate) fn with_report(mut self, report: Option<MailStorageReport>) -> Self {
        self.report = report.filter(|report| {
            report.account == self.account
                && crate::identity::CanonicalUsername::parse(&report.account).is_ok()
        });
        self
    }
}

fn owned<'a>(account: &str, view: Option<&'a StorageView>) -> Option<&'a StorageView> {
    view.filter(|view| view.account == account)
}

/// Reuse this page's already loaded account snapshot; never fetch for the rail.
pub(crate) fn render_rail(account: &str, view: Option<&StorageView>) -> String {
    let content = match owned(account, view) {
        Some(StorageView {
            quota: Some(quota), ..
        }) => {
            let state = if quota.used_bytes > quota.limit_bytes {
                "<p><strong>Over quota</strong></p>"
            } else if quota.used_bytes == quota.limit_bytes {
                "<p>At quota</p>"
            } else {
                ""
            };
            format!(
                "<p>{} of {}</p>{state}",
                compact_byte_size(quota.used_bytes),
                compact_byte_size(quota.limit_bytes)
            )
        }
        Some(StorageView {
            report: Some(report),
            ..
        }) => {
            let limit = match report.configured_limit_bytes {
                None => "Not reported".into(),
                Some(0) => "Unlimited".into(),
                Some(bytes) => compact_byte_size(bytes),
            };
            let exceeded = if report
                .configured_limit_bytes
                .is_some_and(|limit| limit > 0 && report.message_bytes > limit)
            {
                "<p><strong>Over configured quota</strong></p>"
            } else {
                ""
            };
            format!(
                "<p>Messages: {}</p><p>Configured quota: {limit}</p>{exceeded}",
                compact_byte_size(report.message_bytes)
            )
        }
        _ if view.is_some() => "<p>Unavailable</p>".into(),
        _ => String::new(),
    };
    format!("<section class=\"rail-storage\" aria-label=\"Storage\"><strong>Storage</strong>{content}<p><a href=\"/settings?section=general\">View storage</a></p></section>")
}

fn shared_usage(view: Option<&StorageView>) -> String {
    match view.and_then(|view| view.quota) {
        Some(quota) => format!(
            "{} bytes used of {} bytes{}",
            quota.used_bytes,
            quota.limit_bytes,
            if quota.used_bytes > quota.limit_bytes {
                " · Over quota"
            } else if quota.used_bytes == quota.limit_bytes {
                " · At quota"
            } else {
                ""
            }
        ),
        None => "Unavailable".into(),
    }
}

fn document_usage(view: Option<&StorageView>) -> String {
    match view.and_then(|view| view.documents.as_ref()) {
        Some(documents) => format!(
            "{} bytes of file contents, including {} bytes in Bin",
            documents.used_bytes, documents.bin_bytes
        ),
        None => "Unavailable".into(),
    }
}

fn retention(view: Option<&StorageView>) -> String {
    if view.is_some_and(|view| view.documents.is_some()) {
        format!(
            "Documents Bin: restore within {} days. Expired items need confirmed cleanup. Mail retention unavailable.",
            crate::documents::BIN_RETENTION_SECONDS / (24 * 60 * 60)
        )
    } else {
        "Documents retention unavailable. Mail retention unavailable.".into()
    }
}

pub(crate) fn render_dashboard(account: &str, view: Option<&StorageView>) -> String {
    let view = owned(account, view);
    format!(concat!(
        "<div>{}",
        "<strong>Document file contents</strong><p>{}</p>",
        "<p>Document file contents are reported separately and are not added again to mailbox storage.</p>",
        "<p>{}</p><a href=\"/settings?section=general\">View storage details</a></div>"
    ), mailbox_storage(view), document_usage(view), retention(view))
}

pub(crate) fn render_settings(account: &str, view: Option<&StorageView>) -> String {
    let view = owned(account, view);
    format!(concat!(
        "<div>{}</div>",
        "<div><h3>Document file contents</h3><p>{}</p><span>Indexed file contents only, already included in shared storage.</span><p><a href=\"/documents\">Manage Documents</a></p></div>",
        "<div><h3>Retention</h3><p>{}</p></div>"
    ), mailbox_storage(view), document_usage(view), retention(view))
}

fn byte_size(bytes: u64) -> String {
    let formatted = compact_byte_size(bytes);
    if bytes < 1024 {
        formatted
    } else {
        format!("{formatted} ({bytes} bytes)")
    }
}

fn compact_byte_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} bytes")
    } else {
        let (unit, divisor) = if bytes < 1_048_576 {
            ("KiB", 1024.0)
        } else if bytes < 1_073_741_824 {
            ("MiB", 1_048_576.0)
        } else {
            ("GiB", 1_073_741_824.0)
        };
        format!("{:.1} {unit}", bytes as f64 / divisor)
    }
}

fn mailbox_storage(view: Option<&StorageView>) -> String {
    if view.is_some_and(|view| view.quota.is_some()) {
        return format!(
            "<h3>Shared mailbox and Documents</h3><p>{}</p><p>Enforced account quota measured as allocated filesystem storage, including message and directory overhead.</p>",
            shared_usage(view)
        );
    }
    let Some(report) = view.and_then(|view| view.report.as_ref()) else {
        return "<h3>Mailbox storage</h3><p>Unavailable</p><p>Current storage values could not be read from the mail server.</p>".into();
    };
    let limit = match report.configured_limit_bytes {
        None => "Not reported by the mail server".into(),
        Some(0) => "Unlimited".into(),
        Some(bytes) => byte_size(bytes),
    };
    let exceeded = if report
        .configured_limit_bytes
        .is_some_and(|limit| limit > 0 && report.message_bytes > limit)
    {
        "<p><strong>Message size exceeds the configured limit.</strong></p>"
    } else {
        ""
    };
    format!(
        "<h3>Mailbox messages</h3><p>{}</p><strong>Configured mailbox quota</strong><p>{limit}</p>{exceeded}<p>Message-size total reported by your mail server; disk overhead is excluded. The configured quota is reported here. Enforcement has not been verified.</p>",
        byte_size(report.message_bytes)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_rail_reuses_owned_reporting_and_prefers_qualified_quota() {
        let report = MailStorageReport {
            account: "alice".into(),
            message_bytes: 172_605_611,
            configured_limit_bytes: Some(102_400_000),
        };
        let reported =
            StorageView::from_reads("alice", None, None).with_report(Some(report.clone()));
        let rail = render_rail("alice", Some(&reported));
        assert!(rail.contains("Messages: 164.6 MiB"));
        assert!(rail.contains("Configured quota: 97.7 MiB"));
        assert!(rail.contains("Over configured quota"));
        assert!(!rail.contains("Enforced") && !rail.contains("172605611 bytes"));
        let qualified = StorageView::from_reads(
            "alice",
            Some(QuotaStatus {
                used_bytes: 1024,
                limit_bytes: 2048,
            }),
            None,
        )
        .with_report(Some(report));
        let rail = render_rail("alice", Some(&qualified));
        assert!(rail.contains("1.0 KiB of 2.0 KiB"));
        assert!(!rail.contains("164.6") && !rail.contains("Messages:"));
    }

    #[test]
    fn storage_rail_separates_unloaded_failed_and_foreign_snapshots() {
        let unloaded = render_rail("alice", None);
        assert!(unloaded.contains(">View storage</a>"));
        assert!(!unloaded.contains("Unavailable") && !unloaded.contains("unavailable"));
        let failed = StorageView::from_reads("alice", None, None);
        let foreign =
            StorageView::from_reads("bob", None, None).with_report(Some(MailStorageReport {
                account: "bob".into(),
                message_bytes: 987_654,
                configured_limit_bytes: Some(1_234_567),
            }));
        for view in [&failed, &foreign] {
            let rail = render_rail("alice", Some(view));
            assert!(rail.contains("Unavailable") && rail.contains(">View storage</a>"));
            assert!(!rail.contains("987") && !rail.contains("bob"));
        }
    }

    #[test]
    fn storage_rail_distinguishes_unlimited_and_unreported_configured_limits() {
        for (limit, expected) in [(Some(0), "Unlimited"), (None, "Not reported")] {
            let view =
                StorageView::from_reads("alice", None, None).with_report(Some(MailStorageReport {
                    account: "alice".into(),
                    message_bytes: 0,
                    configured_limit_bytes: limit,
                }));
            let rail = render_rail("alice", Some(&view));
            assert!(rail.contains("Messages: 0 bytes") && rail.contains(expected));
            assert!(!rail.contains("Unavailable") && !rail.contains("Over configured quota"));
        }
    }

    fn index(account: &str, pending: bool) -> Index {
        serde_json::from_value(serde_json::json!({
            "version":1,"account":account,"revision":1,"folders":[],
            "documents":[{
                "id":"a".repeat(32),"name":"<private-name>",
                "media_type":"application/octet-stream","size":7,
                "sha256":"a".repeat(64),"created_at":1,"modified_at":2,
                "folder":"","state":if pending {"restoring"}else{"in_bin"},
                "location":{"mailbox":"OSMAP.DocumentsBin","uid":1,
                    "mailbox_guid":"b".repeat(32),"message_guid":"c".repeat(32)},
                "binned_at":2
            }]
        }))
        .unwrap()
    }

    #[test]
    fn measured_storage_keeps_shared_quota_and_document_payload_separate() {
        let index = index("alice", false);
        let view = StorageView::from_reads(
            "alice",
            Some(QuotaStatus {
                used_bytes: 1024,
                limit_bytes: 2048,
            }),
            Some(&index),
        );
        for html in [
            render_dashboard("alice", Some(&view)),
            render_settings("alice", Some(&view)),
        ] {
            assert!(html.contains("1024 bytes used of 2048 bytes"));
            assert!(html.contains("7 bytes of file contents, including 7 bytes in Bin"));
            assert!(html.contains("restore within 30 days"));
            assert!(html.contains("confirmed cleanup"));
            assert!(html.contains("Mail retention unavailable"));
            assert!(!html.contains("1031"));
            assert!(!html.contains("<private-name>"));
            assert!(!html.contains("<form"));
            assert!(!html.contains("automatically"));
        }
    }

    #[test]
    fn mail_reporting_displays_complete_measurement_without_claiming_enforcement() {
        let view =
            StorageView::from_reads("alice", None, None).with_report(Some(MailStorageReport {
                account: "alice".into(),
                message_bytes: 172_605_611,
                configured_limit_bytes: Some(102_400_000),
            }));
        for html in [
            render_dashboard("alice", Some(&view)),
            render_settings("alice", Some(&view)),
        ] {
            assert!(html.contains("164.6 MiB (172605611 bytes)"));
            assert!(html.contains("97.7 MiB (102400000 bytes)"));
            assert!(html.contains("Message size exceeds the configured limit."));
            assert!(html.contains("disk overhead is excluded"));
            assert!(html.contains("Enforcement has not been verified"));
            assert!(!html.contains("Enforced account quota"));
            assert!(!html.contains("allocated filesystem storage"));
        }
    }

    #[test]
    fn mail_reporting_distinguishes_missing_unlimited_and_foreign_values() {
        for (limit, expected) in [
            (None, "Not reported by the mail server"),
            (Some(0), "Unlimited"),
        ] {
            let view =
                StorageView::from_reads("alice", None, None).with_report(Some(MailStorageReport {
                    account: "alice".into(),
                    message_bytes: 0,
                    configured_limit_bytes: limit,
                }));
            let html = render_settings("alice", Some(&view));
            assert!(html.contains("<p>0 bytes</p>"));
            assert!(html.contains(expected));
            assert!(!html.contains("exceeds the configured limit"));
        }
        let foreign =
            StorageView::from_reads("alice", None, None).with_report(Some(MailStorageReport {
                account: "bob".into(),
                message_bytes: 987_654,
                configured_limit_bytes: Some(1_234_567),
            }));
        let html = render_settings("alice", Some(&foreign));
        assert!(html.contains("<p>Unavailable</p>"));
        assert!(!html.contains("987654"));
        assert!(!html.contains("1234567"));
    }

    #[test]
    fn storage_distinguishes_empty_partial_pending_and_foreign_reads() {
        let mut empty: Index = serde_json::from_value(serde_json::json!({
            "version":1,"account":"alice","revision":0,"folders":[],"documents":[]
        }))
        .unwrap();
        let empty_view = StorageView::from_reads("alice", None, Some(&empty));
        let html = render_settings("alice", Some(&empty_view));
        assert!(html.contains("0 bytes of file contents, including 0 bytes in Bin"));
        assert!(html.contains("<p>Unavailable</p>"));
        let pending = index("alice", true);
        let foreign = index("bob", false);
        empty.documents = foreign.documents.clone();
        empty.documents[0].size = u64::MAX;
        for index in [None, Some(&pending), Some(&foreign), Some(&empty)] {
            let view = StorageView::from_reads(
                "alice",
                Some(QuotaStatus {
                    used_bytes: 4096,
                    limit_bytes: 2048,
                }),
                index,
            );
            let html = render_settings("alice", Some(&view));
            assert!(html.contains("4096 bytes used of 2048 bytes · Over quota"));
            assert!(html.contains("Documents retention unavailable"));
            assert!(!html.contains("7 bytes of file contents"));
            assert!(!html.contains("restore within 30 days"));
            assert!(!html.contains("bob"));
        }
        let foreign_view = StorageView::from_reads(
            "bob",
            Some(QuotaStatus {
                used_bytes: 987654,
                limit_bytes: 1000000,
            }),
            Some(&foreign),
        );
        for html in [
            render_dashboard("alice", Some(&foreign_view)),
            render_settings("alice", Some(&foreign_view)),
        ] {
            assert!(!html.contains("987654"));
            assert!(!html.contains("7 bytes of file contents"));
            assert!(html.contains("Documents retention unavailable"));
        }
        let invalid = StorageView::from_reads(
            "invalid account",
            Some(QuotaStatus {
                used_bytes: 987654,
                limit_bytes: 1000000,
            }),
            None,
        );
        assert!(!render_settings("invalid account", Some(&invalid)).contains("987654"));
        let no_limit = StorageView::from_reads(
            "alice",
            Some(QuotaStatus {
                used_bytes: 987654,
                limit_bytes: 0,
            }),
            None,
        );
        assert!(!render_settings("alice", Some(&no_limit)).contains("987654"));
    }
}
