//! Account-bound mail storage reporting. Configured quota is advisory here;
//! presentation does not establish enforcement or inspect retained Documents.
use crate::documents::MailStorageReport;

#[derive(Debug)]
pub(crate) struct StorageView {
    account: String,
    report: Option<MailStorageReport>,
}
impl StorageView {
    pub(crate) fn from_report(account: &str, report: Option<MailStorageReport>) -> Self {
        let valid_account = crate::identity::CanonicalUsername::parse(account).is_ok();
        Self {
            account: account.into(),
            report: report.filter(|report| valid_account && report.account == account),
        }
    }
}
fn owned<'a>(account: &str, view: Option<&'a StorageView>) -> Option<&'a StorageView> {
    view.filter(|view| view.account == account)
}
/// Reuse this page's account report; the rail never fetches storage itself.
pub(crate) fn render_rail(account: &str, view: Option<&StorageView>) -> String {
    let content = match owned(account, view).and_then(|view| view.report.as_ref()) {
        Some(report) => {
            let limit = match report.configured_limit_bytes {
                None => "Not reported".into(),
                Some(0) => "Unlimited".into(),
                Some(bytes) => compact_byte_size(bytes),
            };
            format!(
                "<p>Messages: {}</p><p>Configured quota: {limit}</p>{}",
                compact_byte_size(report.message_bytes),
                if over_limit(report) {
                    "<p><strong>Over configured quota</strong></p>"
                } else {
                    ""
                }
            )
        }
        None if view.is_some() => "<p>Unavailable</p>".into(),
        None => String::new(),
    };
    format!("<section class=\"rail-storage\" aria-label=\"Storage\"><strong>Storage</strong>{content}<p><a href=\"/settings?section=general\">View storage</a></p></section>")
}
pub(crate) fn render_dashboard(account: &str, view: Option<&StorageView>) -> String {
    format!("<div>{}<p>Mail retention unavailable.</p><a href=\"/settings?section=general\">View storage details</a></div>", mailbox_storage(owned(account, view)))
}
pub(crate) fn render_settings(account: &str, view: Option<&StorageView>) -> String {
    format!(
        "<div>{}</div><div><h3>Retention</h3><p>Mail retention unavailable.</p></div>",
        mailbox_storage(owned(account, view))
    )
}
fn over_limit(report: &MailStorageReport) -> bool {
    report
        .configured_limit_bytes
        .is_some_and(|limit| limit > 0 && report.message_bytes > limit)
}
fn mailbox_storage(view: Option<&StorageView>) -> String {
    let Some(report) = view.and_then(|view| view.report.as_ref()) else {
        return "<h3>Mailbox storage</h3><p>Unavailable</p><p>Current storage values could not be read from the mail server.</p>".into();
    };
    let limit = match report.configured_limit_bytes {
        None => "Not reported by the mail server".into(),
        Some(0) => "Unlimited".into(),
        Some(bytes) => byte_size(bytes),
    };
    format!("<h3>Mailbox messages</h3><p>{}</p><strong>Configured mailbox quota</strong><p>{limit}</p>{}<p>Message-size total reported by your mail server; disk overhead is excluded. The configured quota is reported here. Enforcement has not been verified.</p>", byte_size(report.message_bytes), if over_limit(report) { "<p><strong>Message size exceeds the configured limit.</strong></p>" } else { "" })
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
#[cfg(test)]
mod tests {
    use super::*;
    fn report(account: &str, bytes: u64, limit: Option<u64>) -> MailStorageReport {
        MailStorageReport {
            account: account.into(),
            message_bytes: bytes,
            configured_limit_bytes: limit,
        }
    }
    #[test]
    fn two_accounts_have_independent_mail_reports_without_document_or_quota_reads() {
        for (account, bytes, limit) in [("alice", 172_605_611, 102_400_000), ("bob", 4096, 8192)] {
            let view = StorageView::from_report(account, Some(report(account, bytes, Some(limit))));
            for html in [
                render_dashboard(account, Some(&view)),
                render_settings(account, Some(&view)),
            ] {
                assert!(html.contains(&format!("{bytes} bytes")));
                assert!(html.contains(&format!("{limit} bytes")));
                assert!(html.contains("Enforcement has not been verified"));
                assert!(!html.contains("Documents") && !html.contains("/documents"));
                assert!(
                    !html.contains("Enforced account quota")
                        && !html.contains("allocated filesystem")
                );
            }
            let rail = render_rail(account, Some(&view));
            assert!(
                rail.contains(&compact_byte_size(bytes))
                    && rail.contains(&compact_byte_size(limit))
            );
            assert_eq!(rail.contains("Over configured quota"), bytes > limit);
        }
    }
    #[test]
    fn empty_unlimited_unreported_and_unavailable_are_distinct() {
        for (limit, label) in [
            (Some(0), "Unlimited"),
            (None, "Not reported by the mail server"),
        ] {
            let view = StorageView::from_report("alice", Some(report("alice", 0, limit)));
            let html = render_settings("alice", Some(&view));
            assert!(html.contains("<p>0 bytes</p>") && html.contains(label));
            assert!(!html.contains("<p>Unavailable</p>") && !html.contains("exceeds"));
        }
        let failed = StorageView::from_report("alice", None);
        assert!(render_settings("alice", Some(&failed)).contains("<p>Unavailable</p>"));
        assert!(render_rail("alice", Some(&failed)).contains("Unavailable"));
        assert!(!render_rail("alice", None).contains("Unavailable"));
    }
    #[test]
    fn foreign_reports_foreign_views_and_invalid_accounts_never_expose_measurements() {
        let foreign = StorageView::from_report("bob", Some(report("bob", 987654, Some(1234567))));
        let mismatched =
            StorageView::from_report("alice", Some(report("bob", 987654, Some(1234567))));
        let invalid = StorageView::from_report(
            "invalid account",
            Some(report("invalid account", 987654, Some(1234567))),
        );
        for (account, view) in [
            ("alice", &foreign),
            ("alice", &mismatched),
            ("invalid account", &invalid),
        ] {
            for html in [
                render_dashboard(account, Some(view)),
                render_settings(account, Some(view)),
                render_rail(account, Some(view)),
            ] {
                assert!(html.contains("Unavailable"));
                assert!(!html.contains("987654") && !html.contains("1234567"));
                assert!(!html.contains("bob") && !html.contains("Documents"));
            }
        }
    }
}
