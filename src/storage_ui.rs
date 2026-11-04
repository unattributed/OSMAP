//! Read-only account storage presentation. Document payload is not added to
//! shared quota: Dovecot already counts its stored document messages there.
use crate::documents::{Index, QuotaStatus, StorageSummary};

#[derive(Debug)]
pub(crate) struct StorageView {
    account: String,
    quota: Option<QuotaStatus>,
    documents: Option<StorageSummary>,
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
        }
    }
}

fn owned<'a>(account: &str, view: Option<&'a StorageView>) -> Option<&'a StorageView> {
    view.filter(|view| view.account == account)
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
        "<div><strong>Shared mailbox and Documents</strong><p>{}</p>",
        "<strong>Document file contents</strong><p>{}</p>",
        "<p>Documents share the mailbox quota; their file contents are not an additional total. Shared usage measures allocated filesystem storage, including message and directory overhead.</p>",
        "<p>{}</p><a href=\"/settings?section=general\">View storage details</a></div>"
    ), shared_usage(view), document_usage(view), retention(view))
}

pub(crate) fn render_settings(account: &str, view: Option<&StorageView>) -> String {
    let view = owned(account, view);
    format!(concat!(
        "<div><h3>Shared mailbox and Documents</h3><p>{}</p><span>Authoritative account quota measured as allocated filesystem storage, including stored document messages and directory overhead.</span></div>",
        "<div><h3>Document file contents</h3><p>{}</p><span>Indexed file contents only, already included in shared storage.</span><p><a href=\"/documents\">Manage Documents</a></p></div>",
        "<div><h3>Retention</h3><p>{}</p></div>"
    ), shared_usage(view), document_usage(view), retention(view))
}

#[cfg(test)]
mod tests {
    use super::*;

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
