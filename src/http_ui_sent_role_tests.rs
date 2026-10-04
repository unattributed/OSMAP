//! Rendering projection tests; ownership is independently qualified by routes.
use super::*;
use crate::message_metadata::{MessageMetadata, MessageProtection, MessageVersion};
const TARGET: &str = "INBOX.SentCopyA";
const GUID: &str = "1234567890abcdef1234567890abcdef";
const OTHER_GUID: &str = "abcdef1234567890abcdef1234567890";
fn saved(name: &str) -> crate::sent_location::Preference {
    crate::sent_location::Preference {
        revision: 1,
        mailbox_name: name.into(),
        mailbox_guid: Some(GUID.into()),
    }
}
fn role(name: &str) -> SentFolderRole {
    let status = crate::mailbox_status::MailboxStatus::new(name, GUID, 0, 0).unwrap();
    SentFolderRole::confirmed(&saved(name), Some(&status)).unwrap()
}
fn metadata(guid: &str) -> MessageMetadata {
    MessageMetadata {
        threading: None,
        version: MessageVersion::new(guid.into(), "public-message-guid".into()).unwrap(),
        attachment_count: Some(0),
        attachments: Some(vec![]),
        protection: MessageProtection::Plain,
        preview: None,
    }
}
fn row(name: &str) -> MessageSummary {
    MessageSummary {
        mailbox_name: name.into(),
        uid: 7,
        metadata: Some(metadata(GUID)),
        to: Some("public-recipient@example.test".into()),
        from: Some("public-sender@example.test".into()),
        subject: Some("Public role fixture".into()),
        flags: vec![],
        date_received: "2026-10-04T00:00:00Z".into(),
        size_virtual: 128,
    }
}
fn list(name: &str, context: &MailReaderContext) -> String {
    render_message_list_page(
        "alice@example.test",
        "public-test-token",
        name,
        &[row(name)],
        None,
        MessageListBulkActions {
            archive_mailbox_name: None,
            move_destinations: &[],
        },
        MessageListSortLinks {
            view: &ListViewState::from_query(&std::collections::BTreeMap::new()).unwrap(),
            search_query: None,
            search_scope: None,
            reader: context,
        },
    )
    .as_str()
    .into()
}
fn sent_active(html: &str) -> bool {
    let target = "href=\"/mailbox/shortcut?kind=sent\"";
    html.match_indices(target).any(|(start, _)| {
        html[start..]
            .split_once('>')
            .is_some_and(|(attrs, _)| attrs.contains("aria-current=\"page\""))
    })
}
fn rendered(name: &str, guid: &str) -> RenderedMessageView {
    RenderedMessageView {
        openpgp: None,
        metadata: Some(metadata(guid)),
        flags: vec![],
        mailbox_name: name.into(),
        uid: 7,
        subject: Some("Public role fixture".into()),
        from: Some("public-sender@example.test".into()),
        to: Some("public-recipient@example.test".into()),
        cc: None,
        reply_metadata: None,
        date_received: "2026-10-04T00:00:00Z".into(),
        mime_top_level_content_type: "text/plain".into(),
        body_source: crate::mime::MimeBodySource::SinglePartPlainText,
        contains_html_body: false,
        body_html: TrustedHtml::from_template("<pre>Public role body</pre>".into()),
        body_text_for_compose: "Public role body".into(),
        attachments: vec![],
        rendering_mode: crate::rendering::RenderingMode::PlainTextPreformatted,
    }
}
#[test]
fn sent_role_requires_current_exact_status_and_valid_saved_preference() {
    let saved = saved(TARGET);
    assert!(SentFolderRole::confirmed(&saved, None).is_none());
    for status in [
        crate::mailbox_status::MailboxStatus::new(TARGET, OTHER_GUID, 0, 0).unwrap(),
        crate::mailbox_status::MailboxStatus::new("Other", GUID, 0, 0).unwrap(),
    ] {
        assert!(SentFolderRole::confirmed(&saved, Some(&status)).is_none());
    }
    let mut invalid = saved.clone();
    invalid.revision = 0;
    assert!(SentFolderRole::confirmed(
        &invalid,
        Some(&crate::mailbox_status::MailboxStatus::new(TARGET, GUID, 0, 0).unwrap())
    )
    .is_none());
    let legacy =
        SentFolderRole::confirmed(&crate::sent_location::Preference::default(), None).unwrap();
    assert!(legacy.matches("Sent"));
    assert!(!legacy.matches(TARGET));
}
#[test]
fn configured_sent_list_uses_recipient_mode_and_preserves_actual_folder_identity() {
    let context = MailReaderContext {
        sent_role: Some(role(TARGET)),
        ..MailReaderContext::default()
    };
    let html = list(TARGET, &context);
    assert!(sent_active(&html));
    assert!(html.contains("approved-mail-table sent-table"));
    assert!(html.contains(">Recipient<"));
    assert!(html.contains("Stored Sent copies. Their presence does not confirm delivery."));
    assert!(html.contains("public-recipient@example.test"));
    assert!(html.contains("INBOX.SentCopyA"));
    assert!(html.contains("name=INBOX.SentCopyA"));
    let old = list("Sent", &context);
    assert!(!sent_active(&old));
    assert!(!old.contains("sent-table"));
    assert!(old.contains(">From<"));
    let unavailable = list(
        TARGET,
        &MailReaderContext {
            sent_role: None,
            ..MailReaderContext::default()
        },
    );
    assert!(!sent_active(&unavailable));
    assert!(!unavailable.contains("sent-table"));
    assert!(unavailable.contains(">From<"));
    assert!(sent_active(&list("Sent", &MailReaderContext::default())));
}
#[test]
fn configured_sent_reader_role_requires_current_rendered_mailbox_guid() {
    let context = MailReaderContext {
        sent_role: Some(role(TARGET)),
        ..MailReaderContext::default()
    };
    let neighbours = crate::reader_neighbours::ReaderNeighbours::default();
    let actual = render_message_view_page_with_context(
        "alice@example.test",
        "public-test-token",
        &rendered(TARGET, GUID),
        &context,
        &neighbours,
    );
    assert!(sent_active(actual.as_str()));
    assert!(actual.as_str().contains("mailbox=INBOX.SentCopyA"));
    for message in [rendered(TARGET, OTHER_GUID), rendered("Sent", GUID)] {
        let html = render_message_view_page_with_context(
            "alice@example.test",
            "public-test-token",
            &message,
            &context,
            &neighbours,
        );
        assert!(!sent_active(html.as_str()));
        assert!(html.as_str().contains("Public role body"));
    }
}
#[test]
fn configured_sent_inbox_role_uses_sent_table_and_bin_keeps_delete_projection() {
    let inbox = list(
        "INBOX",
        &MailReaderContext {
            sent_role: Some(role("INBOX")),
            ..MailReaderContext::default()
        },
    );
    assert!(sent_active(&inbox));
    assert!(inbox.contains("sent-table"));
    assert!(!inbox.contains("inbox-table"));
    let bin = list(
        TARGET,
        &MailReaderContext {
            sent_role: Some(role(TARGET)),
            bin_mailbox_name: Some(TARGET.into()),
            ..MailReaderContext::default()
        },
    );
    assert!(!sent_active(&bin));
    assert!(!bin.contains("sent-table"));
}
