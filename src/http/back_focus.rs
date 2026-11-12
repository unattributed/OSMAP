//! Native fragment focus is presentation only; current owned rows grant no new authority.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn target(
    account: &str,
    mailbox: &str,
    uid: u64,
    metadata: Option<&MessageMetadata>,
) -> Option<String> {
    if account.is_empty()
        || account.len() > crate::auth::DEFAULT_USERNAME_MAX_LEN
        || account.chars().any(char::is_control)
        || uid == 0
        || uid > u64::from(u32::MAX)
        || MailboxEntry::new(crate::mailbox::MailboxListingPolicy::default(), mailbox).is_err()
    {
        return None;
    }
    let version = &metadata?.version;
    let version = crate::message_metadata::MessageVersion::new(
        version.mailbox_guid.clone(),
        version.message_guid.clone(),
    )
    .ok()?;
    let mut hash = Sha256::new();
    hash.update(b"OSMAP/native-list-focus/v1\0");
    let uid = uid.to_be_bytes();
    for field in [
        account.as_bytes(),
        mailbox.as_bytes(),
        uid.as_slice(),
        version.mailbox_guid.as_bytes(),
        version.message_guid.as_bytes(),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    Some(format!("mail-row-{:x}", hash.finalize()))
}

fn unique_targets<'a>(
    account: &str,
    rows: impl Iterator<Item = (&'a str, u64, Option<&'a MessageMetadata>)>,
) -> Vec<Option<String>> {
    let rows: Vec<_> = rows.collect();
    let mut counts = BTreeMap::new();
    for &(mailbox, uid, _) in &rows {
        *counts.entry((mailbox, uid)).or_insert(0usize) += 1;
    }
    rows.into_iter()
        .map(|(mailbox, uid, metadata)| {
            if counts.get(&(mailbox, uid)) == Some(&1) {
                target(account, mailbox, uid, metadata)
            } else {
                None
            }
        })
        .collect()
}

pub(super) fn summary_targets(account: &str, rows: &[MessageSummary]) -> Vec<Option<String>> {
    if rows.len() > crate::mailbox::DEFAULT_MAX_MESSAGES {
        return vec![None; rows.len()];
    }
    unique_targets(
        account,
        rows.iter()
            .map(|r| (r.mailbox_name.as_str(), r.uid, r.metadata.as_ref())),
    )
}

pub(super) fn search_targets(account: &str, rows: &[MessageSearchResult]) -> Vec<Option<String>> {
    if rows.len() > crate::mailbox::DEFAULT_MAX_SEARCH_RESULTS {
        return vec![None; rows.len()];
    }
    unique_targets(
        account,
        rows.iter()
            .map(|r| (r.mailbox_name.as_str(), r.uid, r.metadata.as_ref())),
    )
}

pub(super) fn attributes(target: Option<&str>) -> String {
    target
        .map(|id| {
            format!(
                " id=\"{}\" tabindex=\"-1\" data-list-focus=\"true\"",
                escape_html(id)
            )
        })
        .unwrap_or_default()
}

pub(super) fn back_href(
    account: &str,
    base: &str,
    view: &ListViewState,
    reader: &MailReaderContext,
    targets: &[Option<String>],
) -> String {
    let mut cleared = view.clone();
    cleared.selection = None;
    cleared.requested_version = None;
    cleared.opened_read = false;
    let back = list_navigation_href(base, &cleared, view.page);
    let focused = || -> Option<String> {
        let SelectedMessagePane::Ready(rendered) = &reader.pane else {
            return None;
        };
        let selected = view.selection.as_ref()?;
        let metadata = rendered.metadata.as_ref()?;
        if selected.mailbox != rendered.mailbox_name
            || selected.uid != rendered.uid
            || view.selected_version.as_ref() != Some(&metadata.version)
            || view.selection_page != Some(view.page)
            || crate::mail_navigation::safe_mail_return(&back).is_none()
        {
            return None;
        }
        let id = target(
            account,
            &rendered.mailbox_name,
            rendered.uid,
            Some(metadata),
        )?;
        // A Ready Seen message can be outside the displayed Unread rows. Only
        // the unique current rendered row may receive a fragment target.
        (targets
            .iter()
            .filter(|candidate| candidate.as_ref() == Some(&id))
            .count()
            == 1)
            .then_some(id)
    };
    focused().map(|id| format!("{back}#{id}")).unwrap_or(back)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message_metadata::{MessageProtection, MessageVersion};

    fn row(mailbox: &str, uid: u64) -> MessageSummary {
        MessageSummary {
            mailbox_name: mailbox.into(),
            uid,
            flags: vec![],
            date_received: "2026-10-03 01:00:00 +0000".into(),
            size_virtual: 0,
            subject: Some("Identical public subject".into()),
            from: None,
            to: None,
            metadata: Some(MessageMetadata {
                version: MessageVersion::new("a".repeat(32), format!("public-{uid}\"<#&'?"))
                    .unwrap(),
                attachment_count: None,
                attachments: None,
                protection: MessageProtection::Unknown,
                preview: None,
                threading: None,
            }),
        }
    }

    fn ready(row: &MessageSummary) -> MailReaderContext {
        MailReaderContext {
            pane: SelectedMessagePane::Ready(Box::new(RenderedMessageView {
                openpgp: None,
                metadata: row.metadata.clone(),
                flags: row.flags.clone(),
                mailbox_name: row.mailbox_name.clone(),
                uid: row.uid,
                subject: row.subject.clone(),
                from: None,
                to: None,
                cc: None,
                reply_metadata: None,
                date_received: row.date_received.clone(),
                mime_top_level_content_type: "text/plain".into(),
                body_source: crate::mime::MimeBodySource::SinglePartPlainText,
                contains_html_body: false,
                body_html: TrustedHtml::from_template("<pre>Owned synthetic</pre>".into()),
                body_text_for_compose: "Owned synthetic".into(),
                attachments: vec![],
                rendering_mode: crate::rendering::RenderingMode::PlainTextPreformatted,
            })),
            ..MailReaderContext::default()
        }
    }

    fn view(row: &MessageSummary, page: usize) -> ListViewState {
        let mut view = ListViewState::from_query(&BTreeMap::from([
            ("filter".into(), "unread".into()),
            ("pgp".into(), "unknown".into()),
            ("from".into(), "sender@example.test".into()),
            ("sort".into(), "subject".into()),
            ("dir".into(), "asc".into()),
            ("page".into(), page.to_string()),
            ("selected_mailbox".into(), row.mailbox_name.clone()),
            ("selected_uid".into(), row.uid.to_string()),
        ]))
        .unwrap();
        view.selected_version = row.metadata.as_ref().map(|m| m.version.clone());
        view.selection_page = Some(page);
        view
    }

    #[test]
    fn back_focus_ids_are_bounded_hashed_full_tuples_not_raw_graphical_guids() {
        let original = row("INBOX", 3);
        let id = target("alice@example.test", "INBOX", 3, original.metadata.as_ref()).unwrap();
        assert_eq!(id.len(), "mail-row-".len() + 64);
        assert!(id
            .strip_prefix("mail-row-")
            .unwrap()
            .bytes()
            .all(|b| b.is_ascii_hexdigit()));
        assert_eq!(
            target("alice@example.test", "INBOX", 3, original.metadata.as_ref()).as_ref(),
            Some(&id)
        );
        for (account, mailbox, uid) in [
            ("bob@example.test", "INBOX", 3),
            ("alice@example.test", "Sent", 3),
            ("alice@example.test", "INBOX", 4),
        ] {
            assert_ne!(
                target(account, mailbox, uid, original.metadata.as_ref()).as_ref(),
                Some(&id)
            );
        }
        let mut changed = original.clone();
        changed
            .metadata
            .as_mut()
            .unwrap()
            .version
            .message_guid
            .push('x');
        assert_ne!(
            summary_targets("alice@example.test", &[changed])[0].as_ref(),
            Some(&id)
        );
        let attributes = attributes(Some(&id));
        assert!(attributes.contains("tabindex=\"-1\" data-list-focus=\"true\""));
        assert!(!attributes.contains("public-3"));
    }

    #[test]
    fn back_focus_duplicate_uid_identity_missing_and_invalid_metadata_have_no_target() {
        let original = row("INBOX", 3);
        let mut duplicate = original.clone();
        duplicate
            .metadata
            .as_mut()
            .unwrap()
            .version
            .message_guid
            .push('x');
        let mut missing = original.clone();
        missing.uid = 4;
        missing.metadata = None;
        let mut invalid = original.clone();
        invalid.uid = 5;
        invalid.metadata.as_mut().unwrap().version.mailbox_guid = "invalid".into();
        let rows = vec![original, duplicate, missing, invalid, row("Sent", 3)];
        let targets = summary_targets("alice@example.test", &rows);
        assert!(targets[..4].iter().all(Option::is_none));
        assert!(targets[4].is_some());
        assert!(attributes(None).is_empty());
        assert!(target("alice@example.test", "INBOX", 0, rows[4].metadata.as_ref()).is_none());
        assert!(target(
            "alice@example.test",
            "INBOX",
            u64::from(u32::MAX) + 1,
            rows[4].metadata.as_ref()
        )
        .is_none());
    }

    #[test]
    fn back_focus_uses_only_current_ready_unique_visible_page_and_preserves_query() {
        let row = row("INBOX", 51);
        let view = view(&row, 2);
        let reader = ready(&row);
        let targets = summary_targets("alice@example.test", std::slice::from_ref(&row));
        let back = back_href(
            "alice@example.test",
            "/search?scope=all&q=public&field=subject",
            &view,
            &reader,
            &targets,
        );
        let (url, fragment) = back.split_once('#').unwrap();
        assert_eq!(Some(fragment), targets[0].as_deref());
        assert!(crate::mail_navigation::safe_mail_return(url).is_some());
        let fields =
            crate::http_form::parse_query_string(url.split_once('?').unwrap().1, 19).unwrap();
        for (key, expected) in [
            ("page", "2"),
            ("q", "public"),
            ("scope", "all"),
            ("field", "subject"),
            ("filter", "unread"),
            ("pgp", "unknown"),
            ("from", "sender@example.test"),
            ("sort", "subject"),
            ("dir", "asc"),
        ] {
            assert_eq!(fields.get(key).map(String::as_str), Some(expected));
        }
        assert!(!fields
            .keys()
            .any(|k| k.starts_with("selected_") || k == "opened_read"));
        let ordinary = back_href(
            "alice@example.test",
            "/search?scope=all&q=public&field=subject",
            &view,
            &reader,
            &[],
        );
        assert_eq!(ordinary, url);
        let mut off_page = view.clone();
        off_page.selection_page = Some(1);
        assert_eq!(
            back_href(
                "alice@example.test",
                "/search?scope=all&q=public&field=subject",
                &off_page,
                &reader,
                &targets
            ),
            url
        );
        let mut stale = view.clone();
        stale
            .selected_version
            .as_mut()
            .unwrap()
            .message_guid
            .push('x');
        assert_eq!(
            back_href(
                "alice@example.test",
                "/search?scope=all&q=public&field=subject",
                &stale,
                &reader,
                &targets
            ),
            url
        );
        let mut wrong_folder = view.clone();
        wrong_folder.selection.as_mut().unwrap().mailbox = "Sent".into();
        assert_eq!(
            back_href(
                "alice@example.test",
                "/search?scope=all&q=public&field=subject",
                &wrong_folder,
                &reader,
                &targets
            ),
            url
        );
        assert_eq!(
            back_href(
                "alice@example.test",
                "/search?scope=all&q=public&field=subject",
                &view,
                &MailReaderContext::default(),
                &targets
            ),
            url
        );
    }

    #[test]
    fn back_focus_actual_mailbox_and_search_render_exact_current_row_and_ready_back() {
        let original = row("INBOX", 3);
        let view = view(&original, 1);
        let reader = ready(&original);
        let rows = [original.clone(), row("Sent", 3)];
        let id = summary_targets("alice@example.test", &rows)[0]
            .clone()
            .unwrap();
        let html = render_message_list_page(
            "alice@example.test",
            "synthetic-csrf",
            "INBOX",
            &rows[..1],
            None,
            MessageListBulkActions {
                archive_mailbox_name: None,
                move_destinations: &[],
            },
            MessageListSortLinks {
                view: &view,
                search_query: None,
                search_scope: None,
                reader: &reader,
            },
        );
        assert_eq!(html.as_str().matches(&format!(" id=\"{id}\"")).count(), 1);
        assert!(html
            .as_str()
            .contains(&format!("#{id}\" aria-label=\"Back to list\"")));
        let search: Vec<_> = rows
            .into_iter()
            .map(|r| MessageSearchResult {
                mailbox_name: r.mailbox_name,
                uid: r.uid,
                flags: r.flags,
                date_received: r.date_received,
                size_virtual: r.size_virtual,
                subject: r.subject,
                from: r.from,
                metadata: r.metadata,
            })
            .collect();
        let ids = search_targets("alice@example.test", &search);
        assert_ne!(ids[0], ids[1]);
        let html = render_message_search_page(
            "alice@example.test",
            "synthetic-csrf",
            None,
            "public",
            &search,
            MessageSearchContext {
                view: &view,
                field: MessageSearchField::Subject,
                reader: &reader,
            },
        );
        for id in ids.iter().flatten() {
            assert_eq!(html.as_str().matches(&format!(" id=\"{id}\"")).count(), 1);
        }
        assert!(html
            .as_str()
            .contains(&format!("#{id}\" aria-label=\"Back to list\"")));
        let mut stale_reader = ready(&original);
        let SelectedMessagePane::Ready(rendered) = &mut stale_reader.pane else {
            unreachable!();
        };
        rendered
            .metadata
            .as_mut()
            .unwrap()
            .version
            .message_guid
            .push('x');
        let html = render_message_search_page(
            "alice@example.test",
            "synthetic-csrf",
            None,
            "public",
            &search,
            MessageSearchContext {
                view: &view,
                field: MessageSearchField::Subject,
                reader: &stale_reader,
            },
        );
        assert!(!html
            .as_str()
            .contains(&format!("#{id}\" aria-label=\"Back to list\"")));
    }
}
