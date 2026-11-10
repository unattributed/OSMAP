//! Hostile strings belong to test fixtures, outside the runtime template file.
use super::*;

#[test]
fn shared_headers_reuse_login_logo_without_changing_navigation_or_copy() {
    let login = render_login_page(None).as_str().to_owned();
    let start = login.find("<svg class=\"login-shield\"").unwrap();
    let end = start + login[start..].find("</svg>").unwrap() + "</svg>".len();
    let logo = &login[start..end];
    for page in ["mailboxes", "inbox", "compose", "settings", "outbox"] {
        let header = app_header("alice@example.test", "synthetic-csrf", page);
        assert_eq!(header.matches(logo).count(), 1, "{page}");
        assert!(header.contains("href=\"/mailboxes\" aria-label=\"OSMAP mailboxes\""));
        assert!(header.contains("action=\"/logout\""));
        if page == "mailboxes" {
            assert!(header.contains("Secure Email. Your Data. Your Control."));
        }
    }
}

#[test]
fn state_card_escapes_inert_content_and_keeps_only_native_link() {
    let html = mail_state_card(
        "<title>",
        "<script>literal</script>",
        "/search?mailbox=A%26B&q=x",
        "Retry",
        true,
    );
    assert!(html.contains("&lt;script&gt;literal&lt;/script&gt;"));
    assert!(html.contains("/search?mailbox=A%26B&amp;q=x"));
    assert!(!html.contains("<script"));
    assert!(!html.contains("<form"));
}

#[cfg(test)]
#[test]
fn scheduled_draft_row_links_job_without_claiming_pending_or_allowing_edit() {
    let draft = DraftSummary {
        draft_id: "a".repeat(32),
        created_at: 100,
        updated_at: 100,
        expires_at: 200,
        revision: 2,
        starred: false,
        storage_bytes: 1,
        recipient_count: 0,
        recipient_preview: None,
        subject: "<script>synthetic</script>".into(),
        subject_len: 30,
        body_len: 1,
        attachment_count: 0,
        total_attachment_bytes: 0,
    };
    let state = crate::http::BrowserDraftEditState::Scheduled {
        job_id: "b".repeat(32),
    };
    let html = render_locked_draft_row(&draft, Some(&state), "synthetic-csrf", true);
    assert!(html.contains("Scheduled copy") && html.contains("Managed in Outbox"));
    assert!(html.contains(&format!("/outbox?id={}", "b".repeat(32))));
    assert!(html.contains("&lt;script&gt;synthetic&lt;/script&gt;"));
    for wrong in [
        "Submission state needs review",
        "View attempt",
        "action=\"/drafts/star\"",
    ] {
        assert!(!html.contains(wrong));
    }
    assert!(html.contains("form=\"draft-selection\"") && html.contains("Delete source copy"));
    assert!(html.contains("name=\"selected_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" value=\"2\" checked"));
    assert!(html.contains("action=\"/drafts/delete\"") && html.contains("synthetic-csrf"));
    assert!(html.contains("name=\"draft_revision\" value=\"2\""));
    let invalid = crate::http::BrowserDraftEditState::Scheduled {
        job_id: "../foreign<script>".into(),
    };
    let html = render_locked_draft_row(&draft, Some(&invalid), "synthetic-csrf", true);
    assert!(html.contains("href=\"/outbox\""));
    assert!(!html.contains("../foreign"));
    assert!(!html.contains("action=\"/drafts/delete\""));
    assert!(html.contains("checkbox\" disabled") && !html.contains("name=\"selected_"));
    let html = render_locked_draft_row(&draft, None, "synthetic-csrf", true);
    assert!(html.contains("Delete unavailable") && !html.contains("action=\"/drafts/delete\""));
}
