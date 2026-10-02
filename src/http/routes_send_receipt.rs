use super::*;
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn send_receipt_response(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        intent: &str,
    ) -> HttpResponse {
        let decision = self.gateway.send_receipt(session, intent);
        let (mut status, title, message, recovery) = receipt_copy(&decision);
        if matches!(
            decision,
            Ok(Some(BrowserSendDecision::Submitted {
                sent_copy_stored: true,
                receipt_persisted: true,
            }))
        ) {
            return receipt_page(
                session,
                status,
                title,
                &message,
                "<p><a href=\"/mailbox?name=Sent\">Open Sent</a></p>",
                false,
            );
        }
        let recovery = match recovery {
            Some(id) => match self.gateway.load_draft(context, session, &id).decision {
                BrowserDraftLoadDecision::Loaded { draft, canonical_username } if canonical_username == session.record.canonical_username && draft.canonical_username == session.record.canonical_username && draft.draft_id == id => saved_version(&draft),
                BrowserDraftLoadDecision::NotFound => "<p>The recovery draft is absent. It may have expired, been discarded, or been removed after confirmed submission.</p>".into(),
                _ => "<p>Recovery availability could not be checked. No claim is made that its bytes remain stored.</p>".into(),
            },
            None => String::new(),
        };
        let snapshot = self.gateway.read_send_recovery(session, intent);
        if matches!(snapshot, BrowserSendRecoveryDecision::Available(_)) {
            status = 200;
        }
        let attempt = attempt_recovery(&snapshot, intent);
        let recovery = format!(
            "<details><summary>View recovery details</summary>{attempt}{recovery}</details>"
        );
        receipt_page(session, status, title, &message, &recovery, true)
    }
    pub(super) fn recovery_body_response(
        &self,
        session: &ValidatedSession,
        intent: &str,
    ) -> HttpResponse {
        match self.gateway.read_send_recovery(session, intent) {
            BrowserSendRecoveryDecision::Available(snapshot) => crate::http_support::recovery_body_download_response(&snapshot.request.body),
            BrowserSendRecoveryDecision::Expired => html_response(410,"Gone","Attempt recovery expired","<p>The attempt recovery retention period has ended.</p>"),
            BrowserSendRecoveryDecision::Missing => html_response(404,"Not Found","Attempt recovery missing","<p>No owned attempt snapshot was found.</p>"),
            _ => html_response(503,"Service Unavailable","Attempt recovery unavailable","<p>The exact attempt bytes could not be confirmed. No body source was returned.</p>"),
        }
    }
    pub(super) fn recovery_attachment_response(
        &self,
        session: &ValidatedSession,
        intent: &str,
        index: &str,
    ) -> HttpResponse {
        let index = match index.parse::<usize>() {
            Ok(value)
                if value.to_string() == index && value < crate::send::DEFAULT_MAX_ATTACHMENTS =>
            {
                value
            }
            _ => {
                return html_response(
                    400,
                    "Bad Request",
                    "Invalid attachment index",
                    "<p>Use a listed recovery attachment link.</p>",
                )
            }
        };
        match self.gateway.read_send_recovery(session,intent) {
            BrowserSendRecoveryDecision::Available(snapshot) => match snapshot.request.attachments.get(index) {
                Some(file)=>crate::http_support::recovery_attachment_download_response(file),
                None=>html_response(404,"Not Found","Attachment not found","<p>This attempt has no attachment at that index.</p>"),
            },
            BrowserSendRecoveryDecision::Expired=>html_response(410,"Gone","Attempt recovery expired","<p>The attempt recovery retention period has ended.</p>"),
            BrowserSendRecoveryDecision::Missing=>html_response(404,"Not Found","Attempt recovery missing","<p>No owned attempt snapshot was found.</p>"),
            _=>html_response(503,"Service Unavailable","Attempt recovery unavailable","<p>The exact attempt bytes could not be confirmed. No attachment was returned.</p>"),
        }
    }
    pub(super) fn saved_draft_receipt_response(
        &self,
        session: &ValidatedSession,
        intent: &str,
        draft: &DraftRecord,
    ) -> HttpResponse {
        let decision = self.gateway.send_receipt(session, intent);
        let (status, title, message, _) = receipt_copy(&decision);
        let mut recovery = saved_version(draft);
        if crate::send_journal::receipt_intent_valid(intent) {
            recovery.push_str(&format!("<p><a href=\"/compose?receipt={}\" target=\"_blank\" rel=\"noopener noreferrer\">View this attempt’s receipt and retained source (opens in a new tab)</a>. The saved version above may differ from the prepared attempt. This link does not submit a message.</p>", escape_html(&url_encode(intent))));
        }
        receipt_page(session, status, title, &message, &recovery, true)
    }

    pub(super) fn intent_guard_response(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
        form: &BTreeMap<String, String>,
        attachments: &[UploadedAttachment],
    ) -> Option<HttpResponse> {
        let Some(intent) = form.get("send_intent").filter(|value| !value.is_empty()) else {
            return Some(html_response(
                400,
                "Bad Request",
                "Send intent required",
                "<p>This form has no send intent. No new intent was substituted.</p>",
            ));
        };
        match self.gateway.send_receipt(session, intent) {
            Ok(None) => None,
            Ok(Some(_)) => Some(super::routes_compose::submission_result_response(
                session,
                form,
                attachments,
                crate::compose_result_ui::SubmissionResult::AlreadyRecorded,
            )),
            Err(_) => Some(super::routes_compose::submission_result_response(
                session,
                form,
                attachments,
                crate::compose_result_ui::SubmissionResult::Paused,
            )),
        }
    }
}

fn receipt_copy(
    decision: &Result<Option<BrowserSendDecision>, String>,
) -> (u16, &'static str, String, Option<String>) {
    match decision {
        Ok(Some(BrowserSendDecision::RecoveryRefused { capacity })) => (200, "Submission was not invoked", if *capacity { "The combined draft and attempt-recovery limit was reached. Submission was not invoked; this intent remains paused. Do not retry automatically." } else { "Attempt recovery was not confirmed. Submission was not invoked; this intent remains paused. Do not retry automatically." }.into(), None),
            Ok(Some(BrowserSendDecision::Submitted { sent_copy_stored: true, receipt_persisted: true })) => (200, "Message submitted", "The mail server accepted your message. A copy was saved in Sent. Delivery to the recipient is not yet confirmed.".into(), None),
            Ok(Some(BrowserSendDecision::Submitted { sent_copy_stored, receipt_persisted })) => (200, "Message accepted for submission", format!("Submission acceptance is known. Delivery is not confirmed. {} {} Do not send again to repair Sent or draft cleanup. The outcome record and retained message snapshot are separate. Open recovery details only if needed to reconcile this attempt.", if *sent_copy_stored { "A copy was stored in Sent." } else { "Sent-copy storage could not be confirmed; the copy may be missing or already present." }, if *receipt_persisted { "The outcome record was saved." } else { "Saving the outcome record could not be confirmed." }), None),
            Ok(Some(BrowserSendDecision::DraftSaved { draft_id, save_confirmed })) => (200, "Saved draft handoff", format!("This original form was retired into a draft. {} The resulting draft may have been sent separately; this receipt does not establish its later submission status.", if *save_confirmed { "The draft save was confirmed." } else { "The draft save could not be confirmed." }), Some(draft_id.clone())),
            Ok(Some(BrowserSendDecision::Unconfirmed { .. })) => (200, "Submission could not be confirmed", "Submission may have occurred. Ask the mail operator to reconcile this attempt; do not send again. Any verified attempt snapshot is shown separately below. Its availability or expiry does not establish the submission outcome.".into(), None),
            Ok(None) => (404, "Receipt not found", "No receipt was found for this account and intent. This is not proof that no submission occurred.".into(), None),
            _ => (503, "Receipt unavailable", "The recorded outcome could not be read. Do not retry submission.".into(), None),
    }
}
fn receipt_page(
    session: &ValidatedSession,
    status: u16,
    title: &str,
    message: &str,
    recovery: &str,
    show_drafts_link: bool,
) -> HttpResponse {
    let footer = if show_drafts_link {
        "<p>This receipt is read-only. <a href=\"/drafts\">Open Drafts</a></p>"
    } else {
        ""
    };
    html_response(status, if status == 200 { "OK" } else if status == 404 { "Not Found" } else { "Service Unavailable" }, title,
        TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell submission-result-page\"><section class=\"panel\"><h1>{}</h1><p role=\"status\">{}</p>{}{footer}</section></main>", crate::http_ui::app_header(&session.record.canonical_username, &session.record.csrf_token, "compose-result"), escape_html(title), escape_html(message), recovery)))
}
fn sender_presentation(identity: &crate::identity_preferences::IdentityPreferences) -> String {
    format!("<section class=\"retained-sender\" aria-label=\"Captured sender presentation\"><h3>Captured sender presentation</h3><p>Display name: <span data-sender-name>{}</span></p><p>Reply-to: <span data-sender-reply>{}</span></p><p>The canonical account address remains the authorized sender. These values come from this retained version, not the current profile.</p></section>", escape_html(if identity.display_name().is_empty() { "None (canonical address only)" } else { identity.display_name() }), escape_html(identity.reply_to().unwrap_or("Canonical account address")))
}

fn saved_version(draft: &DraftRecord) -> String {
    let mut html = String::from("<section aria-labelledby=\"saved-recovery-heading\"><h2 id=\"saved-recovery-heading\">Saved version for comparison</h2><p>This is the saved draft, not a backup of the attempted submission. Its text and attachments may differ from attempted edits and new uploads. Opening this view does not start another attempt. Drafts expire after 30 days.</p>");
    html.push_str(&sender_presentation(&draft.request.sender_identity));
    for (id, label, text) in [
        ("to", "To", &draft.request.recipients_text),
        ("cc", "Cc", &draft.request.cc_text),
        ("bcc", "Bcc", &draft.request.bcc_text),
        ("subject", "Subject", &draft.request.subject),
        ("body", "Body", &draft.request.body),
    ] {
        html.push_str(&format!("<label for=\"saved-recovery-{id}\">{label}</label><textarea id=\"saved-recovery-{id}\" readonly rows=\"{}\">\n{}</textarea>", if id == "body" { 12 } else { 2 }, escape_html(text)));
    }
    html.push_str(&format!(
        "<p>Stored message format: {}. This source is read-only.</p><h3>Stored attachments</h3>",
        draft.request.body_format.as_str()
    ));
    if draft.request.attachments.is_empty() {
        html.push_str("<p>No files are stored in this draft.</p>");
    } else {
        html.push_str("<ul>");
        for file in &draft.request.attachments {
            html.push_str(&format!(
                "<li data-saved-attachment>{} ({} bytes)</li>",
                escape_html(&file.filename),
                file.body.len()
            ));
        }
        html.push_str("</ul>");
    }
    if draft.source_attachments.is_some() {
        html.push_str("<p>This draft also references source-message attachments. Their bytes are not stored in this draft and have not been fetched by this view.</p>");
    }
    html.push_str("</section>");
    html
}

fn attempt_recovery(decision: &BrowserSendRecoveryDecision, intent: &str) -> String {
    let snapshot = match decision {
        BrowserSendRecoveryDecision::Available(value) => value,
        BrowserSendRecoveryDecision::Missing => return "<section><h2>Attempt recovery missing</h2><p>No exact attempt snapshot was found for this account and intent. This does not establish whether submission occurred.</p></section>".into(),
        BrowserSendRecoveryDecision::Expired => return "<section><h2>Attempt recovery expired</h2><p>The 30-day retention period ended. Attachment downloads are unavailable. Expiry does not establish the submission outcome.</p></section>".into(),
        BrowserSendRecoveryDecision::Unconfirmed => return "<section><h2>Attempt recovery not confirmed</h2><p>Snapshot publication was not confirmed. No partial content or attachment bytes are shown. This does not establish the submission outcome.</p></section>".into(),
        BrowserSendRecoveryDecision::Unavailable => return "<section><h2>Attempt recovery unavailable</h2><p>The exact retained attempt could not be verified. Its bytes may still be stored. This does not establish the submission outcome.</p></section>".into(),
    };
    let request = &snapshot.request;
    let mut html=String::from("<section aria-labelledby=\"attempt-recovery-heading\"><h2 id=\"attempt-recovery-heading\">Exact prepared attempt</h2><p>This verified snapshot records what was prepared before submission. Its existence does not prove that submission was invoked, accepted, or delivered. The saved draft comparison may contain different text or files. This view cannot send or edit the attempt.</p>");
    html.push_str(&sender_presentation(&request.sender_identity));
    for (label, time) in [
        ("Created", snapshot.created_at),
        ("Expires", snapshot.expires_at),
    ] {
        let utc = crate::logging::format_unix_timestamp_utc(time);
        html.push_str(&format!(
            "<p>{label}: <time datetime=\"{}\">{}</time></p>",
            escape_html(&utc),
            escape_html(&utc.replace('T', " ").replace('Z', " UTC"))
        ));
    }
    for (id, label, value) in [
        ("to", "Attempt To", request.recipients.join(", ")),
        ("cc", "Attempt Cc", request.cc_recipients.join(", ")),
        ("bcc", "Attempt Bcc", request.bcc_recipients.join(", ")),
        ("subject", "Attempt subject", request.subject.clone()),
        ("body", "Attempt body source", request.body.clone()),
    ] {
        html.push_str(&format!("<label for=\"attempt-{id}\">{label}</label><textarea id=\"attempt-{id}\" readonly rows=\"{}\">\n{}</textarea>",if id=="body"{12}else{2},escape_html(&value)));
    }
    html.push_str(&format!(
        "<p>Prepared message format: {}. The literal source above is read-only.</p>",
        request.body_format.as_str()
    ));
    html.push_str(&format!("<p><a href=\"/compose?receipt={}&amp;recovery_body=1\">Download body source</a>. Text fields normalize line endings; the UTF-8 download preserves the retained source exactly.</p>", escape_html(&url_encode(intent))));
    if let Some(thread) = &request.reply_thread {
        html.push_str(&format!("<h3>Prepared reply context</h3><p>In-Reply-To: <code>{}</code></p><p>References: <code>{}</code></p><p>Reference list shortened: {}.</p>",escape_html(thread.in_reply_to().unwrap_or("None")),escape_html(&thread.references()),thread.shortened()));
    } else {
        html.push_str("<p>No reply context was included.</p>");
    }
    html.push_str("<h3>Prepared attachments</h3><ul>");
    for (index, file) in request.attachments.iter().enumerate() {
        html.push_str(&format!("<li data-attempt-attachment><a href=\"/compose?receipt={}&amp;recovery_attachment={index}\">Download {}</a> ({} bytes)</li>",escape_html(&url_encode(intent)),escape_html(&file.filename),file.body.len()));
    }
    html.push_str("</ul>");
    if request.attachments.is_empty() {
        html.push_str("<p>No attachments were prepared.</p>");
    }
    html.push_str("</section>");
    html
}
#[cfg(test)]
#[test]
fn prepared_reply_metadata_and_formatted_source_are_literal() {
    let mut request = ComposeRequest::new(
        ComposePolicy::default(),
        "bob@example.test",
        "Subject",
        "**🦊**",
    )
    .unwrap()
    .with_body_format(crate::compose_format::BodyFormat::Formatted)
    .unwrap();
    request.sender_identity = crate::identity_preferences::IdentityPreferences::new(
        "Zoë <literal>",
        Some("reply@example.test"),
    )
    .unwrap();
    request.reply_thread = Some(
        crate::reply_thread::ReplyThread::from_original(
            "Message-ID: <parent@example.test>\nReferences: <root@example.test>\n",
        )
        .unwrap(),
    );
    let html = attempt_recovery(
        &BrowserSendRecoveryDecision::Available(BrowserSendRecoverySnapshot {
            request: Box::new(request),
            created_at: 100,
            expires_at: 100 + crate::draft::DEFAULT_DRAFT_MAX_AGE_SECONDS,
        }),
        "100.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    for expected in [
        "Prepared message format: formatted",
        "Zoë &lt;literal&gt;",
        "reply@example.test",
        "**🦊**",
        "&lt;parent@example.test&gt;",
        "&lt;root@example.test&gt;",
        "1970-01-31 00:01:40 UTC",
    ] {
        assert!(html.contains(expected));
    }
    assert!(!html.contains("<strong>") && !html.contains("action=\"/send\""));
}
