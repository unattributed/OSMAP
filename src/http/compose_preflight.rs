//! Read-only composition checks on the draft saved by the explicit action.
use crate::http_support::escape_html;
use crate::http_ui::ComposePageModel;
use crate::send::{ComposePolicy, ComposeRequest};

pub(crate) fn render(model: &ComposePageModel<'_>) -> String {
    if !model.preflight {
        return String::new();
    }
    let result = ComposeRequest::new_with_routing(
        ComposePolicy::default(),
        model.to_value,
        model.cc_value,
        model.bcc_value,
        model.subject_value,
        model.body_value,
        model.draft_attachments.to_vec(),
    )
    .and_then(|request| request.with_body_format(model.body_format));
    let summary = match result {
        Ok(request) => format!(
            "<p class=\"notice notice-success\">Recipient addresses, message text and stored files pass composition checks.</p><dl class=\"message-meta\"><dt>Sender</dt><dd>{}</dd><dt>Recipients</dt><dd>{} To · {} Cc · {} Bcc · {} unique delivery addresses</dd><dt>Message format</dt><dd>{}</dd><dt>Stored attachments</dt><dd>{} files · {} bytes</dd></dl>",
            escape_html(model.sender_identity.and_then(|v|v.sender()).map(|v|v.address()).unwrap_or(model.canonical_username)), request.recipients.len(),
            request.cc_recipients.len(), request.bcc_recipients.len(),
            request.all_recipients().len(),
            if model.body_format == crate::compose_format::BodyFormat::Plain { "Plain text" } else { "Formatted text with a plain-text alternative" },
            model.draft_attachments.len(), model.draft_attachments.iter().map(|file| file.body.len()).sum::<usize>(),
        ),
        Err(error) => format!("<p class=\"notice notice-error\" role=\"alert\">Edit this draft before sending: {}</p>", escape_html(&error.reason)),
    };
    let source = if model.selected_source_part_paths.is_empty() {
        String::new()
    } else {
        format!("<p class=\"notice\">{} original-message attachment(s) selected. Their current availability and combined size will be checked again when you send.</p>", model.selected_source_part_paths.len())
    };
    let requested = |value| if value { "Requested" } else { "Not requested" };
    let key_snapshot = match model.openpgp.as_ref() {
        Some(view) if view.runtime_configured => match view.preflight.as_ref() {
            Some(preflight)
                if view.revision != Some(preflight.revision)
                    || model.protection.binding_revision.is_some_and(|saved| Some(saved) != view.revision) =>
            {
                "This draft uses an older or inconsistent OpenPGP binding snapshot. Use Pre-send check again to review and save the current public keys before sending."
            }
            Some(preflight) => match preflight.state {
                crate::openpgp_bindings::PreflightState::Blocked =>
                    "Blocked by the current public-key or protection-policy checks.",
                crate::openpgp_bindings::PreflightState::Orange =>
                    "Public-key or protection-policy checks need attention.",
                crate::openpgp_bindings::PreflightState::Green if preflight.recipients.is_empty() =>
                    "No recipient addresses checked. Add recipients to check their keys.",
                crate::openpgp_bindings::PreflightState::Green =>
                    "Public keys eligible in the saved-draft snapshot.",
            },
            None if model.to_value.is_empty() && model.cc_value.is_empty() && model.bcc_value.is_empty() =>
                "No recipient addresses checked. Add recipients to check their keys.",
            None => "Recipient-key status is unavailable in the saved-draft snapshot.",
        },
        _ => "OpenPGP capability could not be established on this page. A protected send must pass current capability checks before submission.",
    };
    let public_keys = model
        .openpgp
        .as_ref()
        .filter(|view| view.runtime_configured)
        .map(|view| {
            let revision = view
                .revision
                .map(|value| value.to_string())
                .unwrap_or_else(|| "Unavailable".into());
            let mut details = format!(
                "<dt>Current public binding revision</dt><dd>{}</dd>",
                escape_html(&revision)
            );
            if let Some(plan) = view.preflight.as_ref().and_then(|preflight| {
                (view.revision == Some(preflight.revision)).then_some(preflight.plan.as_ref()).flatten()
            }) {
                if let Some(signer) = plan.signer_fingerprint.as_deref() {
                    details.push_str(&format!(
                        "<dt>Selected signing fingerprint</dt><dd>{}</dd>",
                        escape_html(signer)
                    ));
                }
                if !plan.recipient_fingerprints.is_empty() {
                    let fingerprints = plan
                        .recipient_fingerprints
                        .iter()
                        .map(|fingerprint| format!("<li>{}</li>", escape_html(fingerprint)))
                        .collect::<String>();
                    details.push_str(&format!(
                        "<dt>Planned encryption fingerprints (including self when selected)</dt><dd><ul>{fingerprints}</ul></dd>"
                    ));
                }
            }
            details
        })
        .unwrap_or_default();
    format!(concat!(
        "<section class=\"compose-preview compose-preflight\" aria-label=\"Pre-send check\"><h2>Pre-send check</h2>",
        "<p>This check shows the saved draft. After editing, check again. No message was sent.</p>{summary}{source}",
        "<dl class=\"message-meta\"><dt>Signing</dt><dd>{signing}</dd><dt>Encryption</dt><dd>{encryption}</dd><dt>Encrypt to self</dt><dd>{self_encryption}</dd><dt>Public-key snapshot</dt><dd>{key_snapshot}</dd>{public_keys}</dl>",
        "<p class=\"muted\">This check does not sign, encrypt or send the message. Public-key results are a snapshot. Sending rechecks the current keys, account, draft and attachments.</p></section>"
    ), summary = summary, source = source, signing = requested(model.protection.sign),
       encryption = requested(model.protection.encrypt), self_encryption = requested(model.protection.encrypt_to_self),
       key_snapshot = key_snapshot, public_keys = public_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::ComposeProtectionView;
    use crate::openpgp_bindings::{
        KeyStatus, Preflight, PreflightState, RecipientReadiness, Requirement,
    };
    use crate::send::ProtectionIntent;

    fn model() -> ComposePageModel<'static> {
        ComposePageModel {
            sender_choices: None,
            selected_sender_id: None,
            protection: ProtectionIntent::default(),
            openpgp: None,
            sender_identity: None,
            send_intent: "fixture",
            contacts: None,
            heading: "Compose",
            canonical_username: "alice@example.test",
            csrf_token: "fixture",
            success_message: None,
            error_message: None,
            context_notice: None,
            to_value: "bob@example.test",
            cc_value: "",
            bcc_value: "",
            subject_value: "Synthetic test",
            body_value: "Synthetic text",
            body_format: crate::compose_format::BodyFormat::Plain,
            preview: false,
            preflight: true,
            draft_id: None,
            draft_revision: None,
            draft_attachments: &[],
            removed_attachment_indices: &[],
            source_mailbox_name: None,
            source_uid: None,
            source_version: None,
            source_attachments: &[],
            selected_source_part_paths: &[],
            reply_reference: None,
        }
    }
    fn capability(state: PreflightState) -> ComposeProtectionView {
        ComposeProtectionView {
            runtime_configured: true,
            revision: Some(2),
            account_binding: None,
            policy: crate::openpgp_bindings::ProtectionPolicy::default(),
            recipient_binding_count: 1,
            preflight: Some(Preflight {
                revision: 2,
                state,
                signing: KeyStatus::Ready,
                self_encryption: KeyStatus::Ready,
                recipients: vec![RecipientReadiness {
                    address: "bob@example.test".into(),
                    state: KeyStatus::Ready,
                    requirement: Requirement::Optional,
                }],
                reasons: Vec::new(),
                plan: None,
            }),
        }
    }
    #[test]
    fn selected_protection_preflight_reports_intent_and_snapshot_without_completion_claim() {
        let mut page = model();
        page.protection = ProtectionIntent {
            sign: true,
            encrypt: true,
            encrypt_to_self: true,
            binding_revision: Some(2),
        };
        page.openpgp = Some(capability(PreflightState::Green));
        let html = render(&page);
        assert!(html.contains("<dt>Signing</dt><dd>Requested</dd>"));
        assert!(html.contains("<dt>Encryption</dt><dd>Requested</dd>"));
        assert!(html.contains("<dt>Encrypt to self</dt><dd>Requested</dd>"));
        assert!(html.contains("Public keys eligible in the saved-draft snapshot"));
        assert!(html.contains("This check does not sign, encrypt or send"));
        assert!(!html.contains("Signing and encryption are unavailable"));
        assert!(!html.contains("This message is unsigned and not encrypted"));
    }
    #[test]
    fn defaults_blocked_and_missing_capability_do_not_hide_selection_or_claim_ready() {
        let mut page = model();
        page.openpgp = Some(capability(PreflightState::Blocked));
        let html = render(&page);
        assert!(html.contains("<dt>Signing</dt><dd>Not requested</dd>"));
        assert!(html.contains("Blocked by the current public-key or protection-policy checks"));
        assert!(!html.contains("Public keys eligible"));
        page.openpgp = None;
        page.protection.sign = true;
        let html = render(&page);
        assert!(html.contains("<dt>Signing</dt><dd>Requested</dd>"));
        assert!(html.contains("OpenPGP capability could not be established on this page"));
        assert!(!html.contains("Public keys eligible"));
    }
    #[test]
    fn absent_recipients_are_a_composition_error_not_a_private_crypto_failure() {
        let mut page = model();
        page.to_value = "";
        let mut view = capability(PreflightState::Green);
        view.preflight.as_mut().unwrap().recipients.clear();
        page.openpgp = Some(view);
        let html = render(&page);
        assert!(html.contains("Edit this draft before sending"));
        assert!(html.contains("No recipient addresses checked. Add recipients"));
        assert!(!html.contains("Public keys eligible"));
        assert!(!html.contains("Signing and encryption are unavailable"));
        page.preflight = false;
        assert!(render(&page).is_empty());
    }
}
