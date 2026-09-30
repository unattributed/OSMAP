use super::*;
use crate::message_metadata::MessageMetadata;
use std::collections::BTreeSet;

#[derive(Debug, Default)]
pub(super) struct SyntheticMessageMoves {
    removed: BTreeSet<(String, String, u64)>,
    added: BTreeMap<(String, String, u64), MessageSummary>,
    sequence: u64,
}

impl StubGateway {
    pub(super) fn fixture_added_message(
        &self,
        username: &str,
        mailbox: &str,
        uid: u64,
    ) -> Option<MessageSummary> {
        self.message_moves
            .lock()
            .expect("synthetic moves")
            .added
            .get(&(username.into(), mailbox.into(), uid))
            .cloned()
    }
    pub(super) fn fixture_message_removed(&self, username: &str, mailbox: &str, uid: u64) -> bool {
        self.message_moves
            .lock()
            .expect("synthetic moves")
            .removed
            .contains(&(username.into(), mailbox.into(), uid))
    }
    pub(super) fn fixture_current_metadata(
        &self,
        username: &str,
        mailbox: &str,
        uid: u64,
    ) -> Option<MessageMetadata> {
        let state = self.message_moves.lock().expect("synthetic moves");
        let key = (username.into(), mailbox.into(), uid);
        if state.removed.contains(&key) {
            return None;
        }
        state
            .added
            .get(&key)
            .and_then(|row| row.metadata.clone())
            .or_else(|| {
                (uid > 0 && uid <= 125).then(|| Self::fixture_metadata(username, mailbox, uid))
            })
    }

    pub(super) fn fixture_reconcile_messages(
        &self,
        username: &str,
        mailbox: &str,
        mut messages: Vec<MessageSummary>,
    ) -> Vec<MessageSummary> {
        let state = self.message_moves.lock().expect("synthetic moves");
        messages.retain(|row| {
            !state
                .removed
                .contains(&(username.into(), mailbox.into(), row.uid))
        });
        messages.extend(
            state
                .added
                .iter()
                .filter(|((account, folder, _), _)| account == username && folder == mailbox)
                .map(|(_, row)| row.clone()),
        );
        messages
    }

    pub(super) fn set_fixture_message_move(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        request: &MessageMoveRequest,
    ) -> BrowserMessageMoveOutcome {
        let user = &session.record.canonical_username;
        let denied = |reason: &str, retry_after_seconds| BrowserMessageMoveOutcome {
            decision: BrowserMessageMoveDecision::Denied {
                public_reason: reason.into(),
                retry_after_seconds,
            },
            audit_events: Vec::new(),
        };
        if context.user_agent.contains("MoveThrottled") {
            return denied(TOO_MANY_MESSAGE_MOVES_PUBLIC_REASON, Some(180));
        }
        if context.user_agent.contains("MoveUnknown") && request.uid == 10 {
            return denied("message_move_unknown", None);
        }
        if context.user_agent.contains("MoveBusy") {
            return denied("message_move_busy", None);
        }
        if context.user_agent.contains("MoveUnavailable") {
            return denied("message_move_unavailable", None);
        }
        if (request.source_mailbox_name == "Junk" && request.uid == 9)
            || self
                .fixture_current_metadata(user, &request.source_mailbox_name, request.uid)
                .map(|m| m.version)
                != Some(request.version.clone())
        {
            return denied("message_move_stale", None);
        }
        let flags = self.fixture_message_flags(user, &request.source_mailbox_name, request.uid);
        let mut state = self.message_moves.lock().expect("synthetic moves");
        let source = (
            user.clone(),
            request.source_mailbox_name.clone(),
            request.uid,
        );
        if state.removed.contains(&source) {
            return denied("message_move_stale", None);
        }
        let previous = state.added.remove(&source);
        let mut metadata = previous
            .as_ref()
            .and_then(|row| row.metadata.clone())
            .unwrap_or_else(|| {
                Self::fixture_metadata(user, &request.source_mailbox_name, request.uid)
            });
        metadata.version.mailbox_guid =
            Self::fixture_metadata(user, &request.destination_mailbox_name, 1)
                .version
                .mailbox_guid;
        state.removed.insert(source);
        state.sequence += 1;
        let new_uid = 1000 + state.sequence;
        state.added.insert(
            (
                user.clone(),
                request.destination_mailbox_name.clone(),
                new_uid,
            ),
            MessageSummary {
                to: None,
                metadata: Some(metadata),
                mailbox_name: request.destination_mailbox_name.clone(),
                uid: new_uid,
                flags: flags.clone(),
                date_received: "2026-09-30 00:00:00 +0000".into(),
                size_virtual: 1024,
                subject: previous
                    .as_ref()
                    .and_then(|row| row.subject.clone())
                    .or_else(|| Some(format!("Message {:03}", request.uid))),
                from: Some("Synthetic Sender <sender@example.test>".into()),
            },
        );
        drop(state);
        self.message_flags.lock().expect("synthetic flags").insert(
            (
                user.clone(),
                request.destination_mailbox_name.clone(),
                new_uid,
            ),
            flags,
        );
        BrowserMessageMoveOutcome {
            decision: BrowserMessageMoveDecision::Moved {
                source_mailbox_name: request.source_mailbox_name.clone(),
                destination_mailbox_name: request.destination_mailbox_name.clone(),
                uid: request.uid,
            },
            audit_events: vec![LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                "stub_message_move",
                "synthetic message moved",
            )],
        }
    }
}

/// Upgrade retained baseline test forms to the mandatory identity contract.
/// Separate negative cases send legacy forms verbatim and prove refusal.
pub(super) fn move_form(body: &str, action: &str) -> String {
    let mut form =
        parse_urlencoded_form(body.as_bytes(), 30, 16384).expect("baseline synthetic form");
    let mailbox = form.get("mailbox").cloned().unwrap_or_default();
    form.insert("action".into(), action.into());
    form.insert(
        "return_to".into(),
        format!("/mailbox?name={}", url_encode(&mailbox)),
    );
    if let Some(uid) = form.get("uid") {
        let version =
            StubGateway::fixture_metadata("alice@example.com", &mailbox, uid.parse().unwrap_or(9))
                .version;
        form.insert("mailbox_guid".into(), version.mailbox_guid);
        form.insert("message_guid".into(), version.message_guid);
    }
    let selected: Vec<_> = form
        .keys()
        .filter(|key| key.starts_with("uid_"))
        .cloned()
        .collect();
    for key in selected {
        let value = form.remove(&key).unwrap();
        let uid = value.parse().unwrap_or(9);
        let version = StubGateway::fixture_metadata("alice@example.com", &mailbox, uid).version;
        form.insert(
            format!("message_{uid}"),
            format!("{uid}|{}|{}", version.mailbox_guid, version.message_guid),
        );
    }
    form.iter()
        .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}
