//! Independent native preference and conservative post-Archive navigation.
use super::*;
use crate::after_archive::{Choice, Error};
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_after_archive_settings(
        &self,
        r: &HttpRequest,
        c: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (s, mut audit_events) = match self.require_validated_session(r, c) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let form =
            allows_urlencoded_request_body(r.headers.get("content-type").map(String::as_str))
                .then(|| parse_urlencoded_form(&r.body, 3, 1024).ok())
                .flatten();
        let Some(f) = form else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid after-archive choice",
                    "<p>Reload Reading settings before saving.</p>",
                ),
                audit_events,
            };
        };
        if let Some(e) = self.require_valid_csrf(r, f.get("csrf_token").map(String::as_str), &s, c)
        {
            return e;
        }
        let revision = f
            .get("revision")
            .and_then(|v| v.parse::<u64>().ok().filter(|n| n.to_string() == *v));
        let choice = f.get("choice").and_then(|v| Choice::parse(v));
        let result = if f
            .keys()
            .any(|k| !matches!(k.as_str(), "csrf_token" | "revision" | "choice"))
        {
            Err(Error::Invalid)
        } else {
            match (revision, choice) {
                (Some(v), Some(choice)) => self.gateway.save_after_archive(&s, v, choice),
                _ => Err(Error::Invalid),
            }
        };
        audit_events.push(build_http_info_event(
            if result.is_ok() {
                "after_archive_preference_saved"
            } else {
                "after_archive_preference_unconfirmed"
            },
            "after-archive preference evaluated",
            c,
        ));
        let response=match result{Ok(_)=>redirect_response(303,"See Other","/settings?section=reading"),Err(e)=>html_response(if e==Error::Invalid{400}else if e==Error::Stale{409}else{503},"Preference Not Confirmed","After-archive choice not confirmed",TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell standalone-notice\"><section class=\"panel\"><h1>After-archive choice not confirmed</h1><p>Your submitted choice is retained. Reload saved settings before another change.</p><fieldset disabled><label>After archive<input value=\"{}\"></label><label>Revision<input value=\"{}\"></label></fieldset><a href=\"/settings?section=reading\">Load saved Reading settings</a></section></main>",crate::http_ui::app_header(&s.record.canonical_username,&s.record.csrf_token,"settings-reading"),escape_html(f.get("choice").map(String::as_str).unwrap_or("")),escape_html(f.get("revision").map(String::as_str).unwrap_or(""))))) };
        HandledHttpResponse {
            response,
            audit_events,
        }
    }
    pub(super) fn archive_navigation_rows(
        &self,
        c: &AuthenticationContext,
        s: &ValidatedSession,
        current: &MessageMoveRequest,
        back: &str,
        audit: &mut Vec<LogEvent>,
    ) -> Option<Vec<MessageSummary>> {
        let prefs = self.gateway.load_reading_preferences(c, s).ok()?;
        let outcome = self
            .gateway
            .list_messages(c, s, &current.source_mailbox_name);
        audit.extend(outcome.audit_events);
        let (mut rows, mut view) = verified_rows(
            &s.record.canonical_username,
            current,
            back,
            prefs,
            outcome.decision,
        )?;
        let projection = self.gateway.snooze_project(
            s,
            &s.record.canonical_username,
            &current.source_mailbox_name,
            &rows,
        );
        if projection.unavailable.is_some() {
            return None;
        }
        rows.retain(|row| {
            !projection.hidden.iter().any(|id| {
                crate::snooze::MessageIdentity::from_summary(
                    &s.record.canonical_username,
                    &s.record.canonical_username,
                    &current.source_mailbox_name,
                    row,
                )
                .is_ok_and(|v| v == *id)
            })
        });
        view.apply_messages(&mut rows);
        Some(rows)
    }
}
fn verified_rows(
    account: &str,
    current: &MessageMoveRequest,
    back: &str,
    prefs: crate::reading_preferences::ReadingPreferences,
    decision: BrowserMessageListDecision,
) -> Option<(Vec<MessageSummary>, crate::mail_list::ListViewState)> {
    let safe = crate::mail_navigation::safe_mail_return(back)?;
    let (path, query) = safe.split_once('?')?;
    if path != "/mailbox" {
        return None;
    }
    let mut fields = parse_urlencoded_form(query.as_bytes(), 16, 2048).ok()?;
    if fields.get("name")? != &current.source_mailbox_name
        || fields.get("q").is_some_and(|q| !q.is_empty())
        || fields.get("scope").is_some_and(|s| s != "mailbox")
    {
        return None;
    }
    if !fields.contains_key("sort") && !fields.contains_key("dir") {
        fields.insert("sort".into(), "received".into());
        fields.insert(
            "dir".into(),
            if prefs.date_order == crate::reading_preferences::DateOrder::Newest {
                "desc"
            } else {
                "asc"
            }
            .into(),
        );
    }
    let BrowserMessageListDecision::Listed {
        canonical_username,
        mailbox_name,
        messages,
    } = decision
    else {
        return None;
    };
    if canonical_username != account
        || mailbox_name != current.source_mailbox_name
        || messages.len() > crate::mailbox::DEFAULT_MAX_MESSAGES
    {
        return None;
    }
    let mut uids = std::collections::BTreeSet::new();
    let mut ids = std::collections::BTreeSet::new();
    for row in &messages {
        let version = &row.metadata.as_ref()?.version;
        if row.mailbox_name != mailbox_name
            || row.uid == 0
            || row.uid > u64::from(u32::MAX)
            || row.flags.len() > 256
            || row.flags.iter().map(String::len).sum::<usize>() > 256
            || row.flags.iter().any(|flag| {
                flag.is_empty() || flag.chars().any(|ch| ch.is_control() || ch.is_whitespace())
            })
            || !uids.insert(row.uid)
            || !ids.insert(&version.message_guid)
            || version.mailbox_guid != current.version.mailbox_guid
            || crate::message_metadata::MessageVersion::new(
                version.mailbox_guid.clone(),
                version.message_guid.clone(),
            )
            .as_ref()
                != Ok(version)
            || crate::mailbox::parse_received_timestamp(&row.date_received).is_none()
        {
            return None;
        }
    }
    let view = crate::mail_list::ListViewState::from_query(&fields).ok()?;
    Some((messages, view))
}
pub(super) fn next_candidate(
    rows: &[MessageSummary],
    current: &MessageMoveRequest,
) -> Option<MessageSummary> {
    let index = rows.iter().position(|r| {
        r.uid == current.uid
            && r.metadata
                .as_ref()
                .is_some_and(|m| m.version == current.version)
    })?;
    rows.get(index + 1).cloned()
}
pub(super) fn candidate_link(
    rows: &[MessageSummary],
    candidate: &MessageSummary,
    back: &str,
) -> Option<String> {
    let version = &candidate.metadata.as_ref()?.version;
    let exact = rows.iter().find(|r| {
        r.uid == candidate.uid
            && r.mailbox_name == candidate.mailbox_name
            && r.metadata.as_ref().is_some_and(|m| &m.version == version)
    })?;
    Some(format!(
        "/message?mailbox={}&uid={}&mailbox_guid={}&message_guid={}&return_to={}",
        url_encode(&exact.mailbox_name),
        exact.uid,
        url_encode(&version.mailbox_guid),
        url_encode(&version.message_guid),
        url_encode(back)
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn after_archive_order_context_and_changed_neighbour() {
        let version = |uid| {
            crate::message_metadata::MessageVersion::new("a".repeat(32), format!("m{uid}")).unwrap()
        };
        let current = MessageMoveRequest::new(
            MessageMovePolicy::default(),
            "INBOX",
            "Archive",
            2,
            version(2),
        )
        .unwrap();
        let rows: Vec<_> = (1..=3)
            .map(|uid| MessageSummary {
                to: None,
                metadata: Some(crate::message_metadata::MessageMetadata {
                    version: version(uid),
                    attachment_count: Some(0),
                    preview: None,
                }),
                mailbox_name: "INBOX".into(),
                uid,
                flags: vec![],
                date_received: format!("2026-09-0{uid} 00:00:00 +0000"),
                size_virtual: 0,
                subject: None,
                from: None,
            })
            .collect();
        let validate = |messages| {
            verified_rows(
                "alice@example.com",
                &current,
                "/mailbox?name=INBOX",
                crate::reading_preferences::ReadingPreferences::default(),
                BrowserMessageListDecision::Listed {
                    canonical_username: "alice@example.com".into(),
                    mailbox_name: "INBOX".into(),
                    messages,
                },
            )
            .is_some()
        };
        assert!(validate(rows.clone()));
        for case in 0..8 {
            let mut bad = rows.clone();
            match case {
                0 => bad[0].uid = u64::from(u32::MAX) + 1,
                1 => bad[0].flags = vec![String::new()],
                2 => bad[0].flags = vec!["bad flag".into()],
                3 => bad[0].flags = vec!["bad\u{7f}flag".into()],
                4 => bad[0].flags = vec!["x".repeat(257)],
                5 => bad[0].flags = vec!["x".into(); 257],
                6 => bad[0].uid = bad[1].uid,
                _ => bad[0].metadata.as_mut().unwrap().version.mailbox_guid = "b".repeat(32),
            }
            assert!(!validate(bad), "refusal case {case}");
        }
        let project = |back: &str, prefs| {
            let (mut rows, mut view) = verified_rows(
                "alice@example.com",
                &current,
                back,
                prefs,
                BrowserMessageListDecision::Listed {
                    canonical_username: "alice@example.com".into(),
                    mailbox_name: "INBOX".into(),
                    messages: rows.clone(),
                },
            )?;
            view.apply_messages(&mut rows);
            Some(rows)
        };
        let prefs = crate::reading_preferences::ReadingPreferences {
            date_order: crate::reading_preferences::DateOrder::Oldest,
            ..Default::default()
        };
        let oldest = project("/mailbox?name=INBOX", prefs).unwrap();
        assert_eq!(next_candidate(&oldest, &current).unwrap().uid, 3);
        let explicit = project(
            "/mailbox?name=INBOX&sort=uid&dir=desc&filter=unread&page=1",
            prefs,
        )
        .unwrap();
        let candidate = next_candidate(&explicit, &current).unwrap();
        assert_eq!(candidate.uid, 1);
        let back = "/mailbox?name=INBOX&filter=unread&page=1";
        assert!(candidate_link(&explicit, &candidate, back)
            .unwrap()
            .contains(&url_encode(back)));
        let mut changed = explicit.clone();
        changed
            .iter_mut()
            .find(|r| r.uid == 1)
            .unwrap()
            .metadata
            .as_mut()
            .unwrap()
            .version = version(100);
        assert!(candidate_link(&changed, &candidate, back).is_none());
        for bad in [
            "/search?q=x",
            "/mailbox?name=Foreign",
            "/mailbox?name=INBOX&q=x",
        ] {
            assert!(project(bad, prefs).is_none());
        }
    }
}
