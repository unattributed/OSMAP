//! PAGE-01 welcome surface. Only supplied mailbox identities are projected.
use super::*;

pub(crate) struct WelcomeAccountState<'a> {
    pub openpgp: &'a crate::key_management::State,
    pub defaults: Option<crate::composition_preferences::OpenPgpDefaults>,
    pub storage: Option<&'a crate::storage_ui::StorageView>,
    pub notices: Option<(
        &'a crate::notifications::NotificationInbox,
        Option<&'a crate::notification_preferences::Preference>,
    )>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_mailboxes_page_with_storage(
    canonical_username: &str,
    csrf_token: &str,
    mailboxes: &[MailboxEntry],
    summaries: (Option<&[MessageSummary]>, Option<&str>),
    draft_count: Option<usize>,
    sent_count: Option<usize>,
    _activity: &crate::http::BrowserSessionListDecision,
    open_on_select: bool,
    account_state: WelcomeAccountState<'_>,
) -> TrustedHtml {
    let activity = notice_activity(account_state.notices);
    let openpgp = (account_state.openpgp, account_state.defaults);
    let header = app_header_with_storage(
        canonical_username,
        csrf_token,
        "mailboxes",
        account_state.storage,
    );
    let storage = crate::storage_ui::render_dashboard(canonical_username, account_state.storage);
    let (summaries, snooze_notice) = summaries;
    let key_summary = openpgp_summary(canonical_username, openpgp.0, openpgp.1);
    let has = |name: &str| mailboxes.iter().any(|mailbox| mailbox.name == name);
    let inbox = has("INBOX");
    let sent = has("Sent");
    let unread = summaries.map(|rows| {
        rows.iter()
            .filter(|row| !has_flag(&row.flags, "\\Seen"))
            .count()
    });
    let flagged = summaries.map(|rows| {
        rows.iter()
            .filter(|row| has_flag(&row.flags, "\\Flagged"))
            .count()
    });
    let mut metrics = String::new();
    for (label, icon, destination, count) in [
        (
            "Unread · loaded Inbox",
            "inbox",
            inbox.then_some("/mailbox?name=INBOX&filter=unread"),
            unread,
        ),
        ("Saved drafts", "drafts", Some("/drafts"), draft_count),
        (
            "Sent · loaded messages",
            "sent",
            sent.then_some("/mailbox?name=Sent"),
            sent_count,
        ),
        (
            "Flagged · loaded Inbox",
            "folders",
            inbox.then_some("/mailbox?name=INBOX&filter=starred"),
            flagged,
        ),
    ] {
        let value = count
            .map(|value| value.to_string())
            .unwrap_or_else(|| "Unknown".into());
        let contents = format!("<span class=\"welcome-icon\">{}</span><span><strong>{value}</strong><span>{label}</span></span>", shell_icon(icon));
        metrics.push_str(&if let Some(href) = destination {
            format!("<a class=\"welcome-metric\" href=\"{}\" aria-label=\"{label}: {value}; open list\">{contents}</a>", escape_html(href))
        } else { format!("<div class=\"welcome-metric\">{contents}</div>") });
    }
    let recent = format!(
        "{}{}",
        snooze_notice
            .filter(|text| !text.is_empty())
            .map(|text| format!(
                "<p class=welcome-note role=status>{}</p>",
                escape_html(text)
            ))
            .unwrap_or_default(),
        recent_rows(summaries, inbox, csrf_token, open_on_select)
    );
    let mut shortcuts = String::new();
    for (label, description, icon, href) in [
        ("Compose", "New message", "compose", Some("/compose")),
        (
            "Inbox",
            if inbox {
                "View messages"
            } else {
                "Mailbox unavailable"
            },
            "inbox",
            inbox.then_some("/mailbox?name=INBOX"),
        ),
        (
            "Folders",
            "Browse and manage mail folders",
            "folders",
            Some("/folders"),
        ),
        (
            "Security",
            "Account protection",
            "shield",
            Some("/settings?section=security"),
        ),
        (
            "Settings",
            "Account & preferences",
            "settings",
            Some("/settings"),
        ),
    ] {
        // Archive / Bin occupies its approved position between Folders and Security.
        if label == "Security" {
            shortcuts.push_str(&format!("<details class=\"welcome-shortcut welcome-shortcut-menu\"><summary><span class=\"welcome-icon\">{}</span><span><strong>Archive / Bin</strong><span>Mailbox shortcuts</span></span></summary><div><a href=\"/mailbox/shortcut?kind=archive\">Open configured Archive</a>{}</div></details>", shell_icon("archive"), "<a href=\"/mailbox/shortcut?kind=bin\">Open Bin</a>"));
        }
        let content = format!("<span class=\"welcome-icon\">{}</span><span><strong>{label}</strong><span>{description}</span></span>", shell_icon(icon));
        shortcuts.push_str(&match href {
            Some(href) => format!("<a class=\"welcome-shortcut\" href=\"{href}\">{content}</a>"),
            None => format!("<div class=\"welcome-shortcut welcome-unavailable\" aria-disabled=\"true\">{content}</div>"),
        });
    }
    let mut folders = String::new();
    for mailbox in mailboxes.iter().take(DEFAULT_RENDERED_MAILBOXES_MAX) {
        folders.push_str(&format!("<li><a href=\"/mailbox?name={}\"><span class=\"welcome-folder-icon\">{}</span><strong>{}</strong><span class=\"welcome-folder-open\">Open mailbox <span aria-hidden=\"true\">→</span></span></a></li>", escape_html(&url_encode(&mailbox.name)), shell_icon(if mailbox.name == "INBOX" { "inbox" } else { "folders" }), escape_html(&mailbox.name)));
    }
    if folders.is_empty() {
        folders.push_str(
            "<li class=\"welcome-empty\">No visible mailboxes were returned for this account.</li>",
        );
    }
    let limit = if mailboxes.len() > DEFAULT_RENDERED_MAILBOXES_MAX {
        format!("<p class=\"welcome-note\">Mailbox list display limit reached: showing first {} of {} visible mailboxes.</p>", DEFAULT_RENDERED_MAILBOXES_MAX, mailboxes.len())
    } else {
        String::new()
    };
    let view_all = if inbox {
        "<a href=\"/mailbox?name=INBOX\">Open Inbox <span aria-hidden=\"true\">→</span></a>"
    } else {
        "<a href=\"#welcome-mailboxes\">Browse mailboxes</a>"
    };
    let imported_keys = (openpgp.0.canonical_username == canonical_username
        && openpgp
            .0
            .bindings
            .as_ref()
            .is_none_or(|record| record.ensure_account(canonical_username).is_ok()))
    .then(|| {
        openpgp
            .0
            .inventory
            .as_ref()
            .and_then(|inventory| inventory.keys())
    })
    .flatten();
    let public_key_status = match imported_keys {
        Some([]) => "No public keys imported".into(),
        Some([_]) => "1 imported public key".into(),
        Some(keys) => format!("{} imported public keys", keys.len()),
        None => "Public key status unavailable".into(),
    };
    let mut system = String::new();
    for (label, icon, status) in [
        ("Mail server", "inbox", "Mailbox access verified"),
        ("OpenPGP", "shield", public_key_status.as_str()),
        ("Security services", "shield", "OSMAP session verified"),
        ("Backup", "archive", "Not reported by OSMAP"),
        ("System updates", "settings", "Not checked by OSMAP"),
    ] {
        system.push_str(&format!(
            "<li><span>{}{label}</span><span>{}</span></li>",
            shell_icon(icon),
            escape_html(status)
        ));
    }
    let search = format!("<details class=\"welcome-search\"><summary>Search all mailboxes</summary><form class=\"search-row\" method=\"get\" action=\"/search\"><label for=\"mailbox-global-search\">Search all mailboxes<input id=\"mailbox-global-search\" type=\"text\" name=\"q\" autocomplete=\"off\" maxlength=\"256\" required></label>{}<button type=\"submit\">Search</button></form></details>", render_search_field_select(MessageSearchField::All));
    TrustedHtml::from_template(format!(concat!(
        "{header}<main id=\"main-content\" class=\"page-shell welcome-page\" tabindex=\"-1\">",
        "<section class=\"welcome-intro\" aria-labelledby=\"mailboxes-title\"><div class=\"welcome-greeting\"><h1 id=\"mailboxes-title\">Welcome back.</h1><p>Choose a mailbox to get started.</p><p class=\"welcome-account\">Signed in as <strong>{account}</strong></p></div><div class=\"welcome-metrics\" aria-label=\"Message counts and scope\">{metrics}</div></section>",
        "<nav class=\"welcome-shortcuts\" aria-label=\"Workspace shortcuts\">{shortcuts}</nav>",
        "<div class=\"welcome-primary-grid\"><section class=\"welcome-panel welcome-messages\" aria-labelledby=\"welcome-messages-title\"><div class=\"welcome-panel-heading\"><h2 id=\"welcome-messages-title\">Recent Messages</h2>{view_all}</div>{recent}<details class=\"welcome-browse\"><summary id=\"welcome-mailboxes\">Browse your mailboxes</summary><div class=\"welcome-folder-scroll\" tabindex=\"0\" role=\"region\" aria-labelledby=\"welcome-mailboxes\"><ul>{folders}</ul></div>{limit}</details></section>",
        "<section class=\"welcome-panel welcome-account-security\" aria-labelledby=\"welcome-security-title\"><div class=\"welcome-panel-heading\"><h2 id=\"welcome-security-title\">Account Security</h2></div><div class=\"welcome-protection\">{shield}<div><strong>Protected by Default</strong><p>Remote images and active content are blocked.</p></div></div><div class=\"welcome-security-detail\"><h3>Authenticated session</h3><p>Password and TOTP were required at sign-in.</p><a href=\"/sessions\">Manage sessions <span aria-hidden=\"true\">→</span></a></div></section>",
        "{key_summary}</div>",
        "<div class=\"welcome-secondary-grid\"><section class=\"welcome-panel welcome-activity\" aria-labelledby=\"welcome-activity-title\"><div class=\"welcome-panel-heading\"><h2 id=\"welcome-activity-title\">Recent Activity</h2></div>{activity_rows}</section>",
        "<div class=\"welcome-middle-stack\"><section class=\"welcome-panel welcome-actions\" aria-labelledby=\"welcome-actions-title\"><div class=\"welcome-panel-heading\"><h2 id=\"welcome-actions-title\">Quick Actions</h2></div><div class=\"welcome-action-grid\"><a href=\"/search\">{search_icon}<strong>Search</strong><span>Find messages</span></a><a href=\"{filter_target}\">{filter_icon}<strong>Filters</strong><span>{filter_description}</span></a><a href=\"/labels\">{label_icon}<strong>Labels</strong><span>Organize messages</span></a><details><summary>{more_icon}<strong>More</strong><span>Available tools</span></summary><div><a href=\"/contacts\">Contacts</a><a href=\"/sessions\">Sessions</a><a href=\"/drafts\">Saved drafts</a></div></details></div>{search}</section>",
        "<section class=\"welcome-panel welcome-storage\" aria-labelledby=\"welcome-storage-title\"><div class=\"welcome-panel-heading\"><h2 id=\"welcome-storage-title\">Storage Usage</h2></div><div class=\"welcome-storage-body\">{storage}</div></section></div>",
        "<section class=\"welcome-panel welcome-system\" aria-labelledby=\"welcome-system-title\"><div class=\"welcome-panel-heading\"><h2 id=\"welcome-system-title\">System Status</h2></div><ul>{system}</ul><details><summary>View status details</summary><p class=\"welcome-note\">Checks apply to <strong>{account}</strong> at page load. Mailbox listing does not verify SMTP or message delivery. Public key inventory does not verify private-key readiness. Session verification does not report every security service. OSMAP does not report host backup or system-update results.</p></details></section></div>",
        "<footer class=\"welcome-footer\"><span>OSMAP · Secure by Design. Private by Default.</span><span>Limited status checks</span><span aria-disabled=\"true\">Help unavailable</span><span aria-disabled=\"true\">Feedback unavailable</span></footer></main>"
    ), header=header, account=escape_html(canonical_username), metrics=metrics, recent=recent, shortcuts=shortcuts, view_all=view_all, folders=folders, limit=limit, shield=shell_icon("shield"), key_summary=key_summary, activity_rows=activity, search_icon=shell_icon("search"), filter_icon=shell_icon("inbox"), label_icon=shell_icon("drafts"), more_icon=shell_icon("menu"), filter_target=if inbox { "/mailbox?name=INBOX&filter=unread" } else { "/search" }, filter_description=if inbox { "Unread in Inbox" } else { "Search mail" }, search=search, system=system, storage=storage))
}

fn openpgp_summary(
    account: &str,
    state: &crate::key_management::State,
    defaults: Option<crate::composition_preferences::OpenPgpDefaults>,
) -> String {
    let record = (state.canonical_username == account)
        .then_some(state.bindings.as_ref())
        .flatten()
        .filter(|record| record.ensure_account(account).is_ok());
    let binding = record.and_then(|record| record.account_binding.as_ref());
    let keys = state
        .inventory
        .as_ref()
        .and_then(|inventory| inventory.keys());
    let now = crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider);
    let status = match (record, binding, keys) {
        (None, _, _) => "Account key status unavailable",
        (Some(_), _, None) => "Public inventory unavailable",
        (Some(_), None, Some(_)) => "No account key selected",
        (Some(_), Some(binding), Some(keys)) => {
            match keys
                .iter()
                .find(|key| key.primary.fingerprint == binding.primary_fingerprint)
            {
                None => "Selected account key missing",
                Some(_) if now == 0 => "Account key status unavailable",
                Some(key)
                    if key.primary.revoked
                        || key.primary.expired
                        || key.primary.disabled
                        || key.primary.invalid
                        || key.primary.created > now
                        || key.primary.expires != 0 && key.primary.expires <= now =>
                {
                    "Account key needs attention"
                }
                Some(_) => "Account key configured",
            }
        }
    };
    let fingerprint = binding
        .map(|binding| format!("<code>{}</code>", escape_html(&binding.primary_fingerprint),))
        .unwrap_or_else(|| {
            if record.is_some() {
                "Not configured"
            } else {
                "Unavailable"
            }
            .into()
        });
    let policy = |requirement, selected| match requirement {
        crate::openpgp_bindings::Requirement::Required => "Required",
        crate::openpgp_bindings::Requirement::Disabled => "Disabled",
        crate::openpgp_bindings::Requirement::Optional => match selected {
            Some(true) => "Optional; on by default",
            Some(false) => "Optional; off by default",
            None => "Optional; compose default unavailable",
        },
    };
    let signing = record
        .map(|record| policy(record.policy.signing, defaults.map(|value| value.sign)))
        .unwrap_or("Unavailable");
    let encryption = record
        .map(|record| {
            policy(
                record.policy.encryption,
                defaults.map(|value| value.encrypt),
            )
        })
        .unwrap_or("Unavailable");
    let self_default = match defaults {
        Some(value) if value.encrypt_to_self => "On by default; choose per message",
        Some(_) => "Off by default; choose per message",
        None => "Compose default unavailable; choose per message",
    };
    format!(concat!(
        "<section class=\"welcome-panel welcome-openpgp\" aria-labelledby=\"welcome-openpgp-title\"><div class=\"welcome-panel-heading\"><h2 id=\"welcome-openpgp-title\">OpenPGP Status</h2></div>",
        "<div class=\"welcome-key-state\">{}<div><strong>{status}</strong><p>Public metadata only; private-key readiness is checked when an operation runs.</p></div></div>",
        "<dl class=\"welcome-key-details\"><div><dt>Saved account fingerprint</dt><dd>{fingerprint}</dd></div><div><dt>Signing</dt><dd>{signing}</dd></div><div><dt>Encryption</dt><dd>{encryption}</dd></div><div><dt>Encrypt-to-self</dt><dd>{self_default}</dd></div></dl>",
        "<a class=\"button-link\" href=\"/settings/keys\">Manage Keys</a></section>"
    ), shell_icon("shield"), status=status, fingerprint=fingerprint, signing=signing, encryption=encryption, self_default=self_default)
}

fn recent_rows(
    summaries: Option<&[MessageSummary]>,
    inbox: bool,
    csrf: &str,
    on_open: bool,
) -> String {
    let Some(rows) = summaries else {
        return format!(
            "<p class=\"welcome-note\">{}</p>",
            if inbox {
                "Inbox summaries are unavailable. Open Inbox to try again."
            } else {
                "Inbox is unavailable for this account."
            }
        );
    };
    let mut html = format!("<p class=\"welcome-note\">Newest from {} loaded Inbox messages. Counts cover this loaded set; additional messages may exist.</p>", rows.len());
    if rows.is_empty() {
        html.push_str("<p class=\"welcome-empty\">No messages were returned from Inbox.</p>");
    }
    html.push_str("<ul class=\"welcome-recent\">");
    for row in rows.iter().take(5) {
        let mut href = format!(
            "/message?mailbox={}&uid={}",
            url_encode(&row.mailbox_name),
            row.uid
        );
        if let Some(metadata) = &row.metadata {
            href.push_str(&format!(
                "&mailbox_guid={}&message_guid={}",
                url_encode(&metadata.version.mailbox_guid),
                url_encode(&metadata.version.message_guid)
            ));
        }
        let sender = row.from.as_deref().unwrap_or("Sender unavailable");
        let subject = row
            .subject
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("(No subject)");
        let contents = TrustedHtml::from_template(format!("<span class=\"message-avatar\" aria-hidden=\"true\">{}</span><span class=\"welcome-recent-sender\" title=\"{}\">{}</span><span class=\"welcome-recent-subject\" title=\"{}\">{}</span><span class=\"welcome-recent-date\" title=\"{}\">{}</span><span class=\"welcome-recent-flags\"><span class=\"sr-only\">{}</span><span aria-label=\"{}\">{}</span></span>", escape_html(&sender_initials(row.from.as_deref())), escape_html(sender), escape_html(sender), escape_html(subject), escape_html(subject), escape_html(&row.date_received), escape_html(row.date_received.split_whitespace().next().unwrap_or("Date unavailable")), if has_flag(&row.flags,"\\Seen") { "Read. " } else { "Unread. " }, if has_flag(&row.flags,"\\Flagged") { "Flagged" } else { "Not flagged" }, if has_flag(&row.flags,"\\Flagged") { "★" } else { "☆" }));
        let class = if has_flag(&row.flags, "\\Seen") {
            "welcome-recent-link"
        } else {
            "welcome-recent-link welcome-unread"
        };
        html.push_str(&format!(
            "<li>{}</li>",
            message_open_markup(csrf, &href, class, &contents, false, on_open, None)
        ));
    }
    html.push_str("</ul>");
    html
}

fn notice_activity(
    notices: Option<(
        &crate::notifications::NotificationInbox,
        Option<&crate::notification_preferences::Preference>,
    )>,
) -> String {
    let mut html = String::from("<p class=\"welcome-activity-scope\">Recent recorded account events. Submission acceptance does not confirm delivery.</p><ul class=\"welcome-activity-rows\">");
    match notices {
        None => html.push_str("<li>Account activity could not be loaded.</li>"),
        Some((inbox, preference)) => {
            let mut rows: Vec<_> = inbox
                .events
                .iter()
                .filter(|event| preference.is_none_or(|p| p.choices.allows(event.kind)))
                .collect();
            rows.sort_by_key(|event| std::cmp::Reverse(event.occurred_at));
            if rows.is_empty() {
                html.push_str("<li>No retained notices match your notification choices.</li>");
            }
            for event in rows.into_iter().take(5) {
                let time = crate::logging::format_unix_timestamp_utc(event.occurred_at);
                html.push_str(&format!("<li><span class=\"welcome-activity-dot\" aria-hidden=\"true\">•</span><strong>{}</strong><time datetime=\"{}\">{} UTC</time></li>", event.kind.title(), escape_html(&time), escape_html(time.replace('T', " ").trim_end_matches('Z'))));
            }
        }
    }
    html.push_str("</ul><a class=\"welcome-activity-link\" href=\"/notifications\">View all notifications →</a>");
    html
}

#[cfg(test)]
mod activity_tests {
    use super::*;
    use crate::http::BrowserSessionListDecision as Decision;

    #[test]
    fn recorded_activity_uses_generic_facts_and_preserves_mandatory_preferences() {
        use crate::notifications::{NotificationEvent, NotificationInbox, NotificationKind};
        let inbox = NotificationInbox {
            revision: 3,
            events: vec![
                NotificationEvent {
                    event_id: "a".repeat(32),
                    kind: NotificationKind::PasswordChanged,
                    occurred_at: 100,
                    read: true,
                },
                NotificationEvent {
                    event_id: "b".repeat(32),
                    kind: NotificationKind::NewMail,
                    occurred_at: 200,
                    read: false,
                },
            ],
        };
        let mut preference = crate::notification_preferences::Preference::default();
        preference.choices.new_mail = false;
        let html = notice_activity(Some((&inbox, Some(&preference))));
        assert!(html.contains("Account password changed"));
        assert!(!html.contains("New Inbox message"));
        assert!(!html.contains(&"a".repeat(32)));
        assert!(html.contains("href=\"/notifications\""));
        assert!(notice_activity(None).contains("could not be loaded"));
    }

    #[test]
    fn welcome_storage_projects_only_owned_values_and_offers_details() {
        let keys = crate::key_management::State {
            canonical_username: "alice".into(),
            inventory: None,
            bindings: None,
            binding_changes_available: false,
            public_key_changes_available: false,
            public_inventory_revision: None,
        };
        let storage = crate::storage_ui::StorageView::from_report(
            "alice",
            Some(crate::documents::MailStorageReport {
                account: "alice".into(),
                message_bytes: 12,
                configured_limit_bytes: Some(20),
            }),
        );
        let foreign = crate::storage_ui::StorageView::from_report(
            "bob",
            Some(crate::documents::MailStorageReport {
                account: "bob".into(),
                message_bytes: 987654,
                configured_limit_bytes: Some(1000000),
            }),
        );
        for (storage, measured) in [
            (Some(&storage), true),
            (None, false),
            (Some(&foreign), false),
        ] {
            let html = render_mailboxes_page_with_storage(
                "alice",
                "csrf",
                &[],
                (None, None),
                None,
                None,
                &Decision::Denied {
                    public_reason: "unavailable".into(),
                },
                false,
                WelcomeAccountState {
                    openpgp: &keys,
                    defaults: None,
                    storage,
                    notices: None,
                },
            );
            assert_eq!(html.as_str().contains("<p>12 bytes</p>"), measured);
            let rail = html
                .as_str()
                .split_once("class=\"rail-storage\"")
                .unwrap()
                .1
                .split_once("</section>")
                .unwrap()
                .0;
            assert_eq!(rail.contains("Messages: 12 bytes"), measured);
            assert_eq!(rail.contains("Configured quota: 20 bytes"), measured);
            assert!(rail.contains(">View storage</a>"));
            assert!(!rail.contains("Usage unavailable"));
            assert!(html.as_str().contains(if measured {
                "Mailbox messages"
            } else {
                "Mailbox storage"
            }));
            assert!(html.as_str().contains("Mail retention unavailable"));
            assert!(!html.as_str().contains("Documents"));
            assert!(html
                .as_str()
                .contains("href=\"/settings?section=general\">View storage details"));
            assert!(!html.as_str().contains("987654"));
            assert!(!html.as_str().contains("disabled>Manage Storage"));
            assert!(!html.as_str().contains("Usage and quota unknown"));
        }
    }
    #[test]
    fn welcome_recent_opening_preserves_card_markup_and_public_identity() {
        let mut message = MessageSummary {
            mailbox_name: "INBOX".into(),
            uid: 7,
            flags: vec![],
            date_received: "2026-10-03".into(),
            size_virtual: 10,
            subject: Some("<script> & subject".into()),
            from: Some("Sender <sender@example.test>".into()),
            to: None,
            metadata: Some(crate::message_metadata::MessageMetadata {
                threading: None,
                version: crate::message_metadata::MessageVersion::new(
                    "a".repeat(32),
                    "message-7".into(),
                )
                .unwrap(),
                attachment_count: None,
                attachments: None,
                protection: crate::message_metadata::MessageProtection::Unknown,
                preview: None,
            }),
        };
        let html = recent_rows(
            Some(std::slice::from_ref(&message)),
            true,
            "csrf&token",
            true,
        );
        assert!(html.contains("action=\"/message/open\""));
        assert!(html.contains("name=\"mailbox_guid\" value=\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""));
        assert!(html.contains("<span class=\"welcome-recent-subject\""));
        assert!(!html.contains("&lt;span"));
        assert!(html.contains("&lt;script&gt; &amp; subject"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<a "));
        assert!(
            recent_rows(Some(std::slice::from_ref(&message)), true, "csrf", false)
                .contains("<a class=\"welcome-recent-link welcome-unread\"")
        );
        message.metadata = None;
        let html = recent_rows(Some(&[message]), true, "csrf", true);
        assert!(html.contains("disabled>"));
        assert!(!html.contains("<form"));
        assert!(!html.contains("<a "));
    }
    #[test]
    fn recorded_activity_limits_to_newest_five_without_raw_ids() {
        use crate::notifications::{NotificationEvent, NotificationInbox, NotificationKind};
        let inbox = NotificationInbox {
            revision: 8,
            events: (1..=7)
                .map(|n| NotificationEvent {
                    event_id: format!("{n:032x}"),
                    kind: NotificationKind::SessionIssued,
                    occurred_at: n * 86400,
                    read: false,
                })
                .collect(),
        };
        let html = notice_activity(Some((&inbox, None)));
        assert_eq!(html.matches("<time ").count(), 5);
        assert!(html.find("1970-01-08").unwrap() < html.find("1970-01-07").unwrap());
        assert!(!html.contains("1970-01-02"));
        assert!(!html.contains(&format!("{:032x}", 7)));
    }
}
