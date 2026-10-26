//! Read-only account protection overview from owned sessions and public keys.
use super::*;
use crate::http::BrowserSessionListDecision;

// Bound this overview's validation/sort work. An oversized result is unknown,
// rather than a truncated list presented as an exact active-session count.
#[cfg(test)]
const MAX_SECURITY_SESSION_RECORDS: usize = 256;

fn verified_security_sessions<'a>(
    account: &str,
    decision: &'a BrowserSessionListDecision,
) -> Option<&'a [BrowserVisibleSession]> {
    decision.verified_sessions(account)
}

fn public_account_key_summary(
    account: &str,
    state: Option<&crate::key_management::State>,
) -> (&'static str, String) {
    let owned = state.filter(|value| value.canonical_username == account);
    let Some((record, keys)) = owned.and_then(|value| {
        let record = value.bindings.as_ref()?;
        record.ensure_account(account).ok()?;
        Some((record, value.inventory.as_ref()?.keys()?))
    }) else {
        return (
            "Unknown",
            "Account bindings or public inventory unavailable".into(),
        );
    };
    let Some(binding) = &record.account_binding else {
        return (
            "Account binding needed",
            "No account key is approved for this identity".into(),
        );
    };
    let Some(key) = keys
        .iter()
        .find(|key| key.primary.fingerprint == binding.primary_fingerprint)
    else {
        return (
            "Bound public key missing",
            "The approved account key is absent from the reported public inventory".into(),
        );
    };
    if key.primary.revoked || key.primary.expired || key.primary.disabled || key.primary.invalid {
        return ("Bound public key ineligible", "The reported account public key is revoked, expired, disabled or invalid; review it in Manage keys".into());
    }
    ("Account binding configured", format!(
        "Approved primary fingerprint: {}. Public metadata only; private-key readiness is checked when an operation runs.",
        escape_html(&binding.primary_fingerprint),
    ))
}

#[cfg(test)]
pub(crate) fn render_security_page(
    account: &str,
    csrf: &str,
    decision: &BrowserSessionListDecision,
    keys: Option<&crate::key_management::State>,
    authentication: bool,
    password_available: bool,
    password_changed_at: Option<&str>,
) -> TrustedHtml {
    render_security_page_with_recovery(
        account,
        csrf,
        decision,
        keys,
        authentication,
        password_available,
        password_changed_at,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_security_page_with_recovery(
    account: &str,
    csrf: &str,
    decision: &BrowserSessionListDecision,
    keys: Option<&crate::key_management::State>,
    authentication: bool,
    password_available: bool,
    password_changed_at: Option<&str>,
    recovery: Option<&crate::recovery_contact::RecoveryContactSnapshot>,
) -> TrustedHtml {
    let (recovery_status, recovery_detail) = recovery_contact_summary(recovery);
    let recovery_control = format!("<div class=\"security-control\"><div><strong>Recovery contact</strong><p>{recovery_detail}</p></div><a class=\"button-link secondary\" href=\"/settings/recovery\" aria-label=\"Manage recovery contact\">Manage contact</a></div>");
    let changed_at = password_changed_at.filter(|v| crate::account_mutation::changed_at_valid(v));
    let password_history = changed_at.map_or_else(
        || "Last change unknown".to_owned(),
        |v| {
            format!(
                "Last changed {}-{}-{} {}:{}:{} UTC",
                &v[0..4],
                &v[4..6],
                &v[6..8],
                &v[8..10],
                &v[10..12],
                &v[12..14]
            )
        },
    );
    let password_detail = format!("Required at this sign-in; {password_history}");
    let sessions = verified_security_sessions(account, decision);
    let count = sessions
        .map(|items| {
            format!(
                "{} active browser sessions",
                items.iter().filter(|s| s.revoked_at.is_none()).count()
            )
        })
        .unwrap_or_else(|| "Active session count unknown".into());
    let row = |title: &str, detail: &str, action: &str, enabled: bool| {
        let control = if enabled {
            format!("<a class=\"button-link secondary\" href=\"/sessions\" aria-label=\"Manage sessions\">{action}</a>")
        } else {
            format!("<button type=\"button\" class=\"secondary\" disabled>{action}</button>")
        };
        format!("<div class=\"security-control\"><div><strong>{title}</strong><p>{detail}</p></div>{control}</div>")
    };
    let password = if password_available {
        format!("<div class=\"security-control\"><div><strong>Password</strong><p>{password_detail}</p></div><a class=\"button-link secondary\" href=\"/settings/password\" aria-label=\"Change password\">Change</a></div>")
    } else {
        row(
            "Password",
            &format!("{password_detail}. Password changes are currently unavailable."),
            "Unavailable",
            false,
        )
    };
    let totp = row(
        "TOTP two-factor",
        "Used at this sign-in; current enrollment unknown",
        "Manage",
        false,
    );
    let active = row("Active sessions", &count, "Manage", true);
    let content = if authentication {
        format!(concat!("<div class=\"security-two-cards authentication-cards\"><section class=\"security-card\"><h2>Authentication</h2>{password}{totp}{active}</section>",
            "<section class=\"security-card\"><h2>Recovery</h2><div class=\"security-recovery-contact\"><strong>Recovery contact</strong><span class=\"security-unknown\">Unknown</span><p>Contact and verification status unavailable</p></div><button type=\"button\" class=\"secondary\" disabled>Manage contact</button><p class=\"security-policy-note\">Recovery-contact management is unavailable. This session does not establish a recovery contact or permission to bypass authentication.</p></section></div>"), password=password, totp=totp, active=active)
    } else {
        let (key_status, key_detail) = public_account_key_summary(account, keys);
        let key_control = format!("<div class=\"security-control\"><div><strong>OpenPGP keys</strong><p>{key_detail}</p></div><a class=\"button-link secondary\" href=\"/settings/keys\" aria-label=\"Manage OpenPGP keys\">Manage</a></div>");
        let mut events = String::new();
        if let Some(sessions) = sessions {
            let mut ordered = Vec::new();
            for session in sessions {
                ordered.push((session.issued_at, "Sign-in", session));
                if let Some(revoked_at) = session.revoked_at {
                    ordered.push((revoked_at, "Session revoked", session));
                }
            }
            ordered.sort_by_key(|(at, event, _)| (std::cmp::Reverse(*at), *event));
            for (at, event, session) in ordered.into_iter().take(5) {
                let date = crate::logging::format_unix_timestamp_utc(at);
                let device = if session.device_label.trim().is_empty() {
                    "Unknown device"
                } else {
                    &session.device_label
                };
                events.push_str(&format!("<li><div><strong>{event}</strong><p>{}</p></div><time datetime=\"{}\">{} UTC</time></li>", escape_html(device), escape_html(&date), escape_html(&date.replace('T', " ").replace('Z', ""))));
            }
            if sessions.is_empty() {
                events.push_str("<li>No retained sign-ins are available.</li>");
            }
        } else {
            events.push_str("<li>Retained sign-ins are unavailable.</li>");
        }
        let tiles = [("OpenPGP", key_status, key_detail.as_str()), ("TOTP", "Used at sign-in", "Current enrollment unknown"), ("Password", "Used at sign-in", password_history.as_str()), ("Recovery Contact", "Unknown", "Contact and verification unavailable")].into_iter().map(|(title, state, note)| format!("<section class=\"security-tile\"><span class=\"security-tile-symbol\" aria-hidden=\"true\">{}</span><div><h3>{title}</h3><strong>{state}</strong><p>{note}</p></div></section>", shell_icon("shield"))).collect::<String>();
        format!(concat!("<section class=\"security-card security-heading\"><h2>Security</h2><p>Status and management for account protection. Privacy preferences remain under <a href=\"/settings?section=privacy\">Privacy &amp; Security</a>.</p></section><div class=\"security-tiles\">{tiles}</div>",
            "<div class=\"security-two-cards security-overview-cards\"><section class=\"security-card\"><h2>Security Controls</h2>{keys}{totp}{password}{recovery}{active}</section><section class=\"security-card\"><h2>Recent Security Events</h2><p class=\"security-event-scope\">Sign-ins and revocations from retained browser sessions; other security event history unavailable.</p><ul class=\"security-events\">{events}</ul></section></div>",
            "<section class=\"security-card security-role\"><h3>Security page role</h3><p>These details describe this sign-in, retained sessions and reported public account keys. Manage keys opens account-bound key management; this overview does not establish private-key availability. Password and recovery changes remain unavailable here. <a href=\"/settings?section=privacy\">Review privacy and rendering protections</a>.</p></section>"), password=password, totp=totp, active=active, tiles=tiles, events=events, keys=key_control, recovery=row("Recovery contact", "Contact and verification status unknown", "Manage", false))
    };
    let content = content.replace(
        "Password and recovery changes remain unavailable here.",
        if password_available {
            "Change password opens your account-bound verification form. Recovery changes remain unavailable."
        } else {
            "Password and recovery changes remain unavailable here."
        },
    );
    let content = if recovery.is_some() {
        content.replace("<div class=\"security-recovery-contact\"><strong>Recovery contact</strong><span class=\"security-unknown\">Unknown</span><p>Contact and verification status unavailable</p></div><button type=\"button\" class=\"secondary\" disabled>Manage contact</button>", &recovery_control)
            .replace("Recovery-contact management is unavailable. This session does not establish a recovery contact or permission to bypass authentication.", "Recovery contact management requires fresh confirmation. Contact possession does not bypass authentication.")
            .replace(&row("Recovery contact", "Contact and verification status unknown", "Manage", false), &recovery_control)
            .replace("<h3>Recovery Contact</h3><strong>Unknown</strong><p>Contact and verification unavailable</p>", &format!("<h3>Recovery Contact</h3><strong>{recovery_status}</strong><p>{recovery_detail}</p>"))
            .replace("Recovery changes remain unavailable.", "Manage contact opens your account-bound recovery-contact form.")
            .replace("Password and recovery changes remain unavailable here.", "Manage contact opens your account-bound recovery-contact form; password capability is reported separately.")
    } else {
        content
    };
    let section = if authentication {
        "authentication"
    } else {
        "security"
    };
    TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell settings-page settings-security-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Settings</h1><p>{}</p></div><div class=\"settings-layout\">{}<div class=\"security-content\">{content}</div></div></main>", app_header(account, csrf, &format!("settings-{section}")), if authentication { "Review password, TOTP, recovery contacts and active sessions." } else { "Review account protection, authentication, OpenPGP, sessions and security events." }, settings_navigation(section)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn security_summary_excess_and_duplicate_records_are_unknown() {
        let session = BrowserVisibleSession {
            session_id: String::new(),
            issued_at: 0,
            expires_at: 100,
            last_seen_at: 0,
            revoked_at: None,
            device_label: "bounded-device".into(),
            remote_addr: String::new(),
            user_agent: String::new(),
            factor: crate::auth::RequiredSecondFactor::Totp,
        };
        let sessions: Vec<_> = (0..MAX_SECURITY_SESSION_RECORDS)
            .map(|index| BrowserVisibleSession {
                session_id: index.to_string(),
                issued_at: index as u64,
                ..session.clone()
            })
            .collect();
        let make = |sessions| BrowserSessionListDecision::Listed {
            canonical_username: "alice".into(),
            session_lifetime_seconds: 100,
            session_idle_timeout_seconds: 100,
            sessions,
        };
        let valid = make(sessions.clone());
        let html = render_security_page("alice", "synthetic", &valid, None, false, false, None)
            .as_str()
            .to_owned();
        assert!(html.contains("256 active browser sessions"));
        assert_eq!(html.matches("bounded-device").count(), 5);
        let mut excess = sessions.clone();
        excess.push(BrowserVisibleSession {
            session_id: "excess".into(),
            ..session
        });
        let mut duplicate = sessions;
        duplicate[1].session_id = duplicate[0].session_id.clone();
        for invalid in [make(excess), make(duplicate)] {
            for authentication in [false, true] {
                let html = render_security_page(
                    "alice",
                    "synthetic",
                    &invalid,
                    None,
                    authentication,
                    false,
                    None,
                )
                .as_str()
                .to_owned();
                assert!(html.contains("Active session count unknown"));
                assert!(!html.contains("bounded-device"));
                assert!(!html.contains("256 active browser sessions"));
                assert!(!html.contains("257 active browser sessions"));
                if !authentication {
                    assert!(html.contains("Retained sign-ins are unavailable."));
                }
            }
        }
    }

    #[test]
    fn security_summary_owner_failure_count_and_literal_events() {
        let mut entries = Vec::new();
        for index in 0..7 {
            entries.push(BrowserVisibleSession {
                session_id: index.to_string(),
                issued_at: index,
                expires_at: 100,
                last_seen_at: index,
                revoked_at: if index == 0 { Some(9) } else { None },
                device_label: "<script>device</script>".into(),
                remote_addr: "private-address".into(),
                user_agent: "private-agent".into(),
                factor: crate::auth::RequiredSecondFactor::Totp,
            });
        }
        let decision = BrowserSessionListDecision::Listed {
            canonical_username: "alice".into(),
            session_lifetime_seconds: 100,
            session_idle_timeout_seconds: 100,
            sessions: entries,
        };
        let html = render_security_page("alice", "synthetic", &decision, None, false, false, None)
            .as_str()
            .to_owned();
        assert!(html.contains("6 active browser sessions"));
        assert_eq!(
            html.matches("&lt;script&gt;device&lt;/script&gt;").count(),
            5
        );
        assert!(!html.contains("private-address"));
        assert!(!html.contains("private-agent"));
        assert!(html.contains("<strong>Session revoked</strong>"));
        assert!(html.find("00:00:09").unwrap() < html.find("00:00:06").unwrap());
        assert!(html.find("00:00:06").unwrap() < html.find("00:00:05").unwrap());
        for decision in [
            decision,
            BrowserSessionListDecision::Denied {
                public_reason: "private-error".into(),
            },
        ] {
            let html =
                render_security_page("bob", "synthetic", &decision, None, false, false, None)
                    .as_str()
                    .to_owned();
            assert!(html.contains("Active session count unknown"));
            assert!(!html.contains("device&lt;"));
            assert!(!html.contains("private-error"));
        }
    }
}
