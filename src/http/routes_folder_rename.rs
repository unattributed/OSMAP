//! Explicitly reviewed private subtree rename or move, with fresh authority on confirmation.
use super::*;
use crate::logging::EventCategory;
use crate::{
    folder_create::Refusal,
    folder_rename::{Outcome, RenameFolderRequest},
};

pub(super) fn retained_folder_notice(request: &RenameFolderRequest) -> String {
    let reference = if request.is_recovery() {
        request
            .recovery_original()
            .ok()
            .map(|original| original.action_nonce().to_owned())
    } else {
        Some(request.action_nonce().to_owned())
    };
    let reference = reference.as_deref().unwrap_or("unavailable");
    format!("<section aria-label=\"Pending folder change\"><h2>Folder change still pending</h2><p>This is not a successful completion. Affected folder changes remain paused; you can continue reading mail. Do not repeat the folder action or delete either location.</p><p>Give the mail service administrator this account and operation reference for reconciliation. The administrator is responsible for diagnosis and safe repair; you do not need to troubleshoot.</p><dl><dt>Account</dt><dd>{}</dd><dt>Operation reference</dt><dd><code>{}</code></dd></dl></section>", escape_html(request.account()), escape_html(reference))
}
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn rename_preflight(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        source: &str,
        destination_parent: &str,
        audit: &mut Vec<LogEvent>,
    ) -> Option<(
        crate::folder_metadata::FolderSnapshot,
        crate::mailbox_status::MailboxStatus,
        crate::mailbox_status::MailboxStatus,
        crate::mailbox_status::MailboxStatus,
    )> {
        let (parent, _) = source.rsplit_once('.')?;
        let (guard, event) = self
            .acquire_mailbox_budget(context, session, "folder_rename_preflight")
            .ok()?;
        audit.push(event);
        let metadata = self.gateway.folder_metadata(context, session);
        let source_status = self.gateway.mailbox_status(context, session, source);
        let parent_status = self.gateway.mailbox_status(context, session, parent);
        let destination_status = if destination_parent.is_empty() || destination_parent == parent {
            parent_status.clone()
        } else {
            self.gateway
                .mailbox_status(context, session, destination_parent)
        };
        audit.extend(metadata.audit_events);
        audit.extend(source_status.audit_events);
        audit.extend(parent_status.audit_events);
        if !destination_parent.is_empty() && destination_parent != parent {
            audit.extend(destination_status.audit_events);
        }
        audit.push(self.release_request_budget(guard, "folder_rename_preflight", context, session));
        if [
            &metadata.canonical_username,
            &source_status.canonical_username,
            &parent_status.canonical_username,
            &destination_status.canonical_username,
        ]
        .iter()
        .any(|name| *name != &session.record.canonical_username)
        {
            return None;
        }
        Some((
            metadata.snapshot?,
            source_status.status?,
            parent_status.status?,
            destination_status.status?,
        ))
    }
    pub(super) fn handle_folder_rename(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
        moving: bool,
    ) -> HandledHttpResponse {
        let (session, mut audit) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        match self.gateway.pending_folder_rename(&session) {
            Ok(Some(_)) => return HandledHttpResponse { response: html_response(409, "Conflict", "Rename result pending", "<p>A rename result is still pending. Rename and mail destination preferences are paused.</p><p><a href=\"/settings/folders/rename/check\">Check rename result</a></p>"), audit_events: audit },
            Err(_) => return HandledHttpResponse { response: html_response(503, "Service Unavailable", "Rename unavailable", "<p>Current rename state could not be verified. No rename was attempted. Reload Copies &amp; Folders.</p>"), audit_events: audit },
            Ok(None) => (),
        }
        let post = request.method == HttpMethod::Post;
        let fields = if post {
            if !request.query_params.is_empty()
                || !allows_urlencoded_request_body(
                    request.headers.get("content-type").map(String::as_str),
                )
            {
                None
            } else {
                parse_urlencoded_form(&request.body, 10, 4096).ok()
            }
        } else {
            Some(request.query_params.clone())
        };
        let fields = fields.unwrap_or_else(|| BTreeMap::from([("invalid".into(), String::new())]));
        let get = |name: &str| fields.get(name).map(String::as_str).unwrap_or("");
        if post {
            if let Some(r) = self.require_valid_csrf(
                request,
                fields.get("csrf_token").map(String::as_str),
                &session,
                context,
            ) {
                return r;
            }
        }
        let source = get("source");
        let leaf = if moving {
            source.rsplit_once('.').map_or("", |v| v.1)
        } else {
            get("leaf")
        };
        let destination_parent = get("destination_parent");
        let mut source_parent_guid = get("source_parent_guid").to_owned();
        let mut parents = Vec::new();
        let mut source_guid = get("source_guid").to_owned();
        let mut parent_guid = get("parent_guid").to_owned();
        let mut descendants = if get("descendants").is_empty() {
            "[]".to_owned()
        } else {
            get("descendants").to_owned()
        };
        let mut code = 200;
        let mut stage = "entry";
        let mut notice = None;
        let allowed = fields.keys().all(|key| {
            if post {
                (moving && matches!(key.as_str(), "destination_parent" | "source_parent_guid"))
                    || matches!(
                        key.as_str(),
                        "csrf_token"
                            | "source"
                            | "source_guid"
                            | "parent_guid"
                            | "leaf"
                            | "action"
                            | "confirm"
                            | "descendants"
                    )
            } else {
                key == "source"
            }
        });
        if !allowed
            || source.len() > 255
            || leaf.len() > 255
            || source_guid.len() > 64
            || parent_guid.len() > 64
            || source_parent_guid.len() > 64
            || destination_parent.len() > 255
            || descendants.len() > 2048
            || (post && !matches!(get("action"), "review" | "rename"))
        {
            code = 400;
            stage = "refused";
            notice = Some("Invalid rename request. Reload Copies & Folders.");
        } else if let Some((snapshot, status, source_parent, parent)) =
            self.rename_preflight(context, &session, source, destination_parent, &mut audit)
        {
            if !post {
                source_guid = status.guid().into();
                parent_guid = parent.guid().into();
                source_parent_guid = source_parent.guid().into();
            }
            if moving && post && get("action") == "review" {
                parent_guid = parent.guid().into();
            }
            let names =
                crate::folder_rename::protected_destinations(&self.gateway, context, &session);
            if moving {
                parents = snapshot
                    .folders()
                    .iter()
                    .filter(|folder| {
                        let name = folder.name();
                        name != source.rsplit_once('.').map_or("", |v| v.0)
                            && name != source
                            && !name.starts_with(&format!("{source}."))
                            && (name == "INBOX" || !crate::folder_rename::protected_name(name))
                            && folder.delimiter() == Some('.')
                            && folder.special_use().is_empty()
                            && !folder.has_flag("\\Noselect")
                            && !folder.has_flag("\\NonExistent")
                            && !folder.has_flag("\\Noinferiors")
                            && crate::folder_create::validate_private_namespace(&snapshot, name)
                                .is_ok()
                            && names.as_ref().is_ok_and(|names| {
                                !crate::folder_rename::role_conflict(
                                    names,
                                    source,
                                    &format!("{name}.{leaf}"),
                                )
                            })
                    })
                    .map(|folder| folder.name().to_owned())
                    .collect();
            }
            if names.is_err() {
                code = 503;
                stage = "refused";
                notice = Some("Saved mail destinations could not be verified. No rename was attempted. Reload Copies & Folders.");
            } else if crate::folder_rename::validate_source(
                &session.record.canonical_username,
                source,
                &snapshot,
                &status,
            )
            .is_err()
                || names.as_ref().map_or(true, |names| {
                    crate::folder_rename::role_conflict(names, source, source)
                })
            {
                code = 409;
                stage = "refused";
                notice = Some("Only bounded private user folders can be renamed. System folders and saved mail destinations are protected. Reload before trying again.");
            } else if post {
                let rename = if moving {
                    RenameFolderRequest::for_move(
                        &session.record.canonical_username,
                        source,
                        &source_guid,
                        &source_parent_guid,
                        destination_parent,
                        &parent_guid,
                    )
                } else {
                    RenameFolderRequest::new(
                        &session.record.canonical_username,
                        source,
                        &source_guid,
                        &parent_guid,
                        leaf,
                    )
                }
                .and_then(|r| {
                    let declared = if get("action") == "review" {
                        None
                    } else {
                        Some(
                            serde_json::from_str::<Vec<crate::folder_subtree::Descendant>>(
                                &descendants,
                            )
                            .map_err(|_| Refusal::Invalid)?,
                        )
                    };
                    let r = {
                        let (guard, event) = self
                            .acquire_mailbox_budget(context, &session, "folder_subtree_preflight")
                            .map_err(|_| Refusal::Unavailable)?;
                        audit.push(event);
                        let captured = crate::folder_subtree::capture_from(&snapshot, &r, |name| {
                            let outcome = self.gateway.mailbox_status(context, &session, name);
                            audit.extend(outcome.audit_events);
                            if outcome.canonical_username != session.record.canonical_username {
                                return Err(Refusal::Invalid);
                            }
                            outcome.status.ok_or(Refusal::Unavailable)
                        });
                        audit.push(self.release_request_budget(
                            guard,
                            "folder_subtree_preflight",
                            context,
                            &session,
                        ));
                        let captured = captured?;
                        if declared.is_some_and(|expected| expected != captured) {
                            return Err(Refusal::Stale);
                        }
                        r.with_descendants(captured)?
                    };
                    descendants =
                        serde_json::to_string(r.descendants()).map_err(|_| Refusal::Unavailable)?;
                    r.validate_before(&snapshot, &status, &parent)?;
                    if moving {
                        r.validate_source_parent(&snapshot, &source_parent)?;
                    }
                    if crate::folder_rename::role_conflict(
                        names.as_ref().map_err(|_| Refusal::Unavailable)?,
                        r.source(),
                        &r.destination(),
                    ) {
                        return Err(Refusal::Invalid);
                    }
                    Ok(r)
                });
                match rename {
                    Err(_) => {
                        code = 409;
                        stage = "refused";
                        notice = Some("The folder identity or requested name changed or is protected. No rename was attempted. Reload before trying again.");
                    }
                    Ok(rename)
                        if snapshot
                            .folder(rename.account(), &rename.destination())
                            .is_ok() =>
                    {
                        code = 409;
                        stage = "refused";
                        notice = Some("The destination already exists. No rename was attempted.");
                    }
                    Ok(_) if get("action") == "review" => stage = "review",
                    Ok(_) if get("confirm") != "rename" => {
                        code = 400;
                        stage = "refused";
                        notice =
                            Some("Rename requires explicit confirmation. No rename was attempted.");
                    }
                    Ok(rename) => {
                        let (guard, event) =
                            match self.acquire_mailbox_budget(context, &session, "folder_rename") {
                                Ok(v) => v,
                                Err(r) => return r,
                            };
                        audit.push(event);
                        let outcome = self.gateway.rename_folder(context, &session, &rename);
                        audit.push(
                            LogEvent::new(
                                LogLevel::Info,
                                EventCategory::Mailbox,
                                "folder_rename_result",
                                "folder rename returned a bounded outcome",
                            )
                            .with_field(
                                "confirmed",
                                matches!(outcome, Outcome::Renamed).to_string(),
                            ),
                        );
                        audit.push(self.release_request_budget(
                            guard,
                            "folder_rename",
                            context,
                            &session,
                        ));
                        if outcome == Outcome::Renamed {
                            return HandledHttpResponse {
                                response: redirect_response(
                                    303,
                                    "See Other",
                                    &format!(
                                        "/settings?section=copies&folder={}",
                                        url_encode(&rename.destination())
                                    ),
                                ),
                                audit_events: audit,
                            };
                        }
                        code = if matches!(
                            outcome,
                            Outcome::Conflict | Outcome::Refused(Refusal::Stale | Refusal::Invalid)
                        ) {
                            409
                        } else {
                            503
                        };
                        stage = if outcome == Outcome::Unknown {
                            "pending"
                        } else {
                            "refused"
                        };
                        notice = Some(if outcome == Outcome::Unknown {
                            "Rename could not be confirmed. The folder may have changed. Reload and inspect both names before doing anything else; no retry was made."
                        } else {
                            "Rename was refused. Reload and inspect current folders before trying again."
                        });
                    }
                }
            }
        } else {
            code = 503;
            stage = "refused";
            notice = Some("Current folder ownership and status could not be verified. Reload Copies & Folders.");
        }
        let notice = notice.map(|text| {
            if moving {
                text.replace("Rename", "Move").replace("rename", "move")
            } else {
                text.to_owned()
            }
        });
        HandledHttpResponse {
            response: html_response(
                code,
                if code == 200 {
                    "OK"
                } else if code == 400 {
                    "Bad Request"
                } else if code == 409 {
                    "Conflict"
                } else {
                    "Service Unavailable"
                },
                if moving {
                    "Move folder"
                } else {
                    "Rename folder"
                },
                crate::http_ui::render_folder_rename(crate::http_ui::RenamePageModel {
                    descendants: &descendants,
                    account: &session.record.canonical_username,
                    csrf: &session.record.csrf_token,
                    source,
                    source_guid: &source_guid,
                    parent_guid: &parent_guid,
                    leaf,
                    stage,
                    notice: notice.as_deref(),
                    moving,
                    destination_parent,
                    source_parent_guid: &source_parent_guid,
                    parents: &parents,
                }),
            ),
            audit_events: audit,
        }
    }
}

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_folder_rename_recover(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        use crate::folder_rename::RecoveryOutcome;
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let pending =
            match self.gateway.pending_folder_rename(&session) {
                Ok(Some(value)) if !value.descendants().is_empty() => value,
                _ => return HandledHttpResponse {
                    response: html_response(
                        409,
                        "Conflict",
                        "Recovery unavailable",
                        "<p>No bounded subtree recovery is available. No folder was changed.</p>",
                    ),
                    audit_events,
                },
            };
        let mut notice = "This repairs one remaining original subfolder only after its original helper record proves native settlement and every current original GUID has exactly one safe placement. It never repeats the original root rename. Changed, missing, duplicated or foreign identities refuse recovery. A completely unchanged original tree can be released without moving any folder.";
        let mut code = 200;
        let mut nonce = if pending.is_recovery() {
            pending.action_nonce().to_owned()
        } else {
            crate::draft::generate_draft_id().unwrap_or_default()
        };
        let post = request.method == HttpMethod::Post;
        if post {
            let fields = if request.query_params.is_empty()
                && allows_urlencoded_request_body(
                    request.headers.get("content-type").map(String::as_str),
                ) {
                parse_urlencoded_form(&request.body, 3, 512).ok()
            } else {
                None
            };
            let Some(fields) = fields.filter(|f| {
                f.keys()
                    .all(|k| matches!(k.as_str(), "csrf_token" | "confirm" | "recovery_nonce"))
                    && f.get("confirm").map(String::as_str) == Some("recover")
            }) else {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid recovery",
                        "<p>No recovery was dispatched.</p>",
                    ),
                    audit_events,
                };
            };
            if let Some(r) = self.require_valid_csrf(
                request,
                fields.get("csrf_token").map(String::as_str),
                &session,
                context,
            ) {
                return r;
            }
            nonce = fields.get("recovery_nonce").cloned().unwrap_or_default();
            if nonce.len() != 32
                || !nonce
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid recovery",
                        "<p>No recovery was dispatched.</p>",
                    ),
                    audit_events,
                };
            }
            let (guard, event) =
                match self.acquire_mailbox_budget(context, &session, "folder_subtree_recovery") {
                    Ok(v) => v,
                    Err(r) => return r,
                };
            audit_events.push(event);
            let outcome = self
                .gateway
                .recover_folder_rename(context, &session, &nonce);
            audit_events.push(self.release_request_budget(
                guard,
                "folder_subtree_recovery",
                context,
                &session,
            ));
            match outcome {
                RecoveryOutcome::Complete { destination } => return HandledHttpResponse { response: redirect_response(303, "See Other", &format!("/folders?folder={}", url_encode(&destination))), audit_events },
                RecoveryOutcome::Unchanged => return HandledHttpResponse { response: html_response(200, "OK", "Original folders unchanged", "<p>The original native operation is settled and all original folders remain in their original locations. The pending action was released without repeating it.</p><p><a href=\"/folders\">Folders</a></p>"), audit_events },
                RecoveryOutcome::Progress => notice = "This recovery step is confirmed. Other original subfolders remain pending. Review the next bounded recovery; no root rename was repeated.",
                RecoveryOutcome::Inspected => notice = "The previous recovery is settled or proved undispatched. It was not repeated. Review current recovery to continue only if the remaining identities qualify.",
                RecoveryOutcome::Refused => { code = 409; notice = "Recovery was refused before a new native change. Current authority, settlement, identities or capacity did not qualify. The original pending result is preserved."; },
                RecoveryOutcome::Unknown => { code = 409; notice = "Recovery remains unconfirmed. Its original nonce is retained; reopening recovery inspects that attempt without dispatching it again."; },
                RecoveryOutcome::Unavailable => { code = 503; notice = "Recovery authority or durable state is unavailable. The original pending result is preserved."; },
            }
        } else if !request.query_params.is_empty() {
            code = 400;
        }
        let form = if !post && code == 200 && nonce.len() == 32 {
            format!("<form method=\"post\" action=\"/settings/folders/rename/recover\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"recovery_nonce\" value=\"{}\"><button name=\"confirm\" value=\"recover\">{}</button></form>", escape_html(&session.record.csrf_token), escape_html(&nonce), if pending.is_recovery() { "Inspect previous recovery" } else { "Confirm recover next subfolder" })
        } else {
            String::new()
        };
        let retained = retained_folder_notice(&pending);
        HandledHttpResponse { response: html_response(code, if code == 200 { "OK" } else if code == 503 { "Service Unavailable" } else { "Conflict" }, "Recover partial folder change", crate::html::TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><h1>Recover partial folder change</h1><p role=\"status\">{}</p><dl><dt>Original folder</dt><dd>{}</dd><dt>Intended folder</dt><dd>{}</dd></dl>{retained}{form}<p><a href=\"/settings/folders/rename/recover\">Review current recovery</a> · <a href=\"/settings/folders/rename/check\">Check original result</a> · <a href=\"/folders\">Folders</a></p></main>", crate::http_ui::app_header(&session.record.canonical_username, &session.record.csrf_token, "folders"), escape_html(notice), escape_html(pending.source()), escape_html(&pending.destination())))), audit_events }
    }
    pub(super) fn handle_folder_rename_check(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let mut pending = self.gateway.pending_folder_rename(&session);
        if pending
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .is_some_and(|r| r.disposition().is_some())
        {
            return self.handle_folder_disposition_check(request, context);
        }
        let mut code = if pending.is_ok() { 200 } else { 503 };
        let mut notice = if pending.as_ref().is_ok_and(|p| p.is_none()) {
            "No rename result is pending. Inspect Copies & Folders for current names."
        } else {
            "Rename and mail destination preferences remain paused until the result is confirmed. This check reads current folders and never retries a rename."
        };
        if request.method == HttpMethod::Post {
            let fields = if request.query_params.is_empty()
                && allows_urlencoded_request_body(
                    request.headers.get("content-type").map(String::as_str),
                ) {
                parse_urlencoded_form(&request.body, 2, 512).ok()
            } else {
                None
            };
            let Some(fields) = fields.filter(|f| {
                f.keys()
                    .all(|k| matches!(k.as_str(), "csrf_token" | "confirm"))
                    && f.get("confirm").map(String::as_str) == Some("check")
            }) else {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid result check",
                        "<p>No folder was changed.</p>",
                    ),
                    audit_events: audit,
                };
            };
            if let Some(response) = self.require_valid_csrf(
                request,
                fields.get("csrf_token").map(String::as_str),
                &session,
                context,
            ) {
                return response;
            }
            let (guard, event) =
                match self.acquire_mailbox_budget(context, &session, "folder_rename_check") {
                    Ok(value) => value,
                    Err(response) => return response,
                };
            audit.push(event);
            let outcome = self.gateway.check_folder_rename(context, &session);
            audit.push(self.release_request_budget(
                guard,
                "folder_rename_check",
                context,
                &session,
            ));
            match outcome {
                crate::folder_rename::CheckOutcome::Renamed { destination } => {
                    return HandledHttpResponse {
                        response: redirect_response(
                            303,
                            "See Other",
                            &format!(
                                "/settings?section=copies&folder={}",
                                url_encode(&destination)
                            ),
                        ),
                        audit_events: audit,
                    }
                }
                crate::folder_rename::CheckOutcome::Unchanged => {
                    pending = Ok(None);
                    notice = "The helper confirms that this original action finished without attempting a rename, and current folder identities are unchanged. Preferences are available again. No rename was retried.";
                }
                crate::folder_rename::CheckOutcome::NoPending => {
                    notice =
                        "No rename result is pending. Inspect Copies & Folders for current names."
                }
                crate::folder_rename::CheckOutcome::Unavailable => {
                    code = 503;
                    notice = "Current result authority is unavailable. Preferences remain paused. Reload to inspect; no rename was retried.";
                }
                crate::folder_rename::CheckOutcome::Unconfirmed => {
                    code = 409;
                    notice = "The rename is still unconfirmed. The original folder may be unchanged or current identities may be ambiguous. Preferences remain paused. A proven settled helper result is required before an unchanged result can be cleared; no rename was retried.";
                }
            }
        } else if !request.query_params.is_empty() {
            code = 400;
        }
        let details = pending.as_ref().ok().and_then(Option::as_ref).map(|r| format!("<dl><dt>Original folder</dt><dd>{}</dd><dt>Requested folder</dt><dd>{}</dd></dl>{}{}", escape_html(r.source()), escape_html(&r.destination()), retained_folder_notice(r), if r.descendants().is_empty() { "" } else { "<p><a href=\"/settings/folders/rename/recover\">Review bounded partial recovery</a></p>" })).unwrap_or_default();
        let check = if pending.as_ref().is_ok_and(|p| p.is_some()) {
            format!("<form method=\"post\" action=\"/settings/folders/rename/check\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button name=\"confirm\" value=\"check\">Check current result</button></form>", escape_html(&session.record.csrf_token))
        } else {
            String::new()
        };
        HandledHttpResponse { response: html_response(code, if code == 200 { "OK" } else if code == 400 { "Bad Request" } else if code == 409 { "Conflict" } else { "Service Unavailable" }, "Check rename result", crate::html::TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><h1>Check rename result</h1><p role=\"status\">{}</p>{details}{check}<p><a href=\"/settings?section=copies\">Inspect Copies &amp; Folders</a></p></main>", crate::http_ui::app_header(&session.record.canonical_username, &session.record.csrf_token, "settings-copies"), escape_html(notice)))), audit_events: audit }
    }
}
