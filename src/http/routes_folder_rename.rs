//! Explicitly reviewed same-parent folder rename, with fresh authority on confirmation.
use super::*;
use crate::logging::EventCategory;
use crate::{
    folder_create::Refusal,
    folder_rename::{Outcome, RenameFolderRequest},
};
impl<G: BrowserGateway> BrowserApp<G> {
    fn rename_preflight(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        source: &str,
        audit: &mut Vec<LogEvent>,
    ) -> Option<(
        crate::folder_metadata::FolderSnapshot,
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
        audit.extend(metadata.audit_events);
        audit.extend(source_status.audit_events);
        audit.extend(parent_status.audit_events);
        audit.push(self.release_request_budget(guard, "folder_rename_preflight", context, session));
        if [
            &metadata.canonical_username,
            &source_status.canonical_username,
            &parent_status.canonical_username,
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
        ))
    }
    pub(super) fn handle_folder_rename(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
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
                parse_urlencoded_form(&request.body, 8, 4096).ok()
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
        let leaf = get("leaf");
        let mut source_guid = get("source_guid").to_owned();
        let mut parent_guid = get("parent_guid").to_owned();
        let mut code = 200;
        let mut stage = "entry";
        let mut notice = None;
        let allowed = fields.keys().all(|key| {
            if post {
                matches!(
                    key.as_str(),
                    "csrf_token"
                        | "source"
                        | "source_guid"
                        | "parent_guid"
                        | "leaf"
                        | "action"
                        | "confirm"
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
            || (post && !matches!(get("action"), "review" | "rename"))
        {
            code = 400;
            stage = "refused";
            notice = Some("Invalid rename request. Reload Copies & Folders.");
        } else if let Some((snapshot, status, parent)) =
            self.rename_preflight(context, &session, source, &mut audit)
        {
            if !post {
                source_guid = status.guid().into();
                parent_guid = parent.guid().into();
            }
            let names =
                crate::folder_rename::protected_destinations(&self.gateway, context, &session);
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
                notice = Some("Only private user folders without subfolders can be renamed. System folders and saved mail destinations are protected. Reload before trying again.");
            } else if post {
                let rename = RenameFolderRequest::new(
                    &session.record.canonical_username,
                    source,
                    &source_guid,
                    &parent_guid,
                    leaf,
                )
                .and_then(|r| {
                    r.validate_before(&snapshot, &status, &parent)?;
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
                "Rename folder",
                crate::http_ui::render_folder_rename(crate::http_ui::RenamePageModel {
                    account: &session.record.canonical_username,
                    csrf: &session.record.csrf_token,
                    source,
                    source_guid: &source_guid,
                    parent_guid: &parent_guid,
                    leaf,
                    stage,
                    notice,
                }),
            ),
            audit_events: audit,
        }
    }
}

impl<G: BrowserGateway> BrowserApp<G> {
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
        let details = pending.as_ref().ok().and_then(Option::as_ref).map(|r| format!("<dl><dt>Original folder</dt><dd>{}</dd><dt>Requested folder</dt><dd>{}</dd></dl>", escape_html(r.source()), escape_html(&r.destination()))).unwrap_or_default();
        let check = if pending.as_ref().is_ok_and(|p| p.is_some()) {
            format!("<form method=\"post\" action=\"/settings/folders/rename/check\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button name=\"confirm\" value=\"check\">Check current result</button></form>", escape_html(&session.record.csrf_token))
        } else {
            String::new()
        };
        HandledHttpResponse { response: html_response(code, if code == 200 { "OK" } else if code == 400 { "Bad Request" } else if code == 409 { "Conflict" } else { "Service Unavailable" }, "Check rename result", crate::html::TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><h1>Check rename result</h1><p role=\"status\">{}</p>{details}{check}<p><a href=\"/settings?section=copies\">Inspect Copies &amp; Folders</a></p></main>", crate::http_ui::app_header(&session.record.canonical_username, &session.record.csrf_token, "settings-copies"), escape_html(notice)))), audit_events: audit }
    }
}
