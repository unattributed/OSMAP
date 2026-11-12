//! Owned receipts plus fresh account facts; never retries an uncertain Rename.
use super::*;
use crate::folder_rename::{CheckOutcome, Outcome, RenameFolderRequest};

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_deleted_folders(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        if !request.query_params.is_empty() {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid folder selection",
                    "<p>No folder was changed.</p>",
                ),
                audit_events,
            };
        }
        let receipts = self.gateway.folder_disposition_receipts(&session);
        HandledHttpResponse {
            response: html_response(
                if receipts.is_ok() { 200 } else { 503 },
                if receipts.is_ok() {
                    "OK"
                } else {
                    "Service Unavailable"
                },
                "Deleted folders / Restore",
                crate::http_ui::render_deleted_folders(
                    &session.record.canonical_username,
                    &session.record.csrf_token,
                    receipts.as_deref().ok(),
                ),
            ),
            audit_events,
        }
    }
    pub(super) fn handle_folder_disposition(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
        restoring: bool,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let post = request.method == HttpMethod::Post;
        let fields = if post {
            if !request.query_params.is_empty()
                || !allows_urlencoded_request_body(
                    request.headers.get("content-type").map(String::as_str),
                )
            {
                None
            } else {
                parse_urlencoded_form(&request.body, 3, 4096).ok()
            }
        } else {
            Some(request.query_params.clone())
        };
        let fields = fields.filter(|f| {
            f.keys().all(|key| {
                if post {
                    matches!(key.as_str(), "csrf_token" | "expected_request" | "confirm")
                } else if restoring {
                    key == "id"
                } else {
                    key == "source"
                }
            })
        });
        let Some(fields) = fields else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid folder request",
                    "<p>No folder was changed.</p>",
                ),
                audit_events,
            };
        };
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
        let get = |key: &str| fields.get(key).map(String::as_str).unwrap_or("");
        let supplied = if post {
            serde_json::from_str::<RenameFolderRequest>(get("expected_request"))
                .ok()
                .filter(|r| {
                    r.account() == session.record.canonical_username
                        && r.validate().is_ok()
                        && r.disposition().is_some_and(|p| p.restoring() == restoring)
                })
        } else {
            None
        };
        if post && (supplied.is_none() || !matches!(get("confirm"), "review" | "apply")) {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid folder review",
                    "<p>No folder was changed.</p>",
                ),
                audit_events,
            };
        }
        let (guard, event) =
            match self.acquire_mailbox_budget(context, &session, "folder_disposition") {
                Ok(v) => v,
                Err(r) => return r,
            };
        audit_events.push(event);
        let prepared = if post && get("confirm") == "apply" {
            // Apply consumes the already typed, account-bound review request.
            // Runtime's execute engine reloads current roles, identities and
            // receipt state under its locks before its single native dispatch.
            // Re-preparing here adds remote reads without granting authority.
            supplied
                .clone()
                .ok_or(crate::folder_create::Refusal::Invalid)
        } else if restoring {
            let id = supplied
                .as_ref()
                .and_then(|r| r.disposition())
                .map(|p| p.context().receipt_id.as_str())
                .unwrap_or_else(|| get("id"));
            self.gateway
                .folder_disposition_receipts(&session)
                .and_then(|receipts| {
                    let receipt = receipts
                        .into_iter()
                        .find(|r| r.id == id)
                        .ok_or(crate::folder_create::Refusal::Invalid)?;
                    if let Some(expected) = &supplied {
                        if !receipt.matches(expected)
                            || receipt.state != crate::folder_disposition::State::Binned
                        {
                            return Err(crate::folder_create::Refusal::Stale);
                        }
                        Ok(expected.clone())
                    } else {
                        receipt.restore_request(&session.record.canonical_username)
                    }
                })
        } else {
            let source = supplied
                .as_ref()
                .map(|r| r.source())
                .unwrap_or_else(|| get("source"));
            self.gateway
                .prepare_folder_bin(context, &session, source)
                .and_then(|fresh| {
                    if let Some(expected) = &supplied {
                        let a = expected
                            .disposition()
                            .ok_or(crate::folder_create::Refusal::Invalid)?
                            .context();
                        let b = fresh
                            .disposition()
                            .ok_or(crate::folder_create::Refusal::Unavailable)?
                            .context();
                        if expected.account() != fresh.account()
                            || expected.source() != fresh.source()
                            || expected.source_guid() != fresh.source_guid()
                            || expected.source_parent_guid() != fresh.source_parent_guid()
                            || expected.parent() != fresh.parent()
                            || expected.parent_guid() != fresh.parent_guid()
                            || expected.descendants() != fresh.descendants()
                            || a.bin != b.bin
                            || a.bin_guid != b.bin_guid
                            || a.bin_revision != b.bin_revision
                        {
                            return Err(crate::folder_create::Refusal::Stale);
                        }
                        Ok(expected.clone())
                    } else {
                        Ok(fresh)
                    }
                })
        };
        let (code, stage, notice, prepared) = match prepared {
            Err(_) => (409, "refused", Some("The folder, receipt, Bin preference or current authority changed or is unavailable. No action was attempted. Reload Folders."), None),
            Ok(prepared) if !post || get("confirm") == "review" => (200, if post { "review" } else { "entry" }, None, Some(prepared)),
            Ok(prepared) => {
                let outcome = self.gateway.apply_folder_disposition(context, &session, &prepared);
                if outcome == Outcome::Renamed {
                    audit_events.push(self.release_request_budget(guard, "folder_disposition", context, &session));
                    return HandledHttpResponse { response: redirect_response(303, "See Other", if restoring { "/folders" } else { "/folders/deleted" }), audit_events };
                }
                if outcome == Outcome::Unknown { (503, "pending", Some("The original result is unconfirmed. No action was retried. Check the original result; folder editing and mail-destination changes remain paused."), Some(prepared)) }
                else { (409, "refused", Some("The action was refused. No automatic retry was made. Reload and review current folders."), Some(prepared)) }
            }
        };
        audit_events.push(self.release_request_budget(
            guard,
            "folder_disposition",
            context,
            &session,
        ));
        HandledHttpResponse {
            response: html_response(
                code,
                if code == 200 {
                    "OK"
                } else if code == 503 {
                    "Service Unavailable"
                } else {
                    "Conflict"
                },
                "Folder preservation",
                crate::http_ui::render_folder_disposition(
                    &session.record.canonical_username,
                    &session.record.csrf_token,
                    restoring,
                    prepared.as_ref(),
                    stage,
                    notice,
                ),
            ),
            audit_events,
        }
    }
    pub(super) fn handle_folder_disposition_check(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let mut notice = "This checks durable reservation state or the original helper witness and current folder identities. It never retries a move or restore.";
        let mut code = 200;
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
            let (guard, event) =
                match self.acquire_mailbox_budget(context, &session, "folder_disposition_check") {
                    Ok(v) => v,
                    Err(r) => return r,
                };
            audit_events.push(event);
            match self.gateway.check_folder_disposition(context, &session) {
                CheckOutcome::Renamed { .. } => notice = "The original helper result and current identities confirm the move or restore. Private metadata has been reconciled. No move was retried.",
                CheckOutcome::Unchanged => notice = "The durable record confirms this action was not dispatched, or the original helper confirmed no mutation. No action was retried.",
                CheckOutcome::NoPending => notice = "No folder preservation result is pending.",
                CheckOutcome::Unavailable | CheckOutcome::Unconfirmed => { code = 409; notice = "The original result remains unconfirmed or unavailable. No action was retried; editing remains paused."; },
            }
            audit_events.push(self.release_request_budget(
                guard,
                "folder_disposition_check",
                context,
                &session,
            ));
        } else if !request.query_params.is_empty() {
            code = 400;
        }
        let pending = self
            .gateway
            .pending_folder_rename(&session)
            .ok()
            .flatten()
            .filter(|r| {
                r.account() == session.record.canonical_username && r.disposition().is_some()
            });
        let retained = pending
            .as_ref()
            .map(super::routes_folder_rename::retained_folder_notice)
            .unwrap_or_default();
        let recovery = if pending
            .as_ref()
            .is_some_and(|r| !r.descendants().is_empty())
        {
            "<p><a href=\"/settings/folders/rename/recover\">Review bounded partial recovery</a></p>"
        } else {
            ""
        };
        HandledHttpResponse { response: html_response(code, if code == 200 { "OK" } else { "Conflict" }, "Check folder result", crate::html::TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><h1>Check folder preservation result</h1><p role=\"status\">{}</p>{retained}<form method=\"post\" action=\"/settings/folders/disposition/check\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button name=\"confirm\" value=\"check\">Check original result</button></form>{recovery}<a href=\"/folders/deleted\">Deleted folders / Restore</a></main>", crate::http_ui::app_header(&session.record.canonical_username, &session.record.csrf_token, "folders"), escape_html(notice), escape_html(&session.record.csrf_token)))), audit_events }
    }
}
