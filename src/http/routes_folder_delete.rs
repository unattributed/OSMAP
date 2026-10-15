//! Current authenticated authority and one explicit empty-container confirmation.
use super::*;
use crate::folder_delete::{CheckOutcome, DeleteFolderRequest, Outcome};
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_folder_delete(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit) = match self.require_validated_session(request, context) {
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
                parse_urlencoded_form(&request.body, 5, 2048).ok()
            }
        } else {
            Some(request.query_params.clone())
        };
        let Some(fields) = fields.filter(|f| {
            f.keys().all(|k| {
                if post {
                    matches!(
                        k.as_str(),
                        "csrf_token" | "source" | "source_guid" | "parent_guid" | "confirm"
                    )
                } else {
                    k == "source"
                }
            })
        }) else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid deletion",
                    "<p>No folder was changed.</p>",
                ),
                audit_events: audit,
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
        let get = |n: &str| fields.get(n).map(String::as_str).unwrap_or("");
        let source = get("source");
        let mut source_guid = get("source_guid").to_owned();
        let mut parent_guid = get("parent_guid").to_owned();
        let mut code = 200;
        let mut notice = None;
        let mut pending = false;
        let state = self.gateway.pending_folder_delete(&session);
        if state.as_ref().is_ok_and(|v| v.is_some()) {
            code = 409;
            pending = true;
            notice =
                Some("The original deletion result remains pending. Check it without retrying.");
        } else if state.is_err()
            || !self
                .gateway
                .pending_folder_rename(&session)
                .is_ok_and(|v| v.is_none())
        {
            code = 503;
            notice=Some("Folder mutation state is unavailable or another original action is pending. Inspect current results before changing a folder.");
        } else if source.len() > 255
            || source_guid.len() > 64
            || parent_guid.len() > 64
            || (post && get("confirm") != "delete-empty")
        {
            code = 400;
            notice=Some("Deletion requires an exact folder and explicit confirmation. No folder was changed.");
        } else if let Some((snapshot, status, parent, _)) =
            self.rename_preflight(context, &session, source, "", &mut audit)
        {
            if !post {
                source_guid = status.guid().into();
                parent_guid = parent.guid().into();
            }
            let checked = DeleteFolderRequest::new(
                &session.record.canonical_username,
                source,
                &source_guid,
                &parent_guid,
            )
            .and_then(|r| {
                r.validate_before(&snapshot, &status, &parent)?;
                let names =
                    crate::folder_rename::protected_destinations(&self.gateway, context, &session)?;
                if crate::folder_rename::role_conflict(&names, source, source) {
                    return Err(crate::folder_create::Refusal::Invalid);
                }
                Ok(r)
            });
            match checked {
                Err(_) => {
                    code = 409;
                    notice=Some("Only current empty private leaf folders can be deleted. System folders, saved destinations, stale identities and populated folders are protected.");
                }
                Ok(r) if post => {
                    let (guard, event) =
                        match self.acquire_mailbox_budget(context, &session, "folder_delete") {
                            Ok(v) => v,
                            Err(r) => return r,
                        };
                    audit.push(event);
                    let outcome = self.gateway.delete_folder(context, &session, &r);
                    audit.push(
                        LogEvent::new(
                            LogLevel::Info,
                            crate::logging::EventCategory::Mailbox,
                            "folder_delete_result",
                            "empty folder deletion returned a bounded outcome",
                        )
                        .with_field("confirmed", (outcome == Outcome::Deleted).to_string()),
                    );
                    audit.push(self.release_request_budget(
                        guard,
                        "folder_delete",
                        context,
                        &session,
                    ));
                    if outcome == Outcome::Deleted {
                        return HandledHttpResponse {
                            response: redirect_response(
                                303,
                                "See Other",
                                "/settings?section=copies",
                            ),
                            audit_events: audit,
                        };
                    }
                    pending = outcome == Outcome::Unknown;
                    code = if pending { 503 } else { 409 };
                    notice = Some(if pending {
                        "Deletion could not be confirmed. No retry was made. Check the original result before any further folder changes."
                    } else {
                        "Deletion was refused. Reload current folders; no message disposal was attempted."
                    });
                }
                Ok(_) => (),
            }
        } else {
            code = 503;
            notice=Some("Current folder ownership and status could not be verified. No deletion was attempted.");
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
                "Delete empty folder",
                crate::http_ui::render_folder_delete(crate::http_ui::DeletePageModel {
                    account: &session.record.canonical_username,
                    csrf: &session.record.csrf_token,
                    source,
                    source_guid: &source_guid,
                    parent_guid: &parent_guid,
                    review: code == 200,
                    pending,
                    notice,
                }),
            ),
            audit_events: audit,
        }
    }
    pub(super) fn handle_folder_delete_check(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let mut state = self.gateway.pending_folder_delete(&session);
        let mut code = if state.is_ok() { 200 } else { 503 };
        let mut notice="This check reads the original action and current identities. It never retries deletion.";
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
                f.len() == 2
                    && f.keys()
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
            if let Some(r) = self.require_valid_csrf(
                request,
                fields.get("csrf_token").map(String::as_str),
                &session,
                context,
            ) {
                return r;
            }
            let (guard, event) =
                match self.acquire_mailbox_budget(context, &session, "folder_delete_check") {
                    Ok(v) => v,
                    Err(r) => return r,
                };
            audit.push(event);
            let outcome = self.gateway.check_folder_delete(context, &session);
            audit.push(self.release_request_budget(
                guard,
                "folder_delete_check",
                context,
                &session,
            ));
            match outcome {
                CheckOutcome::Deleted => {
                    return HandledHttpResponse {
                        response: redirect_response(303, "See Other", "/settings?section=copies"),
                        audit_events: audit,
                    }
                }
                CheckOutcome::Unchanged => {
                    state = Ok(None);
                    notice="The helper confirms the original action performed no mutation; source and parent identities are unchanged. No retry was made."
                }
                CheckOutcome::NoPending => notice = "No deletion is pending.",
                CheckOutcome::Unavailable => {
                    code = 503;
                    notice = "Result authority is unavailable. Pending state is preserved."
                }
                CheckOutcome::Unconfirmed => {
                    code = 409;
                    notice="The original deletion remains unconfirmed. Pending state is preserved; no retry was made."
                }
            }
        } else if !request.query_params.is_empty() {
            code = 400;
        }
        let form = if state.as_ref().is_ok_and(|s| s.is_some()) {
            format!("<form method=\"post\" action=\"/settings/folders/delete/check\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button name=\"confirm\" value=\"check\">Check original result</button></form>",escape_html(&session.record.csrf_token))
        } else {
            String::new()
        };
        HandledHttpResponse{response:html_response(code,if code==200{"OK"}else if code==400{"Bad Request"}else if code==409{"Conflict"}else{"Service Unavailable"},"Check deletion result",crate::html::TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><h1>Check original deletion result</h1><p role=\"status\">{}</p>{form}<p><a href=\"/settings?section=copies\">Inspect folders</a></p></main>",crate::http_ui::app_header(&session.record.canonical_username,&session.record.csrf_token,"settings-copies"),escape_html(notice)))),audit_events:audit}
    }
}
