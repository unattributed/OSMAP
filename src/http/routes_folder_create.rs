//! Native, explicitly confirmed private subfolder creation.
use super::*;
use crate::folder_create::{CreateFolderRequest, Outcome, Refusal};
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn folder_create_preflight(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        parent: &str,
        audit: &mut Vec<LogEvent>,
    ) -> Option<(
        crate::folder_metadata::FolderSnapshot,
        crate::mailbox_status::MailboxStatus,
    )> {
        let (guard, event) = self
            .acquire_mailbox_budget(context, session, "folder_create_preflight")
            .ok()?;
        audit.push(event);
        let metadata = self.gateway.folder_metadata(context, session);
        let status = self.gateway.mailbox_status(context, session, parent);
        audit.extend(metadata.audit_events);
        audit.extend(status.audit_events);
        audit.push(self.release_request_budget(guard, "folder_create_preflight", context, session));
        if metadata.canonical_username != session.record.canonical_username
            || status.canonical_username != session.record.canonical_username
        {
            return None;
        }
        let snapshot = metadata.snapshot?;
        let status = status.status?;
        crate::folder_create::validate_creation_parent(
            &session.record.canonical_username,
            parent,
            &snapshot,
            &status,
        )
        .ok()?;
        Some((snapshot, status))
    }
    pub(super) fn handle_folder_create(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let post = request.method == HttpMethod::Post;
        let form = if post {
            if !request.query_params.is_empty()
                || !allows_urlencoded_request_body(
                    request.headers.get("content-type").map(String::as_str),
                )
            {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid folder request",
                        "<p>Reload Copies &amp; Folders.</p>",
                    ),
                    audit_events: audit,
                };
            }
            match parse_urlencoded_form(&request.body, 8, 4096) {
                Ok(v) => v,
                Err(_) => {
                    return HandledHttpResponse {
                        response: html_response(
                            400,
                            "Bad Request",
                            "Invalid folder request",
                            "<p>Reload Copies &amp; Folders.</p>",
                        ),
                        audit_events: audit,
                    }
                }
            }
        } else {
            request.query_params.clone()
        };
        if post {
            if let Some(mut r) = self.require_valid_csrf(
                request,
                form.get("csrf_token").map(String::as_str),
                &session,
                context,
            ) {
                r.response=html_response(403,"Forbidden","Creation refused",crate::http_ui::render_folder_create(&session.record.canonical_username,&session.record.csrf_token,form.get("parent").map(String::as_str).unwrap_or(""),"",form.get("leaf").map(String::as_str).unwrap_or(""),"refused",Some("The form could not be verified. No folder was created. Reload before trying again.")));
                return r;
            }
        }
        let get = |k: &str| form.get(k).map(String::as_str).unwrap_or("");
        let parent = get("parent");
        let leaf = get("leaf");
        let guid = get("parent_guid");
        let valid_fields = form.keys().all(|k| {
            if post {
                matches!(
                    k.as_str(),
                    "parent" | "leaf" | "parent_guid" | "csrf_token" | "action" | "confirm"
                )
            } else {
                k == "parent"
            }
        });
        let mut code = 200;
        let mut message = None;
        let mut stage = "entry";
        let mut current_guid = guid.to_owned();
        if !valid_fields
            || parent.len() > 255
            || leaf.len() > 255
            || guid.len() > 64
            || (post && !matches!(get("action"), "review" | "create"))
        {
            code = 400;
            message = Some("The folder request is invalid. Reload before trying again.");
            stage = "refused";
        } else if let Some((snapshot, status)) =
            self.folder_create_preflight(context, &session, parent, &mut audit)
        {
            if !post {
                current_guid = status.guid().into();
            } else {
                match CreateFolderRequest::new(
                    &session.record.canonical_username,
                    parent,
                    guid,
                    leaf,
                )
                .and_then(|r| r.validate_parent(&snapshot, &status).map(|_| r))
                {
                    Err(reason) => {
                        code = 409;
                        stage = "refused";
                        message=Some(match reason{Refusal::Stale=>"The parent folder changed. No folder was created. Reload before trying again.",Refusal::Invalid=>"The name or folder request is invalid. No folder was created.",_=>"Creation is unavailable or the folder already exists. No creation was attempted. Reload to inspect current folders."});
                    }
                    Ok(create) => {
                        if snapshot
                            .folder(&session.record.canonical_username, &create.child())
                            .is_ok()
                        {
                            code = 409;
                            stage = "refused";
                            message=Some("A folder with this name already exists. No creation was attempted. Reload to inspect it.");
                        } else if get("action") == "review" {
                            stage = "review";
                        } else if get("confirm") != "create" {
                            code = 400;
                            stage = "refused";
                            message = Some(
                                "Creation requires explicit confirmation. No folder was created.",
                            );
                        } else {
                            let (guard, event) = match self.acquire_mailbox_budget(
                                context,
                                &session,
                                "folder_create",
                            ) {
                                Ok(v) => v,
                                Err(r) => return r,
                            };
                            audit.push(event);
                            let result = self.gateway.create_folder(context, &session, &create);
                            audit.extend(result.audit_events);
                            audit.push(self.release_request_budget(
                                guard,
                                "folder_create",
                                context,
                                &session,
                            ));
                            stage = "refused";
                            match result.outcome {
                                Outcome::Created { .. } => {
                                    return HandledHttpResponse {
                                        response: redirect_response(
                                            303,
                                            "See Other",
                                            &format!(
                                                "/settings?section=copies&folder={}",
                                                url_encode(&create.child())
                                            ),
                                        ),
                                        audit_events: audit,
                                    }
                                }
                                Outcome::Conflict => {
                                    code = 409;
                                    message=Some("A folder with this name already exists. Reload to inspect it; no retry was made.");
                                }
                                Outcome::Unknown => {
                                    code = 503;
                                    message=Some("Creation could not be confirmed. The folder may exist. Reload and inspect the folder list before attempting another creation.");
                                }
                                Outcome::Refused(Refusal::Stale) => {
                                    code = 409;
                                    message=Some("The parent folder changed. Creation was refused. Reload before trying again.");
                                }
                                Outcome::Refused(_) => {
                                    code = 503;
                                    message=Some("Creation was refused. Reload to inspect current folders before trying again.");
                                }
                            }
                        }
                    }
                }
            }
        } else {
            code = 503;
            stage = "refused";
            message = Some(
                "This parent folder could not be verified for creation. Reload Copies & Folders.",
            );
        }
        HandledHttpResponse {
            response: html_response(
                code,
                if code == 200 {
                    "OK"
                } else if code == 409 {
                    "Conflict"
                } else if code == 400 {
                    "Bad Request"
                } else {
                    "Service Unavailable"
                },
                "New subfolder",
                crate::http_ui::render_folder_create(
                    &session.record.canonical_username,
                    &session.record.csrf_token,
                    parent,
                    &current_guid,
                    leaf,
                    stage,
                    message,
                ),
            ),
            audit_events: audit,
        }
    }
}
