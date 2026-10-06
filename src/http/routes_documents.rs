//! Authenticated account-private Documents surface. Every write is CSRF-bound.
use super::*;
use crate::documents::{Error as DocumentError, Index, State};
use std::time::{SystemTime, UNIX_EPOCH};

fn status(error: DocumentError) -> (u16, &'static str, &'static str) {
    match error {
        DocumentError::Invalid => (400, "Bad Request", "The document request is invalid."),
        DocumentError::NotFound => (404, "Not Found", "That document is unavailable."),
        DocumentError::Stale => (409, "Conflict", "Documents changed. Reload before trying again."),
        DocumentError::Limit => (409, "Conflict", "The document or storage limit was reached."),
        DocumentError::Busy => (429, "Too Many Requests", "A document change is already in progress."),
        DocumentError::Unavailable => (503, "Service Unavailable", "Document storage or its shared quota authority is unavailable."),
        DocumentError::PreDispatchUnavailable => (503, "Service Unavailable", "Document storage or its shared quota authority is unavailable. Nothing was changed."),
        DocumentError::ConfirmedNoWrite => (503, "Service Unavailable", "The storage operation was refused and exact inspection confirmed no change. Reload before trying again."),
        DocumentError::Unconfirmed => (503, "Service Unavailable", "A document change could not be confirmed. Do not repeat it until the current state is reconciled."),
    }
}

fn error_page(session: &ValidatedSession, error: DocumentError) -> HttpResponse {
    let (code, reason, text) = status(error);
    html_response(code, reason, "Documents", TrustedHtml::from_template(format!(
        "{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><section class=\"content-pane\"><h1>Documents</h1><p role=\"alert\">{}</p><a href=\"/documents\">Reload Documents</a></section></main>",
        crate::http_ui::app_header(&session.record.canonical_username, &session.record.csrf_token, "documents"), escape_html(text)
    )))
}

fn revision(form: &BTreeMap<String, String>) -> Result<u64, DocumentError> {
    let raw = form.get("revision").ok_or(DocumentError::Invalid)?;
    let value = raw.parse::<u64>().map_err(|_| DocumentError::Invalid)?;
    if value.to_string() != *raw {
        return Err(DocumentError::Invalid);
    }
    Ok(value)
}

fn selected_option(value: &str, current: &str) -> &'static str {
    if value == current {
        " selected"
    } else {
        ""
    }
}

fn render_page(
    session: &ValidatedSession,
    index: &Index,
    request: &HttpRequest,
    quota: Option<crate::documents::QuotaStatus>,
) -> TrustedHtml {
    let quota_ready = quota.is_some();
    let query = request
        .query_params
        .get("q")
        .map(String::as_str)
        .unwrap_or("");
    let sort = request
        .query_params
        .get("sort")
        .map(String::as_str)
        .unwrap_or("modified");
    let view = request
        .query_params
        .get("view")
        .map(String::as_str)
        .unwrap_or("list");
    let bin = request.query_params.get("bin").map(String::as_str) == Some("1");
    let folder_id = request
        .query_params
        .get("folder")
        .map(String::as_str)
        .unwrap_or("");
    let selected = request.query_params.get("selected").map(String::as_str);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs());
    let mut documents: Vec<_> = index
        .documents
        .iter()
        .filter(|doc| {
            if bin {
                doc.state == State::InBin
            } else {
                doc.state == State::Available
            }
        })
        .filter(|doc| bin || doc.folder == folder_id)
        .filter(|doc| doc.name.to_lowercase().contains(&query.to_lowercase()))
        .collect();
    match sort {
        "name" => documents.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
        "type" => documents.sort_by(|a, b| a.media_type.cmp(&b.media_type)),
        "size" => documents.sort_by(|a, b| a.size.cmp(&b.size)),
        _ => documents.sort_by(|a, b| b.modified_at.cmp(&a.modified_at)),
    }
    let mut body = format!(
        "{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><section class=\"content-pane\"><h1>Documents</h1><p>Private files stored under the same mailbox quota. {} of {} files; {} of {} MiB additional document limit used. Downloads are attachments only.</p>",
        crate::http_ui::app_header(&session.record.canonical_username, &session.record.csrf_token, "documents"),
        index.documents.len(), crate::documents::MAX_DOCUMENTS,
        index.used_bytes() / (1024 * 1024), crate::documents::MAX_ACCOUNT_BYTES / (1024 * 1024),
    );
    if let Some(current) = quota {
        body.push_str(&format!(
            "<p>Shared mailbox and Documents storage: {} KiB used of {} KiB current account limit.</p>",
            current.used_bytes / 1024, current.limit_bytes / 1024
        ));
    }
    if quota_ready && !index.has_unconfirmed_change() {
        body.push_str(&format!("<form method=\"post\" action=\"/documents/upload\" enctype=\"multipart/form-data\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\"><label for=\"document-file\">Upload a file</label><input id=\"document-file\" type=\"file\" name=\"attachment\" required><button type=\"submit\">Upload</button></form><p>Maximum 10 MiB per file. Files in Bin still count toward storage.</p>", escape_html(&session.record.csrf_token), index.revision));
        body.push_str(&format!("<form method=\"post\" action=\"/documents/folders\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\"><label for=\"folder-name\">New folder</label><input id=\"folder-name\" name=\"name\" maxlength=\"200\" required><button type=\"submit\">Create folder</button></form>", escape_html(&session.record.csrf_token), index.revision));
    } else if !quota_ready {
        body.push_str("<p class=\"notice notice-error\" role=\"status\">Uploads and storage changes are unavailable because the shared mailbox quota authority is not ready.</p>");
    }
    if index.has_unconfirmed_change() {
        body.push_str("<p class=\"notice notice-error\" role=\"alert\">A prior document operation is unconfirmed. Further changes are unavailable pending reconciliation.</p>");
        body.push_str(
            "<section aria-label=\"Pending document changes\"><h2>Pending changes</h2><ul>",
        );
        for pending in index.documents.iter().filter(|doc| {
            matches!(
                doc.state,
                State::Uploading | State::MovingToBin | State::Restoring | State::Deleting
            )
        }) {
            body.push_str(&format!("<li>{} · {:?}<form method=\"post\" action=\"/documents/reconcile\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\"><input type=\"hidden\" name=\"id\" value=\"{}\"><button type=\"submit\">Check current storage state</button></form></li>", escape_html(&pending.name), pending.state, escape_html(&session.record.csrf_token), index.revision, pending.id));
        }
        body.push_str("</ul><p>Checking does not repeat the storage change. Wait five minutes after an interrupted operation before checking.</p></section>");
    }
    let scope_field = if bin {
        "<input type=\"hidden\" name=\"bin\" value=\"1\">".to_string()
    } else if folder_id.is_empty() {
        String::new()
    } else {
        format!(
            "<input type=\"hidden\" name=\"folder\" value=\"{}\">",
            folder_id
        )
    };
    body.push_str(&format!(
        "<form method=\"get\" action=\"/documents\">{}<label for=\"documents-search\">Search file names</label><input id=\"documents-search\" name=\"q\" maxlength=\"200\" value=\"{}\"><label for=\"documents-sort\">Sort</label><select id=\"documents-sort\" name=\"sort\"><option value=\"modified\"{}>Recent</option><option value=\"name\"{}>Name</option><option value=\"type\"{}>Type</option><option value=\"size\"{}>Size</option></select><label for=\"documents-view\">View</label><select id=\"documents-view\" name=\"view\"><option value=\"list\"{}>List</option><option value=\"grid\"{}>Grid</option></select><button type=\"submit\">Apply</button></form><p><a href=\"/documents\">Files</a> · <a href=\"/documents?bin=1\">Bin</a></p><div class=\"document-{}\"><h2>{}</h2>",
        scope_field,
        escape_html(query),
        selected_option("modified", sort), selected_option("name", sort),
        selected_option("type", sort), selected_option("size", sort),
        selected_option("list", view), selected_option("grid", view),
        escape_html(view), if bin { "Bin" } else { "Files" }
    ));
    body.push_str("<nav aria-label=\"Document folders\"><a href=\"/documents\">Root folder</a>");
    for folder in &index.folders {
        body.push_str(&format!(
            " · <a href=\"/documents?folder={}\">{}</a>",
            folder.id,
            escape_html(&folder.name)
        ));
    }
    body.push_str("</nav>");
    if documents.is_empty() {
        body.push_str("<p>No documents in this view.</p>");
    } else {
        body.push_str("<ul class=\"document-list\">");
        for document in documents {
            let is_selected = selected == Some(document.id.as_str());
            body.push_str(&format!(
                "<li><strong dir=\"auto\">{}</strong> <span>{} bytes · {} · modified {} · owner {}</span> ",
                escape_html(&document.name),
                document.size,
                escape_html(&document.media_type), document.modified_at,
                escape_html(&session.record.canonical_username)
            ));
            if is_selected {
                body.push_str("<strong>Selected</strong> ");
            } else {
                let mut selection = vec![format!("selected={}", document.id)];
                if bin {
                    selection.push("bin=1".into());
                } else if !folder_id.is_empty() {
                    selection.push(format!("folder={folder_id}"));
                }
                if !query.is_empty() {
                    selection.push(format!("q={}", url_encode(query)));
                }
                selection.push(format!("sort={sort}"));
                selection.push(format!("view={view}"));
                body.push_str(&format!(
                    "<a href=\"/documents?{}\">Select</a> ",
                    escape_html(&selection.join("&"))
                ));
            }
            if bin {
                if let Some(binned_at) = document.binned_at {
                    let remaining = crate::documents::BIN_RETENTION_SECONDS
                        .saturating_sub(now.saturating_sub(binned_at));
                    body.push_str(&format!(
                        "<span>Bin retention: {} days remaining; expired items require confirmed cleanup.</span> ",
                        remaining.div_ceil(86_400)
                    ));
                }
            }
            if !bin {
                body.push_str(&format!(
                    "<a href=\"/documents/download?id={}\">Download</a>",
                    document.id
                ));
            }
            if is_selected {
                body.push_str("<details><summary>More actions</summary>");
            }
            if is_selected && quota_ready && !index.has_unconfirmed_change() {
                if !bin {
                    body.push_str(&format!("<form method=\"post\" action=\"/documents/folder\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\"><input type=\"hidden\" name=\"id\" value=\"{}\"><label>Move to folder <select name=\"folder_id\"><option value=\"\">Root</option>", escape_html(&session.record.csrf_token), index.revision, document.id));
                    for folder in &index.folders {
                        body.push_str(&format!(
                            "<option value=\"{}\">{}</option>",
                            folder.id,
                            escape_html(&folder.name)
                        ));
                    }
                    body.push_str("</select></label><button type=\"submit\">Move</button></form>");
                }
                body.push_str(&format!(
                    "<form method=\"post\" action=\"/documents/{}\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\"><input type=\"hidden\" name=\"id\" value=\"{}\"><button type=\"submit\">{}</button></form>",
                    if bin { "restore" } else { "bin" }, escape_html(&session.record.csrf_token),
                    index.revision, document.id, if bin { "Restore" } else { "Move to Bin" }
                ));
            }
            if is_selected && bin && !index.has_unconfirmed_change() {
                body.push_str(&format!(
                    " <a href=\"/documents/delete?id={}\">Review permanent deletion</a>",
                    document.id
                ));
            }
            if is_selected {
                body.push_str("</details>");
            }
            body.push_str("</li>");
        }
        body.push_str("</ul>");
    }
    body.push_str("</div></section></main>");
    TrustedHtml::from_template(body)
}

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_document_reconcile(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let result = (|| {
            if !allows_urlencoded_request_body(
                request.headers.get("content-type").map(String::as_str),
            ) {
                return Err(DocumentError::Invalid);
            }
            let form = parse_urlencoded_form(&request.body, 3, 4096)
                .map_err(|_| DocumentError::Invalid)?;
            if form.len() != 3 {
                return Err(DocumentError::Invalid);
            }
            if let Some(response) = self.require_valid_csrf(
                request,
                form.get("csrf_token").map(String::as_str),
                &session,
                context,
            ) {
                return Ok(response);
            }
            self.gateway.reconcile_document(
                &session,
                revision(&form)?,
                form.get("id").ok_or(DocumentError::Invalid)?,
            )?;
            Ok(HandledHttpResponse {
                response: redirect_response(303, "See Other", "/documents"),
                audit_events: vec![],
            })
        })();
        match result {
            Ok(mut response) => {
                response.audit_events.extend(audit_events);
                response
            }
            Err(error) => HandledHttpResponse {
                response: error_page(&session, error),
                audit_events,
            },
        }
    }

    pub(super) fn handle_document_folder_create(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let result = (|| {
            if !allows_urlencoded_request_body(
                request.headers.get("content-type").map(String::as_str),
            ) {
                return Err(DocumentError::Invalid);
            }
            let form = parse_urlencoded_form(&request.body, 3, 4096)
                .map_err(|_| DocumentError::Invalid)?;
            if form.len() != 3 {
                return Err(DocumentError::Invalid);
            }
            if let Some(response) = self.require_valid_csrf(
                request,
                form.get("csrf_token").map(String::as_str),
                &session,
                context,
            ) {
                return Ok(response);
            }
            let name = form.get("name").ok_or(DocumentError::Invalid)?;
            self.gateway
                .create_document_folder(&session, revision(&form)?, name)?;
            Ok(HandledHttpResponse {
                response: redirect_response(303, "See Other", "/documents"),
                audit_events: vec![],
            })
        })();
        match result {
            Ok(mut response) => {
                response.audit_events.extend(audit_events);
                response
            }
            Err(error) => HandledHttpResponse {
                response: error_page(&session, error),
                audit_events,
            },
        }
    }

    pub(super) fn handle_document_folder_move(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let result = (|| {
            if !allows_urlencoded_request_body(
                request.headers.get("content-type").map(String::as_str),
            ) {
                return Err(DocumentError::Invalid);
            }
            let form = parse_urlencoded_form(&request.body, 4, 4096)
                .map_err(|_| DocumentError::Invalid)?;
            if form.len() != 4 {
                return Err(DocumentError::Invalid);
            }
            if let Some(response) = self.require_valid_csrf(
                request,
                form.get("csrf_token").map(String::as_str),
                &session,
                context,
            ) {
                return Ok(response);
            }
            let id = form.get("id").ok_or(DocumentError::Invalid)?;
            let folder_id = form.get("folder_id").ok_or(DocumentError::Invalid)?;
            self.gateway
                .move_document_to_folder(&session, revision(&form)?, id, folder_id)?;
            Ok(HandledHttpResponse {
                response: redirect_response(303, "See Other", "/documents"),
                audit_events: vec![],
            })
        })();
        match result {
            Ok(mut response) => {
                response.audit_events.extend(audit_events);
                response
            }
            Err(error) => HandledHttpResponse {
                response: error_page(&session, error),
                audit_events,
            },
        }
    }

    pub(super) fn handle_document_delete_review(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let result = (|| {
            if request.query_params.len() != 1 {
                return Err(DocumentError::Invalid);
            }
            let id = request
                .query_params
                .get("id")
                .ok_or(DocumentError::Invalid)?;
            let index = self.gateway.load_documents(&session)?;
            let document = index
                .documents
                .iter()
                .find(|doc| doc.id == *id && doc.state == State::InBin)
                .ok_or(DocumentError::NotFound)?;
            Ok(TrustedHtml::from_template(format!(
                "{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><section class=\"content-pane\"><h1>Delete document permanently?</h1><p>Delete <strong>{}</strong> from Bin? This cannot be undone.</p><form method=\"post\" action=\"/documents/delete\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\"><input type=\"hidden\" name=\"id\" value=\"{}\"><button type=\"submit\" name=\"confirm\" value=\"delete\">Delete permanently</button></form><a href=\"/documents?bin=1\">Keep document</a></section></main>",
                crate::http_ui::app_header(&session.record.canonical_username, &session.record.csrf_token, "documents"),
                escape_html(&document.name), escape_html(&session.record.csrf_token), index.revision, document.id
            )))
        })();
        HandledHttpResponse {
            response: match result {
                Ok(body) => html_response(200, "OK", "Delete document", body),
                Err(error) => error_page(&session, error),
            },
            audit_events,
        }
    }

    pub(super) fn handle_document_delete_confirm(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let result = (|| {
            if !allows_urlencoded_request_body(
                request.headers.get("content-type").map(String::as_str),
            ) {
                return Err(DocumentError::Invalid);
            }
            let form = parse_urlencoded_form(&request.body, 4, 4096)
                .map_err(|_| DocumentError::Invalid)?;
            if form.len() != 4 || form.get("confirm").map(String::as_str) != Some("delete") {
                return Err(DocumentError::Invalid);
            }
            if let Some(response) = self.require_valid_csrf(
                request,
                form.get("csrf_token").map(String::as_str),
                &session,
                context,
            ) {
                return Ok(response);
            }
            let id = form.get("id").ok_or(DocumentError::Invalid)?;
            self.gateway
                .delete_document(&session, revision(&form)?, id)?;
            Ok(HandledHttpResponse {
                response: redirect_response(303, "See Other", "/documents?bin=1"),
                audit_events: vec![],
            })
        })();
        match result {
            Ok(mut response) => {
                response.audit_events.extend(audit_events);
                response
            }
            Err(error) => HandledHttpResponse {
                response: error_page(&session, error),
                audit_events,
            },
        }
    }

    pub(super) fn handle_documents(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let result = (|| {
            if request.query_params.keys().any(|key| {
                !["q", "sort", "view", "bin", "folder", "selected"].contains(&key.as_str())
            }) || request
                .query_params
                .get("q")
                .is_some_and(|value| value.len() > 200)
                || request.query_params.get("sort").is_some_and(|value| {
                    !["modified", "name", "type", "size"].contains(&value.as_str())
                })
                || request
                    .query_params
                    .get("view")
                    .is_some_and(|value| !["list", "grid"].contains(&value.as_str()))
                || request
                    .query_params
                    .get("bin")
                    .is_some_and(|value| value != "1")
                || request.query_params.get("folder").is_some_and(|value| {
                    value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                || request.query_params.get("selected").is_some_and(|value| {
                    value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            {
                return Err(DocumentError::Invalid);
            }
            let index = self.gateway.load_documents(&session)?;
            if request
                .query_params
                .get("folder")
                .is_some_and(|id| !index.folders.iter().any(|folder| folder.id == *id))
            {
                return Err(DocumentError::NotFound);
            }
            if request.query_params.get("selected").is_some_and(|id| {
                !index.documents.iter().any(|document| {
                    document.id == *id
                        && if request.query_params.get("bin").map(String::as_str) == Some("1") {
                            document.state == State::InBin
                        } else {
                            document.state == State::Available
                                && document.folder
                                    == request
                                        .query_params
                                        .get("folder")
                                        .map(String::as_str)
                                        .unwrap_or("")
                        }
                })
            }) {
                return Err(DocumentError::NotFound);
            }
            Ok(render_page(
                &session,
                &index,
                request,
                self.gateway.documents_quota_status(&session),
            ))
        })();
        HandledHttpResponse {
            response: match result {
                Ok(body) => html_response(200, "OK", "Documents", body),
                Err(error) => error_page(&session, error),
            },
            audit_events,
        }
    }

    pub(super) fn handle_document_upload(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let result = (|| {
            let policy = ComposePolicy {
                max_attachments: 1,
                attachment_filename_max_len: crate::documents::MAX_NAME_BYTES,
                ..ComposePolicy::default()
            };
            let parsed = parse_compose_form(
                &request.body,
                request.headers.get("content-type").map(String::as_str),
                4,
                self.policy.max_upload_body_bytes,
                policy,
            )
            .map_err(|_| DocumentError::Invalid)?;
            if parsed.upload_error.is_some()
                || parsed
                    .fields
                    .keys()
                    .any(|key| !["csrf_token", "revision"].contains(&key.as_str()))
                || parsed.attachments.len() != 1
            {
                return Err(DocumentError::Invalid);
            }
            if let Some(response) = self.require_valid_csrf(
                request,
                parsed.fields.get("csrf_token").map(String::as_str),
                &session,
                context,
            ) {
                return Ok(response);
            }
            let attachment = &parsed.attachments[0];
            let revision = revision(&parsed.fields)?;
            self.gateway.upload_document(
                &session,
                revision,
                &attachment.filename,
                &attachment.content_type,
                &attachment.body,
            )?;
            Ok(HandledHttpResponse {
                response: redirect_response(303, "See Other", "/documents"),
                audit_events: vec![],
            })
        })();
        match result {
            Ok(mut response) => {
                response.audit_events.extend(audit_events);
                response
            }
            Err(error) => HandledHttpResponse {
                response: error_page(&session, error),
                audit_events,
            },
        }
    }

    pub(super) fn handle_document_download(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let result = (|| {
            if request.query_params.len() != 1 {
                return Err(DocumentError::Invalid);
            }
            let id = request
                .query_params
                .get("id")
                .ok_or(DocumentError::Invalid)?;
            self.gateway.download_document(&session, id)
        })();
        HandledHttpResponse {
            response: match result {
                Ok((name, bytes)) => {
                    crate::http_support::download_bytes(&name, "application/octet-stream", &bytes)
                }
                Err(error) => error_page(&session, error),
            },
            audit_events,
        }
    }

    pub(super) fn handle_document_move(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
        restore: bool,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let result = (|| {
            if !allows_urlencoded_request_body(
                request.headers.get("content-type").map(String::as_str),
            ) {
                return Err(DocumentError::Invalid);
            }
            let form = parse_urlencoded_form(&request.body, 3, 4096)
                .map_err(|_| DocumentError::Invalid)?;
            if form
                .keys()
                .any(|key| !["csrf_token", "revision", "id"].contains(&key.as_str()))
            {
                return Err(DocumentError::Invalid);
            }
            if let Some(response) = self.require_valid_csrf(
                request,
                form.get("csrf_token").map(String::as_str),
                &session,
                context,
            ) {
                return Ok(response);
            }
            let id = form.get("id").ok_or(DocumentError::Invalid)?;
            let expected = revision(&form)?;
            if restore {
                self.gateway.restore_document(&session, expected, id)?;
            } else {
                self.gateway.bin_document(&session, expected, id)?;
            }
            Ok(HandledHttpResponse {
                response: redirect_response(303, "See Other", "/documents"),
                audit_events: vec![],
            })
        })();
        match result {
            Ok(mut response) => {
                response.audit_events.extend(audit_events);
                response
            }
            Err(error) => HandledHttpResponse {
                response: error_page(&session, error),
                audit_events,
            },
        }
    }
}
