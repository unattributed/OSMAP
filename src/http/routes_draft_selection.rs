//! Explicit review and revision-bound discard of at most ten saved drafts.
use super::*;
use crate::draft_list::{DraftListView, MAX_DRAFT_SELECTION};

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_draft_selection(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        if !allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
        {
            return HandledHttpResponse {
                response: invalid_selection(),
                audit_events,
            };
        }
        let form = match parse_urlencoded_form(
            &request.body,
            MAX_DRAFT_SELECTION + 5,
            self.policy.max_body_bytes,
        ) {
            Ok(form) => form,
            Err(_) => {
                return HandledHttpResponse {
                    response: invalid_selection(),
                    audit_events,
                }
            }
        };
        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return response;
        }
        let selected = match parse_selection(&form) {
            Ok(selected) => selected,
            Err(()) => {
                return HandledHttpResponse {
                    response: invalid_selection(),
                    audit_events,
                }
            }
        };
        let query = form
            .iter()
            .filter(|(key, _)| matches!(key.as_str(), "q" | "filter" | "sort"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let view = match DraftListView::parse(&query) {
            Ok(view) => view,
            Err(_) => {
                return HandledHttpResponse {
                    response: invalid_selection(),
                    audit_events,
                }
            }
        };
        let confirm = match form.get("stage").map(String::as_str) {
            Some("review") => false,
            Some("confirm") => true,
            _ => {
                return HandledHttpResponse {
                    response: invalid_selection(),
                    audit_events,
                }
            }
        };
        let mut summaries = Vec::new();
        // Check the whole selection before the first deletion. Each deletion
        // then checks its revision under the account lock again.
        for (id, revision) in &selected {
            let outcome = self.gateway.load_draft(context, &session, id);
            audit_events.extend(outcome.audit_events);
            match outcome.decision {
                BrowserDraftLoadDecision::Loaded {
                    canonical_username,
                    draft,
                } if canonical_username == session.record.canonical_username
                    && draft.canonical_username == canonical_username
                    && draft.draft_id == *id
                    && draft.revision == Some(*revision) =>
                {
                    summaries.push(draft.summary())
                }
                _ => return HandledHttpResponse {
                    response: selection_stopped(
                        &view,
                        0,
                        selected.len(),
                        "A selected draft changed or could not be loaded. Nothing was discarded.",
                    ),
                    audit_events,
                },
            }
        }
        if !confirm {
            return HandledHttpResponse {
                response: html_response(
                    200,
                    "OK",
                    "Review Draft Discard",
                    crate::http_ui::render_draft_selection_review(
                        &session.record.canonical_username,
                        &session.record.csrf_token,
                        &summaries,
                        &view,
                    ),
                ),
                audit_events,
            };
        }
        for (discarded, (id, revision)) in selected.iter().enumerate() {
            let outcome = self.gateway.delete_draft(context, &session, id, *revision);
            audit_events.extend(outcome.audit_events);
            if !matches!(outcome.decision, BrowserDraftDeleteDecision::Deleted) {
                return HandledHttpResponse { response: selection_stopped(&view, discarded, selected.len(), "Discard stopped because a selected draft changed or could not be removed. Remaining drafts were not discarded by this request."), audit_events };
            }
        }
        HandledHttpResponse {
            response: redirect_response(303, "See Other", &view.href()),
            audit_events,
        }
    }
}

fn parse_selection(form: &BTreeMap<String, String>) -> Result<Vec<(String, u64)>, ()> {
    let mut result = Vec::new();
    for (key, value) in form {
        if matches!(
            key.as_str(),
            "csrf_token" | "filter" | "sort" | "q" | "stage"
        ) {
            continue;
        }
        let id = key.strip_prefix("selected_").ok_or(())?;
        crate::draft::validate_draft_id(id).map_err(|_| ())?;
        let revision = value.parse::<u64>().map_err(|_| ())?;
        if value != &revision.to_string() {
            return Err(());
        }
        result.push((id.to_string(), revision));
    }
    if result.is_empty() || result.len() > MAX_DRAFT_SELECTION || form.len() != result.len() + 5 {
        return Err(());
    }
    Ok(result)
}

fn invalid_selection() -> HttpResponse {
    html_response(400, "Bad Request", "Choose Drafts", "<p>Select between 1 and 10 drafts, then choose Review discard. Nothing was discarded.</p><p><a href=\"/drafts\">Return to Drafts</a></p>")
}

fn selection_stopped(
    view: &DraftListView,
    discarded: usize,
    total: usize,
    message: &str,
) -> HttpResponse {
    html_response(409, "Conflict", "Draft Discard Stopped", TrustedHtml::from_template(format!("<p role=\"alert\">{}</p><p>{discarded} of {total} selected drafts discarded.</p><p><a href=\"{}\">Reload Drafts</a> before trying again.</p>", escape_html(message), escape_html(&view.href()))))
}
