//! Account-private filename projection; bytes stay behind the existing download route.
use super::*;

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn document_search_matches(
        &self,
        session: &ValidatedSession,
        query: &str,
    ) -> Result<Vec<crate::documents::Document>, crate::documents::Error> {
        let index = self.gateway.load_documents(session)?;
        index.storage_summary(&session.record.canonical_username)?;
        let query = query.to_lowercase();
        let mut matches: Vec<_> = index
            .documents
            .into_iter()
            .filter(|document| {
                document.state == crate::documents::State::Available
                    && document.name.to_lowercase().contains(&query)
            })
            .collect();
        matches.sort_by_cached_key(|document| (document.name.to_lowercase(), document.id.clone()));
        Ok(matches)
    }

    pub(super) fn handle_documents_search(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let Some(filters) =
            crate::mail_navigation::SearchFilterContext::parse(&request.query_params)
        else {
            return HandledHttpResponse {
                response: html_response(400, "Bad Request", "Invalid Search Request", render_navigation_notice(
                    &session.record.canonical_username, &session.record.csrf_token, "Invalid Search Request",
                    "Use bounded keywords, supported message filters and an available Documents results page.")),
                audit_events,
            };
        };
        let query = request
            .query_params
            .get("q")
            .map(String::as_str)
            .unwrap_or("")
            .trim();
        // Empty landing pages do not open the Documents store or any mail helper.
        let matches = (!query.is_empty()).then(|| self.document_search_matches(&session, query));
        let available = matches.as_ref().and_then(|result| result.as_ref().ok());
        let failed = matches.as_ref().is_some_and(Result::is_err);
        let count = available.map_or(0, Vec::len);
        let pages = count
            .div_ceil(crate::mail_navigation::ALL_SEARCH_PAGE_SIZE)
            .max(1);
        let page = if available.is_some() {
            filters.view.requested_page.min(pages)
        } else {
            filters.view.requested_page
        };
        let href = |page| filters.href(crate::mail_navigation::SearchTab::Documents, query, page);
        let rows = match &matches {
            None => "<li class=\"message-empty-state\">Enter keywords to search document file names.</li>".into(),
            Some(Err(_)) => "<li class=\"message-empty-state\" role=\"status\">Documents search unavailable. Current files could not be verified; this does not mean there are no matches.</li>".into(),
            Some(Ok(documents)) if documents.is_empty() => "<li class=\"message-empty-state\">No document file names match.</li>".into(),
            Some(Ok(documents)) => documents.iter().skip((page-1)*crate::mail_navigation::ALL_SEARCH_PAGE_SIZE).take(crate::mail_navigation::ALL_SEARCH_PAGE_SIZE).map(document_row).collect::<String>(),
        };
        let label = if query.is_empty() {
            "Documents not searched".into()
        } else if failed {
            "Documents unavailable".into()
        } else {
            format!("Documents ({count})")
        };
        let mut pagination = String::new();
        if available.is_some() {
            pagination = format!("<span>{count} matching documents · Page {page} of {pages}</span><nav aria-label=\"Documents result pages\">");
            if page > 1 {
                pagination.push_str(&format!(
                    "<a href=\"{}\">Previous page</a> ",
                    escape_html(&href(Some(page - 1)))
                ));
            }
            if page < pages {
                pagination.push_str(&format!(
                    "<a href=\"{}\">Next page</a>",
                    escape_html(&href(Some(page + 1)))
                ));
            }
            pagination.push_str("</nav>");
        }
        let body = TrustedHtml::from_template(format!(concat!(
            "{}<main id=\"main-content\" class=\"page-shell coordinated-mail search-results documents-search\" tabindex=\"-1\"><div class=\"page-intro mail-page-intro\"><h1>Search</h1><p>Find your document file names.</p></div><section class=\"content-pane coordinated-list\">",
            "<form method=\"get\" action=\"/search\"><input type=\"hidden\" name=\"category\" value=\"documents\">{}<label for=\"documents-query\">Search file names</label><input id=\"documents-query\" name=\"q\" maxlength=\"256\" value=\"{}\"><button type=\"submit\">Search</button></form>",
            "<nav class=\"search-result-tabs\" aria-label=\"Search types\"><a href=\"{}\">All</a><a href=\"{}\">Messages</a><span aria-current=\"page\">{label}</span><a href=\"{}\">People</a></nav>",
            "<ul class=\"search-result-list\" aria-label=\"Documents results\">{rows}</ul><div class=\"search-result-footer\">{pagination}</div><p class=\"search-capability-note muted\">Search covers at most 100 active document file names. Bin and pending files are excluded. Retained mail filters apply only to Messages; they do not filter Documents. File contents are not searched or previewed.</p><a href=\"{}\">Clear search</a> · <a href=\"/documents\">Manage Documents</a></section></main>"),
            crate::http_ui::app_header(&session.record.canonical_username,&session.record.csrf_token,"search"),
            crate::http_ui::category_filter_hidden(&filters), escape_html(query),
            escape_html(&filters.href(crate::mail_navigation::SearchTab::All,query,None)),
            escape_html(&filters.href(crate::mail_navigation::SearchTab::Messages,query,None)),
            escape_html(&filters.href(crate::mail_navigation::SearchTab::People,query,None)), escape_html(&href(None)), label=label, rows=rows, pagination=pagination));
        HandledHttpResponse {
            response: html_response(
                if failed { 503 } else { 200 },
                if failed { "Service Unavailable" } else { "OK" },
                "Search Documents",
                body,
            ),
            audit_events,
        }
    }
}

pub(super) fn document_row(document: &crate::documents::Document) -> String {
    format!("<li class=\"search-result-row\"><span>Document</span><div class=\"search-result-title\"><a class=\"message-subject-link\" href=\"/documents?selected={}\" dir=\"auto\">{}</a><span class=\"message-sender\" dir=\"auto\">{} · {} bytes</span></div><span class=\"search-result-location\">Documents</span><span class=\"search-result-date\">{}</span><span></span></li>", escape_html(&document.id),escape_html(&document.name),escape_html(&document.media_type),document.size,escape_html(&crate::logging::format_unix_timestamp_utc(document.modified_at)))
}
