// Removed Documents search cannot become an ordinary All/People dependency.
use super::*;
#[test]
fn ordinary_search_has_no_documents_tab_or_store_reads() {
    let app = BrowserApp::new(HttpPolicy::default(), StubGateway::default());
    for path in [
        "/search",
        "/search?q=public",
        "/search?category=all",
        "/search?category=all&q=public",
        "/search?category=people&q=public",
    ] {
        let response = app.handle_request(
            &request("GET", path, &authenticated_same_origin_headers(), ""),
            "127.0.0.1",
        );
        assert_eq!(response.response.status_code, 200, "{path}");
        let html = body_text(&response);
        assert!(
            !html.contains("Documents")
                && !html.contains("category=documents")
                && !html.contains("/documents"),
            "{path}"
        );
    }
    assert_eq!(app.gateway.document_reads.load(Ordering::SeqCst), 0);
}
