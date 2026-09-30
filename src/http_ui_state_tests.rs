//! Hostile strings belong to test fixtures, outside the runtime template file.
use super::*;

#[test]
fn state_card_escapes_inert_content_and_keeps_only_native_link() {
    let html = mail_state_card(
        "<title>",
        "<script>literal</script>",
        "/search?mailbox=A%26B&q=x",
        "Retry",
        true,
    );
    assert!(html.contains("&lt;script&gt;literal&lt;/script&gt;"));
    assert!(html.contains("/search?mailbox=A%26B&amp;q=x"));
    assert!(!html.contains("<script"));
    assert!(!html.contains("<form"));
}
