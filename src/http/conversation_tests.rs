use super::*;
use crate::conversation::ThreadingMetadata;
use crate::mail_list::ListViewState;
use crate::reading_preferences::{DateOrder, ReadingPreferences, ReadingPreferencesStore};

pub(super) fn conversation_rows() -> Vec<MessageSummary> {
    [
        (1, "<root@fixture.test>", None),
        (2, "<unrelated@fixture.test>", None),
        (3, "<reply@fixture.test>", Some("<root@fixture.test>")),
    ]
    .into_iter()
    .map(|(uid, id, parent)| {
        let mut metadata = StubGateway::fixture_metadata("alice@example.com", "INBOX", uid);
        metadata.threading = ThreadingMetadata::from_headers(Some(id), parent, parent);
        MessageSummary {
            mailbox_name: "INBOX".into(),
            uid,
            flags: vec![],
            date_received: format!("2026-10-03 0{uid}:00:00 +0000"),
            size_virtual: 100,
            // Same subject deliberately cannot establish a relationship.
            subject: Some("Shared public subject".into()),
            from: Some("sender@example.test".into()),
            to: None,
            metadata: Some(metadata),
        }
    })
    .collect()
}

fn ids(rows: &[MessageSummary]) -> Vec<u64> {
    rows.iter().map(|row| row.uid).collect()
}

#[test]
fn conversation_saved_newest_default_keeps_reply_parent_contiguous_and_same_subject_separate() {
    let mut ordinary = conversation_rows();
    ListViewState::from_query(&BTreeMap::new())
        .unwrap()
        .apply_messages(&mut ordinary);
    assert_eq!(
        ids(&ordinary),
        [3, 2, 1],
        "individual newest sorting is the discriminating baseline"
    );
    let mut view = ListViewState::from_query(&BTreeMap::new()).unwrap();
    view.apply_saved_reading_defaults(ReadingPreferences::default());
    let mut rows = conversation_rows();
    view.apply_messages(&mut rows);
    assert_eq!(ids(&rows), [3, 1, 2], "real reply ancestry, not subject/date sorting, must keep the loaded conversation contiguous");
}

#[test]
fn conversation_saved_oldest_reverses_members_and_explicit_sort_retains_precedence() {
    let oldest = ReadingPreferences {
        date_order: DateOrder::Oldest,
        ..ReadingPreferences::default()
    };
    let mut view = ListViewState::from_query(&BTreeMap::new()).unwrap();
    view.apply_saved_reading_defaults(oldest);
    let mut rows = conversation_rows();
    view.apply_messages(&mut rows);
    assert_eq!(ids(&rows), [1, 3, 2]);
    for (sort, direction, expected) in [
        ("received", "asc", vec![1, 2, 3]),
        ("received", "desc", vec![3, 2, 1]),
    ] {
        let mut view = ListViewState::from_query(&BTreeMap::from([
            ("sort".into(), sort.into()),
            ("dir".into(), direction.into()),
        ]))
        .unwrap();
        view.apply_saved_reading_defaults(oldest);
        let mut rows = conversation_rows();
        view.apply_messages(&mut rows);
        assert_eq!(
            ids(&rows),
            expected,
            "explicit URL sort must not inherit conversation grouping"
        );
    }
}

#[test]
fn conversation_default_orders_only_filtered_owned_loaded_members_and_preserves_guid_selection() {
    let mut rows = conversation_rows();
    rows[1].flags.push("\\Seen".into());
    let expected = rows[2].metadata.as_ref().unwrap().version.clone();
    let mut view = ListViewState::from_query(&BTreeMap::from([
        ("filter".into(), "unread".into()),
        ("selected_mailbox".into(), "INBOX".into()),
        ("selected_uid".into(), "3".into()),
        (
            "selected_mailbox_guid".into(),
            expected.mailbox_guid.clone(),
        ),
        (
            "selected_message_guid".into(),
            expected.message_guid.clone(),
        ),
    ]))
    .unwrap();
    view.apply_saved_reading_defaults(ReadingPreferences::default());
    view.apply_messages(&mut rows);
    assert_eq!(ids(&rows), [3, 1]);
    assert_eq!(view.selected_version, Some(expected));
    assert_eq!(view.total_results, 2);
    // Removing the parent by a real sender predicate cannot pull it into the list.
    let mut rows = conversation_rows();
    rows[0].from = Some("excluded@example.test".into());
    let mut view = ListViewState::from_query(&BTreeMap::from([(
        "from".into(),
        "sender@example.test".into(),
    )]))
    .unwrap();
    view.apply_saved_reading_defaults(ReadingPreferences::default());
    view.apply_messages(&mut rows);
    assert_eq!(ids(&rows), [3, 2]);
}

struct ConversationFixture {
    root: PathBuf,
    store: ReadingPreferencesStore,
    app: BrowserApp<StubGateway>,
}
impl ConversationFixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = temp_dir(&format!(
            "conversation-integrated-{}",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let store = ReadingPreferencesStore::new(root.join("settings"));
        let app = BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                reading_preferences_store: Some(store.clone()),
                message_list_override: Some(conversation_rows()),
                ..StubGateway::default()
            },
        );
        Self { root, store, app }
    }
    fn get(&self, path: &str) -> HandledHttpResponse {
        self.app.handle_request(
            &request("GET", path, &authenticated_headers(), ""),
            "127.0.0.1",
        )
    }
    fn save(&self, order: &str) -> HandledHttpResponse {
        let form: BTreeMap<String, String> = BTreeMap::from([
            (
                "csrf_token".into(),
                StubGateway::validated_session().record.csrf_token,
            ),
            ("start_page".into(), "inbox".into()),
            ("date_order".into(), order.into()),
            ("show_source_shortcut".into(), "1".into()),
            ("attachment_details".into(), "1".into()),
        ]);
        let body = form
            .iter()
            .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        let mut req = request(
            "POST",
            "/settings/reading",
            &authenticated_same_origin_headers(),
            &body,
        );
        req.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        self.app.handle_request(&req, "127.0.0.1")
    }
}
impl Drop for ConversationFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn rendered_row_order(response: &HandledHttpResponse) -> Vec<u64> {
    // Rendered row More controls, not reader bodies or toolbar duplicates.
    body_text(response)
        .split("aria-label=\"More for message #")
        .skip(1)
        .map(|part| {
            part.split_once(" in INBOX\"")
                .unwrap()
                .0
                .parse::<u64>()
                .unwrap()
        })
        .collect()
}

#[test]
fn conversation_actual_reading_save_reload_changes_flat_list_without_cookie_or_new_panel() {
    let fixture = ConversationFixture::new();
    assert_eq!(fixture.save("newest").response.status_code, 303);
    assert_eq!(
        fixture.store.load("alice@example.com").unwrap().date_order,
        DateOrder::Newest
    );
    let newest = fixture.get("/mailbox?name=INBOX");
    assert_eq!(newest.response.status_code, 200);
    assert_eq!(rendered_row_order(&newest), [3, 1, 2]);
    assert_eq!(fixture.save("oldest").response.status_code, 303);
    assert_eq!(
        fixture.store.load("alice@example.com").unwrap().date_order,
        DateOrder::Oldest
    );
    let oldest = fixture.get("/mailbox?name=INBOX");
    assert_eq!(oldest.response.status_code, 200);
    assert_eq!(rendered_row_order(&oldest), [1, 3, 2]);
    assert_eq!(
        fixture.store.load("bob@example.com").unwrap().date_order,
        DateOrder::Newest
    );
    let settings = fixture.get("/settings?section=reading");
    assert_eq!(settings.response.status_code, 200);
    assert!(body_text(&settings).contains("<option value=\"oldest\" selected>"));
    let explicit = fixture.get("/mailbox?name=INBOX&sort=received&dir=desc");
    assert_eq!(rendered_row_order(&explicit), [3, 2, 1]);
    assert_eq!(
        fixture.app.request_budgets.mailbox_workers.active_count(),
        0
    );
}
