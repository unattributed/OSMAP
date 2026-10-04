#[test]
fn sender_identity_draft_codec_captures_exact_pair_and_refuses_downgrade_or_partial_pair() {
    let dir = temp_dir("sender-v13");
    let store = FileDraftStore::new(&dir, DraftPolicy::default());
    let mut record = DraftRecord::new(
        DraftPolicy::default(),
        input(
            &draft_id(25),
            "alice@example.com",
            100,
            "Public",
            "Public body",
            vec![attachment(b"exact")],
        ),
    )
    .unwrap();
    record.request.sender_identity =
        crate::identity_preferences::IdentityPreferences::new("Desk", Some("reply@example.test"))
            .unwrap()
            .with_sender("desk", "desk@example.test")
            .unwrap();
    store.save(&record, 100).unwrap();
    let path = store.metadata_path("alice@example.com", &record.draft_id);
    let metadata = fs::read_to_string(&path).unwrap();
    assert!(metadata.starts_with("version=13\n"));
    let loaded = store
        .load("alice@example.com", &record.draft_id, 100)
        .unwrap()
        .unwrap();
    assert_eq!(
        loaded.request.sender_identity,
        record.request.sender_identity
    );
    assert_eq!(loaded.request.attachments, record.request.attachments);
    for invalid in [
        metadata.replace("version=13\n", "version=10\n"),
        metadata
            .lines()
            .filter(|v| !v.starts_with("sender_id_hex="))
            .collect::<Vec<_>>()
            .join("\n"),
        format!("{metadata}sender_id_hex=6465736b\n"),
        metadata.replace("sender_address_hex=", "unknown_address_hex="),
    ] {
        fs::write(&path, invalid).unwrap();
        assert!(store
            .load("alice@example.com", &record.draft_id, 100)
            .is_err());
    }
    fs::write(&path, &metadata).unwrap();
    assert_eq!(
        store
            .read_immutable("alice@example.com", &record.draft_id)
            .unwrap()
            .unwrap()
            .request
            .sender_identity,
        record.request.sender_identity
    );
    fs::remove_dir_all(dir).unwrap();
}
