use super::*;

#[test]
fn protected_authoring_roundtrips_without_resetting_choices() {
    let root = temp_dir("osmap-protected-draft");
    let store = FileDraftStore::new(&root, DraftPolicy::default());
    let mut draft = record(&draft_id(1), "alice@example.com", 100);
    draft.request.protection = crate::send::ProtectionIntent {
        sign: true,
        encrypt: true,
        encrypt_to_self: true,
        binding_revision: Some(7),
    };
    store.save(&draft, 100).unwrap();
    let loaded = store
        .load("alice@example.com", &draft.draft_id, 101)
        .unwrap()
        .unwrap();
    assert_eq!(loaded.request.protection, draft.request.protection);
    let encoded = serialize_draft_metadata(&loaded);
    assert!(encoded.starts_with("version=11\n"));
    let mut identified = loaded.clone();
    identified.request.sender_identity =
        crate::identity_preferences::IdentityPreferences::new("Alice", None).unwrap();
    let encoded = serialize_draft_metadata(&identified);
    assert!(encoded.starts_with("version=12\n"));
    let decoded = parse_draft_metadata(
        DraftPolicy::default(),
        "alice@example.com",
        &root.join(&draft.draft_id).join("draft.metadata"),
        &encoded,
    )
    .unwrap()
    .unwrap();
    assert_eq!(decoded.request.protection, draft.request.protection);
    assert_eq!(
        decoded.request.sender_identity,
        identified.request.sender_identity
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn protected_schema_requires_strict_complete_compatible_intent() {
    let root = temp_dir("osmap-protected-schema");
    let mut draft = record(&draft_id(1), "alice@example.com", 100);
    draft.revision = Some(1);
    draft.request.protection = crate::send::ProtectionIntent {
        sign: true,
        encrypt: false,
        encrypt_to_self: false,
        binding_revision: Some(7),
    };
    let encoded = serialize_draft_metadata(&draft);
    for malformed in [
        encoded.replace("pgp_sign=1\n", "pgp_sign=true\n"),
        encoded.replace("pgp_encrypt=0\n", ""),
        encoded.replace("pgp_binding_revision=7\n", "pgp_binding_revision=07\n"),
        encoded.replace("version=11\n", "version=9\n"),
        encoded.replace("pgp_self=0\n", "pgp_self=0\npgp_self=1\n"),
        encoded
            .lines()
            .filter(|line| !line.starts_with("pgp_"))
            .collect::<Vec<_>>()
            .join("\n"),
    ] {
        assert!(parse_draft_metadata(
            DraftPolicy::default(),
            "alice@example.com",
            &root.join(&draft.draft_id).join("draft.metadata"),
            &malformed
        )
        .is_err());
    }
    draft.request.protection = crate::send::ProtectionIntent::default();
    let legacy = serialize_draft_metadata(&draft);
    assert!(legacy.starts_with("version=9\n"));
    assert_eq!(
        parse_draft_metadata(
            DraftPolicy::default(),
            "alice@example.com",
            &root.join(&draft.draft_id).join("draft.metadata"),
            &legacy
        )
        .unwrap()
        .unwrap()
        .request
        .protection,
        crate::send::ProtectionIntent::default()
    );
}
