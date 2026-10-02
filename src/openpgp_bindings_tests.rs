use super::*;
use serde_json::{json, Value};
use std::fs;
use std::sync::{Arc, Barrier};
fn key(fp: char, sign: bool, encrypt: bool) -> Value {
    json!({"fingerprint":fp.to_string().repeat(40),"algorithm":1,"bits":3072,"created":1,"expires":0,"revoked":false,"expired":false,"disabled":false,"invalid":false,"can_sign":sign,"can_encrypt":encrypt,"can_certify":false,"can_authenticate":false})
}
fn raw_inventory() -> Value {
    json!({"version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.4.8","keys":[{"primary":key('A',true,false),"subkeys":[key('B',true,false),key('C',false,true)]},{"primary":key('D',true,false),"subkeys":[key('E',true,false),key('F',false,true)]}]})
}
fn inventory(value: &Value) -> Inventory {
    Inventory::parse(&serde_json::to_vec(value).unwrap()).unwrap()
}
fn update() -> Update {
    Update {
        account_binding: Some(AccountBinding {
            primary_fingerprint: "A".repeat(40),
            signing_fingerprint: Some("B".repeat(40)),
            decrypt_primary_fingerprints: vec!["A".repeat(40)],
        }),
        recipient_bindings: vec![RecipientBinding {
            address: "receiver@example.test".into(),
            primary_fingerprint: "D".repeat(40),
            encryption: Requirement::Optional,
        }],
        policy: ProtectionPolicy::default(),
    }
}
fn record() -> BindingRecord {
    let update = update();
    BindingRecord {
        version: 1,
        canonical_username: "alice@example.test".into(),
        revision: 1,
        account_binding: update.account_binding,
        recipient_bindings: update.recipient_bindings,
        policy: update.policy,
    }
}
fn evaluate_to(record: &BindingRecord, inventory: &Inventory, selection: Selections) -> Preflight {
    let to = vec!["receiver@example.test".into()];
    evaluate(
        "alice@example.test",
        record,
        inventory,
        Recipients {
            to: &to,
            cc: &[],
            bcc: &[],
        },
        selection,
        100,
    )
    .unwrap()
}
fn scratch() -> PathBuf {
    std::env::temp_dir().join(format!(
        "osmap-pgp-bindings-{}",
        crate::draft::generate_draft_id().unwrap()
    ))
}

#[test]
fn safe_defaults_distinguish_capability_from_choices() {
    let empty = BindingRecord::empty("alice@example.test").unwrap();
    assert_eq!(
        Selections::default(),
        Selections {
            sign: false,
            encrypt: false,
            encrypt_to_self: false
        }
    );
    let result = evaluate_to(&empty, &inventory(&raw_inventory()), Selections::default());
    assert_eq!(result.state, PreflightState::Orange);
    assert_eq!(result.signing, KeyStatus::MissingBinding);
    assert!(result.plan.unwrap().recipient_fingerprints.is_empty());
    let bound = evaluate_to(
        &record(),
        &inventory(&raw_inventory()),
        Selections::default(),
    );
    assert_eq!(bound.signing, KeyStatus::Ready);
    assert_eq!(bound.recipients[0].state, KeyStatus::Ready);
    assert!(bound.plan.unwrap().signer_fingerprint.is_none());
}
#[test]
fn exact_signing_subkey_and_self_encryption_operation_plan() {
    let result = evaluate_to(
        &record(),
        &inventory(&raw_inventory()),
        Selections {
            sign: true,
            encrypt: true,
            encrypt_to_self: true,
        },
    );
    assert_eq!(result.state, PreflightState::Green);
    let plan = result.plan.unwrap();
    assert_eq!(plan.signer_fingerprint, Some("B".repeat(40)));
    assert_eq!(
        plan.recipient_fingerprints,
        vec!["A".repeat(40), "D".repeat(40)]
    );
    assert!(plan.encrypt_to_self);
    let mut changed = raw_inventory();
    changed["keys"][0]["subkeys"][0]["revoked"] = json!(true);
    let result = evaluate_to(
        &record(),
        &inventory(&changed),
        Selections {
            sign: true,
            ..Selections::default()
        },
    );
    assert_eq!(result.signing, KeyStatus::Revoked);
    assert_eq!(result.state, PreflightState::Blocked);
    assert!(result.plan.is_none());
    // Primary SC capability never replaces the revoked explicitly bound S subkey.
}
#[test]
fn required_optional_disabled_matrix_never_downgrades_selection() {
    let inventory = inventory(&raw_inventory());
    for signing in [
        Requirement::Required,
        Requirement::Optional,
        Requirement::Disabled,
    ] {
        for encryption in [
            Requirement::Required,
            Requirement::Optional,
            Requirement::Disabled,
        ] {
            for sign in [false, true] {
                for encrypt in [false, true] {
                    let mut record = record();
                    record.policy = ProtectionPolicy {
                        signing,
                        encryption,
                    };
                    let result = evaluate_to(
                        &record,
                        &inventory,
                        Selections {
                            sign,
                            encrypt,
                            encrypt_to_self: false,
                        },
                    );
                    let blocked = signing == Requirement::Required && !sign
                        || signing == Requirement::Disabled && sign
                        || encryption == Requirement::Required && !encrypt
                        || encryption == Requirement::Disabled && encrypt;
                    assert_eq!(result.state == PreflightState::Blocked, blocked);
                    assert_eq!(result.plan.is_none(), blocked);
                }
            }
        }
    }
    let mut missing = record();
    missing.recipient_bindings.clear();
    let result = evaluate_to(
        &missing,
        &inventory,
        Selections {
            encrypt: true,
            ..Selections::default()
        },
    );
    assert_eq!(result.state, PreflightState::Blocked);
    assert!(result.plan.is_none());
}
#[test]
fn recipient_policy_bcc_and_encrypt_self_must_be_resolved_explicitly() {
    let inventory = inventory(&raw_inventory());
    let mut record = record();
    record.recipient_bindings[0].encryption = Requirement::Required;
    assert_eq!(
        evaluate_to(&record, &inventory, Selections::default()).state,
        PreflightState::Blocked
    );
    record.recipient_bindings[0].encryption = Requirement::Disabled;
    assert_eq!(
        evaluate_to(
            &record,
            &inventory,
            Selections {
                encrypt: true,
                ..Selections::default()
            }
        )
        .state,
        PreflightState::Blocked
    );
    record.recipient_bindings[0].encryption = Requirement::Optional;
    let hidden = vec!["receiver@example.test".into()];
    let result = evaluate(
        "alice@example.test",
        &record,
        &inventory,
        Recipients {
            to: &[],
            cc: &[],
            bcc: &hidden,
        },
        Selections {
            encrypt: true,
            ..Selections::default()
        },
        100,
    )
    .unwrap();
    assert!(result
        .reasons
        .contains(&BlockReason::EncryptedBccUnqualified));
    assert!(result.plan.is_none());
    let result = evaluate_to(
        &record,
        &inventory,
        Selections {
            encrypt_to_self: true,
            ..Selections::default()
        },
    );
    assert!(result
        .reasons
        .contains(&BlockReason::SelfRequiresEncryption));
    assert!(result.plan.is_none());
}
#[test]
fn inventory_expiry_revocation_weak_keys_and_ambiguity_block_selected_protection() {
    for field in ["revoked", "expired", "invalid", "disabled"] {
        let mut raw = raw_inventory();
        raw["keys"][1]["primary"][field] = json!(true);
        let result = evaluate_to(
            &record(),
            &inventory(&raw),
            Selections {
                encrypt: true,
                ..Selections::default()
            },
        );
        assert_eq!(result.state, PreflightState::Blocked);
        assert!(result.plan.is_none());
    }
    for value in [json!(100), json!(99)] {
        let mut raw = raw_inventory();
        raw["keys"][1]["subkeys"][1]["expires"] = value;
        assert_eq!(
            evaluate_to(
                &record(),
                &inventory(&raw),
                Selections {
                    encrypt: true,
                    ..Selections::default()
                }
            )
            .state,
            PreflightState::Blocked
        );
    }
    let mut raw = raw_inventory();
    raw["keys"][1]["subkeys"]
        .as_array_mut()
        .unwrap()
        .push(key('1', false, true));
    let result = evaluate_to(
        &record(),
        &inventory(&raw),
        Selections {
            encrypt: true,
            ..Selections::default()
        },
    );
    assert_eq!(result.recipients[0].state, KeyStatus::Ambiguous);
    let mut raw = raw_inventory();
    raw["keys"][1]["subkeys"][1]["bits"] = json!(2048);
    assert_eq!(
        evaluate_to(
            &record(),
            &inventory(&raw),
            Selections {
                encrypt: true,
                ..Selections::default()
            }
        )
        .recipients[0]
            .state,
        KeyStatus::Unsupported
    );
    let unavailable =
        Inventory::parse(br#"{"version":1,"ok":false,"error":"inventory_unavailable"}"#).unwrap();
    assert_eq!(
        evaluate_to(
            &record(),
            &unavailable,
            Selections {
                encrypt: true,
                ..Selections::default()
            }
        )
        .state,
        PreflightState::Blocked
    );
    assert_eq!(
        evaluate_to(&record(), &unavailable, Selections::default()).state,
        PreflightState::Orange
    );
}
#[test]
fn only_exact_qualified_curve_metadata_enables_existing_curve_keys() {
    let mut raw = raw_inventory();
    raw["keys"][1]["primary"]["algorithm"] = json!(303);
    raw["keys"][1]["primary"]["bits"] = json!(255);
    raw["keys"][1]["primary"]["curve"] = json!("ed25519");
    raw["keys"][1]["subkeys"][1]["algorithm"] = json!(302);
    raw["keys"][1]["subkeys"][1]["bits"] = json!(255);
    raw["keys"][1]["subkeys"][1]["curve"] = json!("cv25519");
    assert_eq!(
        evaluate_to(
            &record(),
            &inventory(&raw),
            Selections {
                encrypt: true,
                ..Selections::default()
            }
        )
        .recipients[0]
            .state,
        KeyStatus::Ready
    );
    let mut packet_number = raw.clone();
    packet_number["keys"][1]["subkeys"][1]["algorithm"] = json!(18);
    assert_eq!(
        evaluate_to(
            &record(),
            &inventory(&packet_number),
            Selections {
                encrypt: true,
                ..Selections::default()
            }
        )
        .recipients[0]
            .state,
        KeyStatus::Unsupported
    );
    for curve in [json!(null), json!("nistp256"), json!("unknown")] {
        raw["keys"][1]["subkeys"][1]["curve"] = curve;
        assert_eq!(
            evaluate_to(
                &record(),
                &inventory(&raw),
                Selections {
                    encrypt: true,
                    ..Selections::default()
                }
            )
            .recipients[0]
                .state,
            KeyStatus::Unsupported
        );
    }
}
#[test]
fn future_fingerprint_versions_remain_inventory_only() {
    let mut raw = raw_inventory();
    raw["keys"][1]["primary"]["fingerprint"] = json!("D".repeat(64));
    let inventory = inventory(&raw);
    let mut record = record();
    record.recipient_bindings[0].primary_fingerprint = "D".repeat(64);
    let result = evaluate_to(
        &record,
        &inventory,
        Selections {
            encrypt: true,
            ..Selections::default()
        },
    );
    assert_eq!(result.recipients[0].state, KeyStatus::Unsupported);
    assert_eq!(result.state, PreflightState::Blocked);
    assert!(result.plan.is_none());
}
#[test]
fn reported_usage_flags_cannot_override_algorithm_purpose() {
    let mut raw = raw_inventory();
    raw["keys"][0]["subkeys"][0]["algorithm"] = json!(302);
    raw["keys"][0]["subkeys"][0]["curve"] = json!("cv25519");
    assert_eq!(
        evaluate_to(
            &record(),
            &inventory(&raw),
            Selections {
                sign: true,
                ..Selections::default()
            }
        )
        .signing,
        KeyStatus::Unsupported
    );
    let mut raw = raw_inventory();
    raw["keys"][1]["subkeys"][1]["algorithm"] = json!(303);
    raw["keys"][1]["subkeys"][1]["curve"] = json!("ed25519");
    assert_eq!(
        evaluate_to(
            &record(),
            &inventory(&raw),
            Selections {
                encrypt: true,
                ..Selections::default()
            }
        )
        .recipients[0]
            .state,
        KeyStatus::Unsupported
    );
}
#[test]
fn store_is_account_private_atomic_and_revision_checked() {
    let root = scratch();
    let store = BindingStore::new(&root);
    let inventory = inventory(&raw_inventory());
    assert_eq!(store.load("alice@example.test").unwrap().revision, 0);
    let saved = store
        .replace_operator("alice@example.test", 0, update(), &inventory, 100)
        .unwrap();
    assert_eq!(saved.revision, 1);
    assert_eq!(
        BindingStore::new(&root).load("alice@example.test").unwrap(),
        saved
    );
    assert_eq!(store.load("bob@example.test").unwrap().revision, 0);
    assert_eq!(
        store
            .replace_operator("alice@example.test", 0, update(), &inventory, 100)
            .unwrap_err(),
        BindingError::Stale
    );
    let mut wrong = update();
    wrong.account_binding.as_mut().unwrap().signing_fingerprint = Some("E".repeat(40));
    assert_eq!(
        store
            .replace_operator("alice@example.test", 1, wrong, &inventory, 100)
            .unwrap_err(),
        BindingError::InvalidKey
    );
    assert_eq!(store.load("alice@example.test").unwrap(), saved);
    assert!(!format!("{saved:?}").contains("example.test"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for p in fs::read_dir(&root).unwrap() {
            assert_eq!(p.unwrap().metadata().unwrap().mode() & 0o777, 0o600);
        }
    }
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn malformed_duplicate_foreign_and_overquota_records_refuse_without_replacement() {
    let root = scratch();
    let store = BindingStore::new(&root);
    let inventory = inventory(&raw_inventory());
    store
        .replace_operator("alice@example.test", 0, update(), &inventory, 100)
        .unwrap();
    let file = fs::read_dir(&root)
        .unwrap()
        .map(|p| p.unwrap().path())
        .find(|p| p.extension().is_some_and(|s| s == "json"))
        .unwrap();
    let original = fs::read(&file).unwrap();
    let mut raw: Value = serde_json::from_slice(&original).unwrap();
    raw["canonical_username"] = json!("bob@example.test");
    fs::write(&file, serde_json::to_vec(&raw).unwrap()).unwrap();
    assert_eq!(
        store.load("alice@example.test").unwrap_err(),
        BindingError::ForeignAccount
    );
    let mut raw: Value = serde_json::from_slice(&original).unwrap();
    raw["private_key_home"] = json!("/tmp/forbidden");
    fs::write(&file, serde_json::to_vec(&raw).unwrap()).unwrap();
    assert_eq!(
        store.load("alice@example.test").unwrap_err(),
        BindingError::Unavailable
    );
    let duplicate = String::from_utf8(original.clone())
        .unwrap()
        .replace("\"version\":1", "\"version\":1,\"version\":1");
    fs::write(&file, duplicate).unwrap();
    assert_eq!(
        store.load("alice@example.test").unwrap_err(),
        BindingError::Unavailable
    );
    fs::write(&file, &original).unwrap();
    let mut doubled = update();
    doubled.recipient_bindings.push(RecipientBinding {
        address: "receiver@EXAMPLE.test".into(),
        primary_fingerprint: "D".repeat(40),
        encryption: Requirement::Optional,
    });
    assert_eq!(
        store
            .replace_operator("alice@example.test", 1, doubled, &inventory, 100)
            .unwrap_err(),
        BindingError::Duplicate
    );
    let mut quota = update();
    quota.recipient_bindings = (0..201)
        .map(|i| RecipientBinding {
            address: format!("r{i}@example.test"),
            primary_fingerprint: "D".repeat(40),
            encryption: Requirement::Optional,
        })
        .collect();
    assert_eq!(
        store
            .replace_operator("alice@example.test", 1, quota, &inventory, 100)
            .unwrap_err(),
        BindingError::Quota
    );
    assert_eq!(fs::read(&file).unwrap(), original);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn concurrent_binding_changes_publish_only_one_revision() {
    let root = scratch();
    let store = BindingStore::new(&root);
    let inv = inventory(&raw_inventory());
    store
        .replace_operator("alice@example.test", 0, update(), &inv, 100)
        .unwrap();
    let held = store.file.lock("alice@example.test").unwrap();
    assert_eq!(
        store
            .replace_operator("alice@example.test", 1, update(), &inv, 100)
            .unwrap_err(),
        BindingError::Busy
    );
    drop(held);
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let store = store.clone();
        let inv = inv.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            store.replace_operator("alice@example.test", 1, update(), &inv, 100)
        }));
    }
    barrier.wait();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(results
        .iter()
        .filter_map(|r| r.as_ref().err())
        .all(|e| matches!(e, BindingError::Stale | BindingError::Busy)));
    assert_eq!(store.load("alice@example.test").unwrap().revision, 2);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn public_admin_closure_holds_same_revision_lock_as_binding_changes() {
    let root = scratch();
    let store = BindingStore::new(&root);
    let inv = inventory(&raw_inventory());
    store
        .replace_operator("alice@example.test", 0, update(), &inv, 100)
        .unwrap();
    let seen = store
        .with_locked_revision("alice@example.test", 1, |record| {
            assert_eq!(record.revision, 1);
            assert_eq!(
                store
                    .replace_operator("alice@example.test", 1, update(), &inv, 100)
                    .unwrap_err(),
                BindingError::Busy
            );
            Ok(record.revision)
        })
        .unwrap();
    assert_eq!(seen, 1);
    assert_eq!(
        store
            .with_locked_revision("alice@example.test", 0, |_| Ok(()))
            .unwrap_err(),
        BindingError::Stale
    );
    assert_eq!(
        store
            .replace_operator("alice@example.test", 1, update(), &inv, 100)
            .unwrap()
            .revision,
        2
    );
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn binding_inventory_is_read_under_same_lock_as_public_admin_mutation() {
    let root = scratch();
    let store = BindingStore::new(&root);
    let inv = inventory(&raw_inventory());
    let captured = store.clone();
    let saved = store
        .replace_operator_with_inventory(
            "alice@example.test",
            0,
            update(),
            || {
                assert_eq!(
                    captured
                        .with_locked_revision("alice@example.test", 0, |_| Ok(()))
                        .unwrap_err(),
                    BindingError::Busy
                );
                Ok(inv.clone())
            },
            100,
        )
        .unwrap();
    assert_eq!(saved.revision, 1);
    assert_eq!(store.load("alice@example.test").unwrap().revision, 1);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn foreign_account_bad_address_and_receiver_count_do_not_create_plan() {
    let inv = inventory(&raw_inventory());
    let recipients = vec!["receiver@example.test".into()];
    assert!(matches!(
        evaluate(
            "bob@example.test",
            &record(),
            &inv,
            Recipients {
                to: &recipients,
                cc: &[],
                bcc: &[]
            },
            Selections::default(),
            100
        ),
        Err(BindingError::ForeignAccount)
    ));
    let bad = vec!["receiver@example.test\r\nBcc: outsider@example.test".into()];
    assert!(evaluate(
        "alice@example.test",
        &record(),
        &inv,
        Recipients {
            to: &bad,
            cc: &[],
            bcc: &[]
        },
        Selections::default(),
        100
    )
    .is_err());
    let too_many = vec!["receiver@example.test".into(); 51];
    assert!(matches!(
        evaluate(
            "alice@example.test",
            &record(),
            &inv,
            Recipients {
                to: &too_many,
                cc: &[],
                bcc: &[]
            },
            Selections::default(),
            100
        ),
        Err(BindingError::Quota)
    ));
}
