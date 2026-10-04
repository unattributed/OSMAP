#[cfg(unix)]
#[test]
fn sender_identity_final_transport_rechecks_authority_and_binds_envelope_mime() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root = std::path::Path::new("/tmp").join(format!(
        "osmap-sender-transport-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    let file = root.join("authority.json");
    std::fs::write(&file, br#"{"version":1,"accounts":[{"account":"alice@example.test","revision":1,"identities":[{"id":"desk","address":"desk@example.test"}]}]}"#).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let provider = crate::sender_authority::Provider::new(
        Some(file.clone()),
        std::fs::metadata(&file).unwrap().uid(),
    );
    let executor = Rc::new(RefCell::new(StubCommandExecutor::success(
        CommandExecution {
            status_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    )));
    let backend =
        SendmailSubmissionBackend::new(executor.clone(), "/not-executed-fixture-sendmail")
            .with_sender_authority(provider);
    let mut request = ComposeRequest::new(
        ComposePolicy::default(),
        "recipient@example.test",
        "Public fixture",
        "Public body",
    )
    .unwrap();
    request.sender_identity =
        crate::identity_preferences::IdentityPreferences::new("Desk", Some("reply@example.test"))
            .unwrap()
            .with_sender("desk", "desk@example.test")
            .unwrap();
    backend
        .submit_message("alice@example.test", &request)
        .unwrap();
    assert_eq!(
        executor.borrow().args.as_ref().unwrap(),
        &vec![
            "-oi",
            "-f",
            "desk@example.test",
            "--",
            "recipient@example.test"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>()
    );
    assert!(
        std::str::from_utf8(executor.borrow().stdin_data.as_ref().unwrap())
            .unwrap()
            .starts_with("From: =?UTF-8?B?RGVzaw==?=\r\n <desk@example.test>\r\nReply-To: reply@example.test\r\n")
    );
    executor.borrow_mut().program = None;
    std::fs::write(&file, br#"{"version":1,"accounts":[{"account":"alice@example.test","revision":2,"identities":[]}]}"#).unwrap();
    assert!(backend
        .submit_message("alice@example.test", &request)
        .is_err());
    assert!(executor.borrow().program.is_none());
    assert!(backend
        .submit_message("bob@example.test", &request)
        .is_err());
    assert!(executor.borrow().program.is_none());
    request.sender_identity = crate::identity_preferences::IdentityPreferences::default();
    std::fs::write(&file, b"corrupt").unwrap();
    backend
        .submit_message("alice@example.test", &request)
        .unwrap();
    assert_eq!(
        executor.borrow().args.as_ref().unwrap()[2],
        "alice@example.test"
    );
}
