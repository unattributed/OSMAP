// Included in the existing native Gateway actor. This qualifies real native
// SDK/MAC admission plus controlled fixture epochs, not the installed account DB.
use crate::http::http_gateway::http_gateway_scheduled_send::{
    ScheduledDispatch, ScheduledSendOutcome,
};
use crate::openpgp_personal::{PersonalAction, PrivateSession};
use crate::scheduled_send::{BlockReason, ClaimedJob, ScheduleInput, ScheduledStore, State};
use crate::session::{FileSessionStore, SessionStore};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

const ACCOUNT: &str = "alice@example.test";
pub(super) struct Inputs<'a> {
    pub gateway: &'a mut RuntimeBrowserGateway,
    pub scratch: &'a Scratch,
    pub crypto: &'a crate::openpgp_crypto_runtime::Client,
    pub submission:
        &'a SubmissionService<crate::send::SendmailSubmissionBackend<SystemCommandExecutor>>,
    pub append: &'a crate::mailbox::DoveadmMessageAppendBackend<SystemCommandExecutor>,
    pub smtp: &'a Arc<Mutex<Vec<Vec<u8>>>>,
    pub drop_ack: &'a Arc<AtomicBool>,
    pub sent_mailbox: &'a crate::mailbox_helper::NativeProtectedSentMailbox,
    pub sent_path: &'a Path,
    pub sent_count: &'a Path,
    pub primary: &'a str,
    pub recipient_primary: &'a str,
    pub binding_revision: u64,
    pub attachments: &'a [crate::send::UploadedAttachment],
    pub public_certificate: &'a [u8],
}

struct AdmissionFixture {
    epoch: Arc<AtomicU64>,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    _mutation_listener: UnixListener,
}
impl AdmissionFixture {
    fn new(scratch: &Scratch, gateway: &mut RuntimeBrowserGateway) -> Self {
        use crate::openpgp_inventory_runtime::{now, read_frame, write_frame};
        let key = [29; 32];
        let admission_key = scratch.write("admission.key", &key, 0o600);
        let mutation_key = scratch.write("mutation.key", &[31; 32], 0o600);
        let proof_key = scratch.write("session-proof.key", &[37; 32], 0o600);
        let socket = scratch.0.join("e.sock");
        let mutation_socket = scratch.0.join("m.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mutation_listener = UnixListener::bind(&mutation_socket).unwrap();
        for path in [&socket, &mutation_socket] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o660)).unwrap();
        }
        let uid = crate::openbsd::effective_uid();
        let admission = crate::account_admission_runtime::Client::paired_fixture_files(
            &socket,
            &admission_key,
            uid,
        )
        .unwrap();
        let mutation = crate::account_mutation_client::Client::stored_fixture_files(
            &mutation_socket,
            &mutation_key,
            &proof_key,
            uid,
        )
        .unwrap();
        gateway.account_runtime =
            crate::http::http_gateway::http_gateway_account::AccountRuntimeCapability::fixture(
                admission, mutation,
            );
        gateway.account_rollout = Some(ACCOUNT.into());
        let epoch = Arc::new(AtomicU64::new(2));
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let current = epoch.clone();
        let count = requests.clone();
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(120);
            let mut verifier = crate::account_admission::Verifier::default();
            while !stopped.load(Ordering::SeqCst) && Instant::now() < end {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => panic!("scheduled native admission accept refused"),
                };
                assert_eq!(crate::openbsd::unix_stream_peer_uid(&stream).unwrap(), uid);
                let deadline = Instant::now() + Duration::from_secs(3);
                let raw =
                    read_frame(&mut stream, crate::account_admission::MAX_FRAME, deadline).unwrap();
                let request = verifier.request(&raw, &key, now().unwrap()).unwrap();
                assert_eq!(request.account(), ACCOUNT);
                let crate::account_admission::Operation::Admit { epoch: wanted } =
                    request.operation()
                else {
                    panic!("scheduled native fixture permits only epoch admission");
                };
                assert!(count.fetch_add(1, Ordering::SeqCst) < 16);
                let epoch = current.load(Ordering::SeqCst);
                let response = request
                    .response((*wanted == epoch).then_some(epoch), &key, now().unwrap())
                    .unwrap();
                write_frame(&mut stream, &response, deadline).unwrap();
            }
        });
        Self {
            epoch,
            requests,
            stop,
            thread: Some(thread),
            _mutation_listener: mutation_listener,
        }
    }
    fn finish(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread
            .take()
            .unwrap()
            .join()
            .expect("scheduled native admission cleanup");
    }
}
impl Drop for AdmissionFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                println!("native_scheduled admission_cleanup=UNCONFIRMED");
            }
        }
    }
}

fn witness(scratch: &Scratch, observations: &mut Vec<serde_json::Value>, value: serde_json::Value) {
    observations.push(value);
    println!(
        "native_scheduled_observation {}",
        serde_json::to_string(observations.last().unwrap()).unwrap()
    );
    let bytes = serde_json::to_vec(&serde_json::json!({
        "version": 1, "account_state_source": "controlled_peer_mac_fixture_epoch_not_live_db",
        "observations": observations,
    }))
    .unwrap();
    let path = scratch.0.join("scheduled-observation.json");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    fs::File::open(&scratch.0).unwrap().sync_all().unwrap();
}
fn kind(outcome: &ScheduledSendOutcome) -> &'static str {
    match &outcome.decision {
        ScheduledDispatch::Submitted => "submitted",
        ScheduledDispatch::Blocked(BlockReason::KeyLocked) => "blocked_locked",
        ScheduledDispatch::Blocked(BlockReason::AccountChanged) => "blocked_epoch",
        ScheduledDispatch::Blocked(_) => "blocked_other",
        ScheduledDispatch::Unknown => "unknown",
    }
}
fn claim(
    store: &ScheduledStore,
    journal: &crate::send_journal::SendJournal,
    session: &PrivateSession,
    request: &ComposeRequest,
) -> ClaimedJob {
    let now = SystemTimeProvider.unix_timestamp();
    let due = now + 1;
    {
        let mut guard = journal.account_guard(ACCOUNT, now).unwrap();
        let revision = store.list(&guard, now).unwrap().revision;
        let staged = store
            .create_staged(
                &guard,
                revision,
                ScheduleInput {
                    due_at: due,
                    account_epoch: 2,
                    private_session: session.clone(),
                    request,
                },
                now,
            )
            .unwrap();
        let source = crate::send_journal::mint_intent(now).unwrap();
        guard
            .begin_schedule(&source, &staged.id, &staged.digest)
            .unwrap();
        store
            .publish_pending(&guard, staged.revision, &staged.id, &staged.digest, now)
            .unwrap();
        guard
            .finish_schedule(&source, &staged.id, &staged.digest)
            .unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while SystemTimeProvider.unix_timestamp() < due {
        assert!(
            Instant::now() < deadline,
            "scheduled native due clock did not advance"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let now = SystemTimeProvider.unix_timestamp();
    let guard = journal.account_guard(ACCOUNT, now).unwrap();
    store.claim_next(&guard, now).unwrap().unwrap()
}
fn assert_sent(inputs: &Inputs<'_>, wire: &[u8]) {
    use crate::auth::CommandExecutor;
    let read = SystemCommandExecutor
        .run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/local/bin/doveadm",
            &[
                "-c".into(),
                inputs.sent_mailbox.config.to_string_lossy().into_owned(),
                "-o".into(),
                "stats_writer_socket_path=".into(),
                "-o".into(),
                format!("auth_socket_path={}", inputs.sent_mailbox.userdb.display()),
                "-f".into(),
                "json".into(),
                "fetch".into(),
                "-u".into(),
                ACCOUNT.into(),
                "text".into(),
                "mailbox".into(),
                "Sent".into(),
                "all".into(),
            ],
            b"",
            Duration::from_secs(3),
            32768,
        )
        .unwrap();
    let status = read.status_code;
    let path = inputs.scratch.0.join("scheduled-sent-read.json");
    let mut retained = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    retained
        .write_all(
            &serde_json::to_vec(&serde_json::json!({
                "status": status, "stdout": read.stdout.as_str(), "stderr": read.stderr.as_str(),
            }))
            .unwrap(),
        )
        .unwrap();
    retained.sync_all().unwrap();
    fs::File::open(&inputs.scratch.0)
        .unwrap()
        .sync_all()
        .unwrap();
    assert_eq!(status, 0, "scheduled native real Sent fetch refused");
    let rows: serde_json::Value = serde_json::from_str(&read.stdout).unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    let text = rows[0]["text"].as_str().unwrap();
    let normalize = |bytes: &[u8]| std::str::from_utf8(bytes).unwrap().replace("\r\n", "\n");
    assert!(
        normalize(text.as_bytes()) == normalize(wire),
        "scheduled real Sent exact wire mismatch"
    );
}

#[cfg(target_os = "openbsd")]
pub(super) fn run_serve(inputs: Inputs<'_>) {
    use crate::http::http_runtime::scheduled_positive_fixture as fixture;
    use crate::send_journal::AttemptOutcome;
    let began = Instant::now();
    let admission = AdmissionFixture::new(inputs.scratch, inputs.gateway);
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserved.local_addr().unwrap().port();
    let config = fixture::configuration(&inputs.scratch.0, port);
    for directory in [&config.state_root, &config.state_layout.runtime_dir,
        &config.state_layout.settings_dir, &config.state_layout.session_dir,
        &config.state_layout.draft_dir, &config.state_layout.audit_dir,
        &config.state_layout.cache_dir, &config.state_layout.totp_secret_dir] {
        fs::create_dir_all(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store = ScheduledStore::new(config.state_layout.settings_dir.join("scheduled-send"));
    let journal = crate::send_journal::SendJournal::new(config.state_layout.settings_dir.join("send-journal"));
    let now = SystemTimeProvider.unix_timestamp();
    let request = ComposeRequest::new(ComposePolicy::default(), "bob@example.test",
        "Native confined scheduled message", "Controlled post-seal ordinary scheduled body\r\n").unwrap();
    let make_pending = |account: &str, due_at: u64| {
        let mut guard = journal.account_guard(account, now).unwrap();
        let staged = store.create_staged(&guard, 0, ScheduleInput {
            due_at, account_epoch: 2,
            private_session: PrivateSession { session_id: "a".repeat(64), account_epoch: Some(2), expires_at: now + 3600 },
            request: &request,
        }, now).unwrap();
        let source = crate::send_journal::mint_intent(now).unwrap();
        guard.begin_schedule(&source, &staged.id, &staged.digest).unwrap();
        store.publish_pending(&guard, staged.revision, &staged.id, &staged.digest, now).unwrap();
        guard.finish_schedule(&source, &staged.id, &staged.digest).unwrap();
        staged.id
    };
    let id = make_pending(ACCOUNT, now + 1);
    let foreign_id = make_pending("bob@example.test", now + 3600);
    let foreign_before = {
        let guard = journal.account_guard("bob@example.test", now).unwrap();
        store.list(&guard, now).unwrap()
    };
    assert!(foreign_before.jobs.iter().any(|job| job.id == foreign_id && job.state == State::Pending));
    // Due before Serve starts: no manual claim/run_once can dispatch the job.
    let due_deadline = Instant::now() + Duration::from_secs(3);
    while SystemTimeProvider.unix_timestamp() <= now {
        assert!(Instant::now() < due_deadline); std::thread::sleep(Duration::from_millis(5));
    }
    let stdout_path = inputs.scratch.write("serve-child.stdout", b"", 0o600);
    let stderr_path = inputs.scratch.write("serve-child.stderr", b"", 0o600);
    let stdout = fs::OpenOptions::new().append(true).open(stdout_path).unwrap();
    let stderr = fs::OpenOptions::new().append(true).open(&stderr_path).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", TEST_NAME, "--ignored", "--nocapture", "--test-threads=1"])
        .env_clear().env("PATH", "/usr/bin:/bin:/usr/local/bin").env("LC_ALL", "C").env("TZ", "UTC").env("TMPDIR", "/tmp")
        .env("OSMAP_GATEWAY_NATIVE_SERVICE", "scheduled-serve")
        .env(fixture::ROOT_ENV, &inputs.scratch.0).env(fixture::PORT_ENV, port.to_string())
        .stdin(Stdio::null()).stdout(Stdio::from(stdout)).stderr(Stdio::from(stderr));
    drop(reserved);
    struct ServeChild { child: Child, reaped: bool }
    impl ServeChild {
        fn alive(&mut self) -> bool {
            if !self.reaped { self.reaped = self.child.try_wait().unwrap().is_some(); }
            !self.reaped
        }
        fn stop(&mut self) -> bool {
            if !self.alive() { return true; }
            let _ = self.child.kill();
            let end = Instant::now() + Duration::from_secs(2);
            while Instant::now() < end {
                if !self.alive() { return true; }
                std::thread::sleep(Duration::from_millis(10));
            }
            false
        }
    }
    impl Drop for ServeChild { fn drop(&mut self) { if !self.stop() { println!("native_scheduled_serve child_cleanup=UNCONFIRMED"); } } }
    let mut child = ServeChild { child: command.spawn().unwrap(), reaped: false };
    let health = || {
        use std::io::Read as _;
        let Ok(mut stream) = TcpStream::connect_timeout(&std::net::SocketAddr::from(([127,0,0,1],port)),Duration::from_millis(250)) else {return false};
        stream.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
        stream.set_write_timeout(Some(Duration::from_millis(250))).unwrap();
        if stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").is_err() {return false;}
        let mut response=Vec::new();
        if stream.take(8193).read_to_end(&mut response).is_err() {return false;}
        response.len() <= 8192 && response.starts_with(b"HTTP/1.1 200 ") && response.ends_with(b"ok\n")
    };
    let deadline=Instant::now()+Duration::from_secs(25);
    let mut healthy=false; let mut settled=None;
    while Instant::now()<deadline && child.alive() {
        if !healthy { healthy=health(); }
        let now=SystemTimeProvider.unix_timestamp();
        if let Ok(guard)=journal.account_guard(ACCOUNT,now) {
            if let Ok(list)=store.list(&guard,now) {
                settled=list.jobs.into_iter().find(|job|job.id==id && !matches!(job.state,State::Pending|State::Claimed));
            }
        }
        if healthy && settled.is_some() { break; }
        std::thread::sleep(Duration::from_millis(25));
    }
    let mut observations=Vec::new();
    witness(inputs.scratch,&mut observations,serde_json::json!({"stage":"postseal_dispatch",
        "healthy":healthy,"state":settled.as_ref().map(|job|job.state),"reason":settled.as_ref().and_then(|job|job.reason),
        "smtp":inputs.smtp.lock().unwrap().len(),"admission_exchanges":admission.requests.load(Ordering::SeqCst),
        "positive_kind":"ordinary_actual_serve_controlled_peer_not_live_db"}));
    assert!(healthy && child.alive());
    let settled=settled.expect("post-seal worker did not settle captured Pending job");
    assert_eq!(settled.state,State::Submitted);
    let intent=settled.intent.as_deref().unwrap();
    assert_eq!(journal.receipt(ACCOUNT,intent,SystemTimeProvider.unix_timestamp()).unwrap(),Some(AttemptOutcome::Accepted{sent_copy_stored:true}));
    assert_eq!(inputs.smtp.lock().unwrap().len(),1);
    assert_eq!(fs::read(inputs.sent_count).unwrap(),b"1");
    let wire=inputs.smtp.lock().unwrap()[0].clone();
    assert_eq!(fs::read(inputs.sent_path).unwrap(),wire);
    assert!(std::str::from_utf8(&wire).unwrap().contains("Controlled post-seal ordinary scheduled body"));
    assert_sent(&inputs,&wire);
    // Observe the existing worker's durable clock cursor after its next real
    // pass, instead of treating elapsed time as proof that the thread ran.
    let cursor_file=crate::private_account_file::PrivateAccountFile::new(
        config.state_layout.settings_dir.join("scheduled-worker"),"scheduled-worker-v1",4096);
    let cursor_state=|| {
        let bytes=cursor_file.read("worker@osmap.invalid").unwrap().unwrap();
        let value=serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
        (value["high_water"].as_u64().unwrap(),value["after"].as_str().unwrap().to_owned())
    };
    let initial_deadline=Instant::now()+Duration::from_secs(3);
    let initial_cursor=loop {
        let (clock,after)=cursor_state();
        if after=="bob@example.test" {break clock;}
        assert!(child.alive()&&Instant::now()<initial_deadline,"initial Alice processing did not complete");
        std::thread::sleep(Duration::from_millis(10));
    };
    let next_pass=Instant::now()+Duration::from_secs(20);
    let mut advanced=false;
    while Instant::now()<next_pass {
        assert!(child.alive(),"Serve exited before next scheduler pass");
        let (clock,after)=cursor_state();
        if clock>=initial_cursor.checked_add(15).unwrap() && after=="bob@example.test" {advanced=true;break;}
        std::thread::sleep(Duration::from_millis(100));
    }
    witness(inputs.scratch,&mut observations,serde_json::json!({"stage":"next_worker_cursor","advanced":advanced,"initial_bob_baseline":true,"subsequent_alice_completed_then_bob_admitted":advanced}));
    assert!(advanced,"actual scheduled worker cursor did not advance through another pass");
    assert!(health());
    assert_eq!(inputs.smtp.lock().unwrap().len(),1);
    assert_eq!(fs::read(inputs.sent_count).unwrap(),b"1");
    assert_eq!(admission.requests.load(Ordering::SeqCst),2);
    let foreign_after={let now=SystemTimeProvider.unix_timestamp();let guard=journal.account_guard("bob@example.test",now).unwrap();store.list(&guard,now).unwrap()};
    assert_eq!(foreign_after,foreign_before);
    assert!(child.stop(),"post-seal child reap unconfirmed");
    let logs=crate::private_account_file::read_record(&stderr_path,128*1024).unwrap().unwrap();
    let stdout=crate::private_account_file::read_record(&inputs.scratch.0.join("serve-child.stdout"),128*1024).unwrap().unwrap();
    // Successful Scratch cleanup follows this bounded durable copy. On panic,
    // Scratch already retains the original child files for private readback.
    use sha2::{Digest, Sha256};
    let outer_log=inputs.scratch.0.parent().unwrap().join("commands.log");
    let before=fs::symlink_metadata(&outer_log).unwrap();
    let uid=crate::openbsd::effective_uid();
    assert!(before.is_file()&&!before.file_type().is_symlink()&&before.nlink()==1&&before.uid()==uid&&before.mode()&0o777==0o600);
    let mut log=fs::OpenOptions::new().append(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK).open(&outer_log).unwrap();
    let opened=log.metadata().unwrap();
    assert!(opened.is_file()&&opened.nlink()==1&&opened.uid()==uid&&opened.mode()&0o777==0o600
        &&(opened.dev(),opened.ino())==(before.dev(),before.ino()));
    for (name,bytes) in [("stdout",stdout.as_slice()),("stderr",logs.as_slice())] {
        let retained=&bytes[bytes.len().saturating_sub(16*1024)..];
        writeln!(log,"\nS08_SCHEDULED_SERVE_CHILD stream={name} total={} retained_tail={} sha256={:x}",bytes.len(),retained.len(),Sha256::digest(bytes)).unwrap();
        log.write_all(retained).unwrap();log.write_all(b"\nS08_SCHEDULED_SERVE_CHILD_END\n").unwrap();
    }
    log.sync_all().unwrap();
    println!("native_scheduled_serve child_logs=OUTER_COMMAND_LOG_SYNCED stdout_bytes={} stderr_bytes={} stdout_sha256={:x} stderr_sha256={:x}",stdout.len(),logs.len(),Sha256::digest(&stdout),Sha256::digest(&logs));
    let logs=std::str::from_utf8(&logs).unwrap();
    assert!(logs.contains("action=openbsd_confinement_enabled") && logs.contains("openbsd_confinement_mode=\"enforce\""));
    assert!(std::str::from_utf8(&stdout).unwrap().contains("fixture_exec_leaf_rules=4 private_ancestor_exec=false"));
    witness(inputs.scratch,&mut observations,serde_json::json!({"stage":"postseal_complete","result":"PASS",
        "actual_serve_enforce":true,"actual_background_dispatch":true,"smtp_accepted":1,"native_sent":1,
        "typed_journal_accepted":true,"persisted_submitted":true,"next_worker_pass_no_duplicate":true,
        "foreign_job_unchanged":true,"owned_child_reaped":true,"ordinary_only":true,"actual_db":"NOT_QUALIFIED",
        "fixture_exec_rules":"four_exact_leaves_not_production_transport_custody"}));
    admission.finish();
    assert!(began.elapsed()<Duration::from_secs(50));
}

pub(super) fn run(inputs: Inputs<'_>) {
    let began = Instant::now();
    let admission = AdmissionFixture::new(inputs.scratch, inputs.gateway);
    let now = SystemTimeProvider.unix_timestamp();
    let session = PrivateSession {
        session_id: "c".repeat(64),
        account_epoch: Some(2),
        expires_at: now + 300,
    };
    let sessions = FileSessionStore::new(inputs.gateway.session_dir.clone());
    sessions
        .save(&crate::session::SessionRecord {
            account_epoch: Some(2),
            session_id: session.session_id.clone(),
            csrf_token: "d".repeat(64),
            canonical_username: ACCOUNT.into(),
            issued_at: now - 1,
            expires_at: session.expires_at,
            last_seen_at: now,
            revoked_at: None,
            remote_addr: "127.0.0.1".into(),
            user_agent: "Controlled scheduled native enrollment".into(),
            factor: crate::auth::RequiredSecondFactor::Totp,
        })
        .unwrap();
    let mut observations = Vec::new();
    let unlocked = inputs.crypto.personal(
        ACCOUNT,
        &session,
        PersonalAction::Unlock { passphrase: b"" },
    );
    witness(
        inputs.scratch,
        &mut observations,
        serde_json::json!({"stage":"initial_unlock",
        "result": unlocked.as_ref().map(|state| state.unlocked_for_session).map_err(|e|format!("{e:?}"))}),
    );
    assert!(unlocked.unwrap().unlocked_for_session);
    let store = ScheduledStore::new(inputs.gateway.settings_dir.join("scheduled-send"));
    let journal =
        crate::send_journal::SendJournal::new(inputs.gateway.settings_dir.join("send-journal"));
    let mut request = ComposeRequest::new_with_routing(
        ComposePolicy::default(),
        "bob@example.test",
        "",
        "",
        "Synthetic gateway protected",
        "Synthetic café body\nSecond line",
        inputs.attachments.to_vec(),
    )
    .unwrap();
    request.protection = crate::send::ProtectionIntent {
        sign: true,
        encrypt: true,
        encrypt_to_self: true,
        binding_revision: Some(inputs.binding_revision),
    };
    let positive = claim(&store, &journal, &session, &request);
    let sent = inputs.gateway.dispatch_scheduled_with_backends(
        &positive,
        inputs.submission,
        inputs.append,
    );
    witness(
        inputs.scratch,
        &mut observations,
        serde_json::json!({"stage":"positive",
        "result":kind(&sent),"smtp":inputs.smtp.lock().unwrap().len()}),
    );
    assert!(matches!(sent.decision, ScheduledDispatch::Submitted));
    assert_eq!(inputs.smtp.lock().unwrap().len(), 1);
    assert_eq!(fs::read(inputs.sent_count).unwrap(), b"1");
    let wire = inputs.smtp.lock().unwrap()[0].clone();
    assert_eq!(fs::read(inputs.sent_path).unwrap(), wire);
    assert_sent(&inputs, &wire);
    let crate::pgp_mime::PgpMimeMessage::Encrypted { ciphertext, .. } =
        crate::pgp_mime::classify(&wire, crate::pgp_mime::PgpMimePolicy::default()).unwrap()
    else {
        panic!("scheduled protected MIME required")
    };
    let bound = inputs.crypto.for_session(session.clone());
    let bob = bound
        .execute(
            "bob@example.test",
            &crate::openpgp_crypto::Operation::Decrypt {
                allowed_primary_fingerprints: vec![inputs.recipient_primary.into()],
                ciphertext: ciphertext.clone(),
            },
        )
        .unwrap()
        .unwrap();
    let own = bound
        .execute(
            ACCOUNT,
            &crate::openpgp_crypto::Operation::Decrypt {
                allowed_primary_fingerprints: vec![inputs.primary.into()],
                ciphertext,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(own.content, bob.content);
    let crate::pgp_mime::PgpMimeMessage::Signed {
        canonical_entity,
        signature,
        ..
    } = crate::pgp_mime::classify(&bob.content, crate::pgp_mime::PgpMimePolicy::default()).unwrap()
    else {
        panic!("scheduled signed entity required")
    };
    let verified = bound
        .execute(
            "bob@example.test",
            &crate::openpgp_crypto::Operation::Verify {
                data: canonical_entity.clone(),
                signature,
            },
        )
        .unwrap()
        .unwrap();
    let signature_valid = verified.signature == crate::openpgp_crypto::SignatureState::Valid
        && verified.primary_fingerprint.as_deref() == Some(inputs.primary);
    witness(
        inputs.scratch,
        &mut observations,
        serde_json::json!({"stage":"verified","signature_valid":signature_valid}),
    );
    assert!(signature_valid);
    assert_eq!(
        attached_public_certificate(&canonical_entity),
        inputs.public_certificate
    );
    assert_decrypted_authored_entity(&canonical_entity);
    {
        let guard = journal
            .account_guard(ACCOUNT, SystemTimeProvider.unix_timestamp())
            .unwrap();
        store
            .submitted(&guard, &positive, SystemTimeProvider.unix_timestamp())
            .unwrap();
    }
    let replay = inputs.gateway.dispatch_scheduled_with_backends(
        &positive,
        inputs.submission,
        inputs.append,
    );
    assert!(matches!(replay.decision, ScheduledDispatch::Submitted));
    assert_eq!(inputs.smtp.lock().unwrap().len(), 1);
    assert_eq!(fs::read(inputs.sent_count).unwrap(), b"1");
    let locked = inputs
        .crypto
        .personal(ACCOUNT, &session, PersonalAction::Lock);
    witness(
        inputs.scratch,
        &mut observations,
        serde_json::json!({"stage":"lock",
        "result":locked.as_ref().map(|s|!s.unlocked_for_session).map_err(|e|format!("{e:?}"))}),
    );
    assert!(!locked.unwrap().unlocked_for_session);
    let locked_job = claim(&store, &journal, &session, &request);
    let locked = inputs.gateway.dispatch_scheduled_with_backends(
        &locked_job,
        inputs.submission,
        inputs.append,
    );
    witness(
        inputs.scratch,
        &mut observations,
        serde_json::json!({"stage":"locked_send","result":kind(&locked),
        "smtp":inputs.smtp.lock().unwrap().len()}),
    );
    assert!(matches!(
        locked.decision,
        ScheduledDispatch::Blocked(BlockReason::KeyLocked)
    ));
    assert!(journal
        .receipt(
            ACCOUNT,
            locked_job.intent(),
            SystemTimeProvider.unix_timestamp()
        )
        .unwrap()
        .is_none());
    {
        let guard = journal
            .account_guard(ACCOUNT, SystemTimeProvider.unix_timestamp())
            .unwrap();
        store
            .block_unsubmitted(
                &guard,
                &locked_job,
                BlockReason::KeyLocked,
                SystemTimeProvider.unix_timestamp(),
            )
            .unwrap();
    }
    let unlocked = inputs.crypto.personal(
        ACCOUNT,
        &session,
        PersonalAction::Unlock { passphrase: b"" },
    );
    witness(
        inputs.scratch,
        &mut observations,
        serde_json::json!({"stage":"second_unlock",
        "result":unlocked.as_ref().map(|s|s.unlocked_for_session).map_err(|e|format!("{e:?}"))}),
    );
    assert!(unlocked.unwrap().unlocked_for_session);
    inputs.drop_ack.store(true, Ordering::SeqCst);
    let uncertain_job = claim(&store, &journal, &session, &request);
    let uncertain = inputs.gateway.dispatch_scheduled_with_backends(
        &uncertain_job,
        inputs.submission,
        inputs.append,
    );
    witness(
        inputs.scratch,
        &mut observations,
        serde_json::json!({"stage":"lost_smtp_ack","result":kind(&uncertain),
        "smtp":inputs.smtp.lock().unwrap().len()}),
    );
    assert!(matches!(uncertain.decision, ScheduledDispatch::Unknown));
    assert_eq!(inputs.smtp.lock().unwrap().len(), 2);
    assert_eq!(fs::read(inputs.sent_count).unwrap(), b"1");
    {
        let guard = journal
            .account_guard(ACCOUNT, SystemTimeProvider.unix_timestamp())
            .unwrap();
        store
            .unknown(&guard, &uncertain_job, SystemTimeProvider.unix_timestamp())
            .unwrap();
    }
    let replay = inputs.gateway.dispatch_scheduled_with_backends(
        &uncertain_job,
        inputs.submission,
        inputs.append,
    );
    assert!(matches!(replay.decision, ScheduledDispatch::Unknown));
    assert_eq!(inputs.smtp.lock().unwrap().len(), 2);
    inputs.drop_ack.store(false, Ordering::SeqCst);
    admission.epoch.store(3, Ordering::SeqCst);
    let stale_job = claim(&store, &journal, &session, &request);
    let stale = inputs.gateway.dispatch_scheduled_with_backends(
        &stale_job,
        inputs.submission,
        inputs.append,
    );
    witness(
        inputs.scratch,
        &mut observations,
        serde_json::json!({"stage":"stale_epoch","result":kind(&stale),
        "smtp":inputs.smtp.lock().unwrap().len(),"admission_requests":admission.requests.load(Ordering::SeqCst)}),
    );
    assert!(matches!(
        stale.decision,
        ScheduledDispatch::Blocked(BlockReason::AccountChanged)
    ));
    assert!(journal
        .receipt(
            ACCOUNT,
            stale_job.intent(),
            SystemTimeProvider.unix_timestamp()
        )
        .unwrap()
        .is_none());
    assert_eq!(inputs.smtp.lock().unwrap().len(), 2);
    assert_eq!(fs::read(inputs.sent_count).unwrap(), b"1");
    {
        let guard = journal
            .account_guard(ACCOUNT, SystemTimeProvider.unix_timestamp())
            .unwrap();
        store
            .block_unsubmitted(
                &guard,
                &stale_job,
                BlockReason::AccountChanged,
                SystemTimeProvider.unix_timestamp(),
            )
            .unwrap();
        let jobs = store
            .list(&guard, SystemTimeProvider.unix_timestamp())
            .unwrap();
        assert_eq!(
            jobs.jobs
                .iter()
                .filter(|j| j.state == State::Submitted)
                .count(),
            1
        );
        assert_eq!(
            jobs.jobs
                .iter()
                .filter(|j| j.state == State::Blocked)
                .count(),
            2
        );
        assert_eq!(
            jobs.jobs
                .iter()
                .filter(|j| j.state == State::Unknown)
                .count(),
            1
        );
    }
    assert_eq!(admission.requests.load(Ordering::SeqCst), 6);
    admission.finish();
    assert!(began.elapsed() < Duration::from_secs(120));
    witness(
        inputs.scratch,
        &mut observations,
        serde_json::json!({"stage":"complete","functional":"PASS",
        "smtp_messages":2,"sent_messages":1,"admission_cleanup":"PASS","real_account_db":"NOT_QUALIFIED"}),
    );
    println!("native_scheduled result=PASS protected_delivery=true locked_refusal=true stale_epoch_refusal=true uncertain_ack_no_retry=true real_sent=true admission=PEER_MAC_CONTROLLED_EPOCH real_account_db=NOT_QUALIFIED");
}
