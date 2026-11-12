use super::*;
use std::cell::{Cell, RefCell};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const ALICE: &str = "alice@example.test";
const BOB: &str = "bob@example.test";
const FLOW: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove owned synthetic store");
    }
}
struct Native {
    enabled: Cell<bool>,
    epoch: Cell<u64>,
    revision: Cell<u64>,
    factor: RefCell<String>,
    lookups: Cell<usize>,
}
impl Authority for Native {
    fn eligible(&self, account: &str, _: Instant) -> Result<Option<EligibleAccount>, Error> {
        self.lookups.set(self.lookups.get() + 1);
        Ok(
            (self.enabled.get() && account == ALICE).then(|| EligibleAccount {
                epoch: self.epoch.get(),
                verified_email: "recovery@example.test".into(),
                contact_revision: self.revision.get(),
                verified_at: 1,
                existing_factor_sha256: self.factor.borrow().clone(),
            }),
        )
    }
}
struct Mail {
    sent: RefCell<Vec<(String, String)>>,
    outcome: Cell<RecoveryContactDelivery>,
}
impl Notifier for Mail {
    fn deliver(
        &self,
        account: &str,
        _: &str,
        code: &str,
        _: u64,
        _: Instant,
    ) -> RecoveryContactDelivery {
        self.sent.borrow_mut().push((account.into(), code.into()));
        self.outcome.get()
    }
}
struct Sequence(Cell<u8>);
impl RandomSource for Sequence {
    fn fill_bytes(&self, output: &mut [u8]) -> Result<(), crate::session::SessionError> {
        let value = self.0.get();
        output.fill(value);
        self.0.set(value.wrapping_add(1));
        Ok(())
    }
}
struct Fixture {
    root: Scratch,
    store: Store,
    native: Native,
    mail: Mail,
    random: Sequence,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "osmap-access-recovery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("exclusive synthetic root");
        Self {
            root: Scratch(path.clone()),
            store: Store::new(path),
            native: Native {
                enabled: Cell::new(true),
                epoch: Cell::new(3),
                revision: Cell::new(1),
                factor: RefCell::new("a".repeat(64)),
                lookups: Cell::new(0),
            },
            mail: Mail {
                sent: RefCell::new(Vec::new()),
                outcome: Cell::new(RecoveryContactDelivery::Accepted),
            },
            random: Sequence(Cell::new(1)),
        }
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(3)
    }
    fn start(&self, account: &str, source: &str, now: u64) -> Started {
        self.store
            .start_random(
                Start {
                    account,
                    source,
                    flow: FLOW,
                    now,
                    deadline: Self::deadline(),
                },
                &self.native,
                &self.mail,
                &self.random,
            )
            .expect("generic start")
    }
    fn proof(
        &self,
        account: &str,
        challenge: &Started,
        code: &str,
        now: u64,
    ) -> Result<RestrictedGrant, Error> {
        self.store.verify_random(
            Verify {
                account,
                source: "192.0.2.1",
                flow: FLOW,
                challenge_id: &challenge.challenge_id,
                email_code: code,
                now,
                deadline: Self::deadline(),
            },
            &self.native,
            &self.random,
        )
    }
    fn grant(&self) -> RestrictedGrant {
        let challenge = self.start(ALICE, "192.0.2.1", 100);
        let code = self.mail.sent.borrow()[0].1.clone();
        self.proof(ALICE, &challenge, &code, 101)
            .expect("proof grant")
    }
    fn bytes(&self) -> Vec<u8> {
        fn collect(path: &std::path::Path, output: &mut Vec<u8>) {
            for entry in fs::read_dir(path).expect("owned directory") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    collect(&path, output);
                } else if path.extension().is_some_and(|v| v == "json") {
                    output.extend(fs::read(path).expect("record"));
                }
            }
        }
        let mut output = Vec::new();
        collect(&self.root.0, &mut output);
        output
    }
}

#[test]
fn email_proof_issues_only_bound_restricted_grant_and_stores_no_plaintext_secrets() {
    let f = Fixture::new();
    let grant = f.grant();
    assert_eq!(grant.binding.account, ALICE);
    assert_eq!(grant.binding.epoch, 3);
    assert_eq!(grant.binding.purpose, Purpose::AccountRecoverySetup);
    let read = f
        .store
        .lookup_grant(grant.token(), FLOW, 102, Fixture::deadline(), &f.native)
        .unwrap();
    assert_eq!(read.account, ALICE);
    let disk = String::from_utf8(f.bytes()).unwrap();
    assert!(!disk.contains(grant.token()));
    assert!(!disk.contains(&format!("\"{}\"", f.mail.sent.borrow()[0].1)));
    assert!(!disk.contains("recovery@example.test"));
    assert!(!format!("{grant:?}").contains(grant.token()));
}

#[test]
fn unknown_and_throttled_accounts_have_same_public_start_shape_without_mail() {
    let f = Fixture::new();
    let known = f.start(ALICE, "192.0.2.1", 100);
    let unknown = f.start(BOB, "192.0.2.1", 100);
    assert_eq!(known.challenge_id.len(), unknown.challenge_id.len());
    assert_eq!(known.expires_at, unknown.expires_at);
    assert_eq!(f.mail.sent.borrow().len(), 1);
    for now in [160, 220, 280] {
        f.start(ALICE, "192.0.2.2", now);
    }
    assert_eq!(f.mail.sent.borrow().len(), 3);
    assert_eq!(
        f.proof(BOB, &unknown, "123456", 101).unwrap_err(),
        Error::Denied
    );
}

#[test]
fn wrong_code_and_wrong_account_do_not_grant_or_consume_other_proofs() {
    let f = Fixture::new();
    let challenge = f.start(ALICE, "192.0.2.1", 100);
    let code = f.mail.sent.borrow()[0].1.clone();
    assert_eq!(
        f.proof(BOB, &challenge, &code, 101).unwrap_err(),
        Error::Denied
    );
    assert_eq!(
        f.proof(ALICE, &challenge, "abcdef", 101).unwrap_err(),
        Error::Denied
    );
    assert!(f.proof(ALICE, &challenge, &code, 102).is_ok());
    assert_eq!(
        f.proof(ALICE, &challenge, &code, 103).unwrap_err(),
        Error::Denied
    );
}

#[test]
fn attempt_limit_and_source_limit_are_durable_and_account_scoped() {
    let f = Fixture::new();
    let challenge = f.start(ALICE, "192.0.2.1", 100);
    for _ in 0..5 {
        assert_eq!(
            f.proof(ALICE, &challenge, "abcdef", 101).unwrap_err(),
            Error::Denied
        );
    }
    let code = f.mail.sent.borrow()[0].1.clone();
    assert_eq!(
        f.proof(ALICE, &challenge, &code, 102).unwrap_err(),
        Error::Denied
    );
    let reopened = Store::new(f.root.0.clone());
    for _ in 0..30 {
        reopened
            .start_random(
                Start {
                    account: BOB,
                    source: "198.51.100.2",
                    flow: FLOW,
                    now: 103,
                    deadline: Fixture::deadline(),
                },
                &f.native,
                &f.mail,
                &f.random,
            )
            .unwrap();
    }
    let prior = f.native.lookups.get();
    reopened
        .start_random(
            Start {
                account: ALICE,
                source: "198.51.100.2",
                flow: FLOW,
                now: 104,
                deadline: Fixture::deadline(),
            },
            &f.native,
            &f.mail,
            &f.random,
        )
        .unwrap();
    assert_eq!(f.native.lookups.get(), prior);
}

#[test]
fn expiry_epoch_contact_or_factor_change_refuses_restricted_authority() {
    for changed in 0..4 {
        let f = Fixture::new();
        let grant = f.grant();
        let now = match changed {
            0 => grant.binding.expires_at,
            1 => {
                f.native.epoch.set(4);
                102
            }
            2 => {
                f.native.revision.set(2);
                102
            }
            _ => {
                *f.native.factor.borrow_mut() = "b".repeat(64);
                102
            }
        };
        assert!(f
            .store
            .lookup_grant(grant.token(), FLOW, now, Fixture::deadline(), &f.native)
            .is_err());
        let called = Cell::new(false);
        assert!(f
            .store
            .consume_grant(
                grant.token(),
                FLOW,
                now,
                Fixture::deadline(),
                &f.native,
                |_| {
                    called.set(true);
                    Ok(())
                }
            )
            .is_err());
        assert!(!called.get());
    }
}

#[test]
fn expired_email_proof_cannot_issue_grant() {
    let f = Fixture::new();
    let challenge = f.start(ALICE, "192.0.2.1", 100);
    let code = f.mail.sent.borrow()[0].1.clone();
    assert_eq!(
        f.proof(ALICE, &challenge, &code, challenge.expires_at)
            .unwrap_err(),
        Error::Denied
    );
}

#[test]
fn grant_effect_is_once_across_reopen_and_complete_record() {
    let f = Fixture::new();
    let grant = f.grant();
    let calls = Cell::new(0);
    f.store
        .consume_grant(
            grant.token(),
            FLOW,
            102,
            Fixture::deadline(),
            &f.native,
            |binding| {
                assert_eq!(binding.account, ALICE);
                calls.set(calls.get() + 1);
                Ok(())
            },
        )
        .unwrap();
    let reopened = Store::new(f.root.0.clone());
    assert_eq!(
        reopened.consume_grant(
            grant.token(),
            FLOW,
            103,
            Fixture::deadline(),
            &f.native,
            |_| {
                calls.set(calls.get() + 1);
                Ok(())
            }
        ),
        Err(Error::Denied)
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn failed_effect_retains_processing_and_never_retries_or_reissues() {
    let f = Fixture::new();
    let grant = f.grant();
    let calls = Cell::new(0);
    assert_eq!(
        f.store.consume_grant(
            grant.token(),
            FLOW,
            102,
            Fixture::deadline(),
            &f.native,
            |_| {
                calls.set(1);
                Err(Error::Unavailable)
            }
        ),
        Err(Error::Unconfirmed)
    );
    let reopened = Store::new(f.root.0.clone());
    assert_eq!(
        reopened.consume_grant(
            grant.token(),
            FLOW,
            103,
            Fixture::deadline(),
            &f.native,
            |_| {
                calls.set(2);
                Ok(())
            }
        ),
        Err(Error::Unconfirmed)
    );
    f.start(ALICE, "192.0.2.2", 1000);
    assert_eq!(f.mail.sent.borrow().len(), 1);
    assert_eq!(calls.get(), 1);
}

#[test]
fn ambiguous_mail_does_not_retry_and_correct_possession_still_verifies() {
    let f = Fixture::new();
    f.mail.outcome.set(RecoveryContactDelivery::Unconfirmed);
    let challenge = f.start(ALICE, "192.0.2.1", 100);
    let repeated = f.start(ALICE, "192.0.2.1", 101);
    assert_eq!(repeated.challenge_id, challenge.challenge_id);
    assert_eq!(f.mail.sent.borrow().len(), 1);
    let code = f.mail.sent.borrow()[0].1.clone();
    assert!(f.proof(ALICE, &challenge, &code, 102).is_ok());
}

#[test]
fn refused_delivery_and_missing_registered_factor_cannot_grant() {
    let f = Fixture::new();
    f.mail.outcome.set(RecoveryContactDelivery::Refused);
    let challenge = f.start(ALICE, "192.0.2.1", 100);
    let code = f.mail.sent.borrow()[0].1.clone();
    assert_eq!(
        f.proof(ALICE, &challenge, &code, 101).unwrap_err(),
        Error::Denied
    );
    *f.native.factor.borrow_mut() = String::new();
    assert!(f
        .store
        .start_random(
            Start {
                account: ALICE,
                source: "192.0.2.1",
                flow: FLOW,
                now: 160,
                deadline: Fixture::deadline()
            },
            &f.native,
            &f.mail,
            &f.random
        )
        .is_err());
    assert_eq!(f.mail.sent.borrow().len(), 1);
}

#[test]
fn corrupt_or_linked_records_fail_closed_without_contact_or_effect() {
    let f = Fixture::new();
    let grant = f.grant();
    let key = token_key(grant.token()).unwrap();
    let locked = f.store.grants.lock(slot(&key)).unwrap();
    locked.write(b"{broken}").unwrap();
    drop(locked);
    assert_eq!(
        f.store
            .lookup_grant(grant.token(), FLOW, 102, Fixture::deadline(), &f.native)
            .unwrap_err(),
        Error::Unavailable
    );
}

#[test]
fn opaque_challenge_resolves_account_and_enforces_browser_flow_through_grant() {
    let f = Fixture::new();
    let challenge = f.start(ALICE, "192.0.2.1", 100);
    let code = f.mail.sent.borrow()[0].1.clone();
    assert_eq!(
        f.store
            .verify_challenge(
                &challenge.challenge_id,
                &"d".repeat(64),
                "192.0.2.1",
                &code,
                101,
                Fixture::deadline(),
                &f.native
            )
            .unwrap_err(),
        Error::Denied
    );
    let grant = f
        .store
        .verify_challenge(
            &challenge.challenge_id,
            FLOW,
            "192.0.2.1",
            &code,
            102,
            Fixture::deadline(),
            &f.native,
        )
        .unwrap();
    assert_eq!(grant.binding.account, ALICE);
    assert_eq!(grant.binding.existing_factor_sha256, "a".repeat(64));
    assert_eq!(
        f.store
            .lookup_grant(
                grant.token(),
                &"d".repeat(64),
                103,
                Fixture::deadline(),
                &f.native
            )
            .unwrap_err(),
        Error::Denied
    );
    assert!(f
        .store
        .lookup_grant(grant.token(), FLOW, 103, Fixture::deadline(), &f.native)
        .is_ok());
}

#[test]
fn unknown_accounts_create_only_fixed_source_buckets_without_account_or_token_files() {
    let f = Fixture::new();
    for n in 1..=40 {
        f.start(
            &format!("unknown{n}@example.test"),
            &format!("192.0.2.{n}"),
            100,
        );
    }
    assert!(!f.root.0.join("accounts").exists());
    assert!(!f.root.0.join("challenges").exists());
    assert!(!f.root.0.join("grants").exists());
    for entry in fs::read_dir(f.root.0.join("sources")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let rate: Rate = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            assert_eq!(rate.key.len(), 3);
        }
    }
}

#[test]
fn source_bucket_collisions_share_throttles_and_ipv6_spelling_cannot_reset_them() {
    let f = Fixture::new();
    let mut buckets = std::collections::BTreeMap::new();
    let mut collision = None;
    for n in 1..10000u32 {
        let ip = std::net::Ipv4Addr::from(0xc0000000 + n).to_string();
        let key = digest("osmap-access-source-v1", ip.as_bytes());
        if let Some(prior) = buckets.insert(slot(&key).to_owned(), ip.clone()) {
            collision = Some((prior, ip));
            break;
        }
    }
    let (first, second) = collision.expect("public test source collision");
    for _ in 0..30 {
        assert!(f.store.source_attempt(&first, 100).unwrap());
    }
    assert!(!f.store.source_attempt(&second, 100).unwrap());
    for _ in 0..30 {
        assert!(f.store.source_attempt("2001:db8::1", 100).unwrap());
    }
    assert!(!f
        .store
        .source_attempt("2001:0db8:0:0:0:0:0:1", 100)
        .unwrap());
    assert!(f.store.source_attempt("192.0.2.1:1234", 100).is_err());
}

#[test]
fn native_source_limit_disposition_is_equal_for_known_and_unknown_before_lookup() {
    let f = Fixture::new();
    for _ in 0..30 {
        assert!(f.store.source_attempt("192.0.2.1", 100).unwrap());
    }
    let before = f.native.lookups.get();
    let known = f.start(ALICE, "192.0.2.1", 101);
    let unknown = f.start(BOB, "192.0.2.1", 101);
    assert!(known.source_limited && unknown.source_limited);
    assert_eq!(known.expires_at, unknown.expires_at);
    assert_eq!(known.challenge_id.len(), unknown.challenge_id.len());
    assert_eq!(f.native.lookups.get(), before);
    assert!(f.mail.sent.borrow().is_empty());
}

struct FixedNonce;
impl RandomSource for FixedNonce {
    fn fill_bytes(&self, output: &mut [u8]) -> Result<(), crate::session::SessionError> {
        output.fill(1);
        if output.len() == 32 {
            output[0] = 0xab;
            output[1] = 0xc1;
        }
        Ok(())
    }
}
#[test]
fn challenge_slots_refuse_uncertainty_and_reuse_expired_settled_records() {
    let f = Fixture::new();
    let previous = ChallengeIndex {
        version: 1,
        id: format!("abc0{}", "0".repeat(60)),
        account: BOB.into(),
        flow_sha256: flow_key(FLOW).unwrap(),
        expires_at: 700,
    };
    let index = f.store.challenges.lock("abc").unwrap();
    save(&index, &previous).unwrap();
    drop(index);
    let account_lock = f.store.accounts.lock(BOB).unwrap();
    let mut account = Account {
        version: 1,
        account: BOB.into(),
        updated_at: 100,
        sends: vec![100],
        challenge: Some(Challenge {
            id: previous.id.clone(),
            flow_sha256: flow_key(FLOW).unwrap(),
            epoch: Some(3),
            contact_digest: Some("a".repeat(64)),
            code_digest: Some("b".repeat(64)),
            created_at: 100,
            expires_at: 700,
            attempts: 1,
            phase: Phase::Verifying,
            delivery: RecoveryContactDelivery::Accepted,
            grant_key: None,
        }),
    };
    save(&account_lock, &account).unwrap();
    drop(account_lock);
    let start = |now| {
        f.store
            .start_random(
                Start {
                    account: ALICE,
                    source: "192.0.2.1",
                    flow: FLOW,
                    now,
                    deadline: Fixture::deadline(),
                },
                &f.native,
                &f.mail,
                &FixedNonce,
            )
            .unwrap()
    };
    start(1000);
    assert!(f.mail.sent.borrow().is_empty());
    assert_eq!(
        serde_json::from_slice::<ChallengeIndex>(&f.store.challenges.read("abc").unwrap().unwrap())
            .unwrap()
            .id,
        previous.id
    );
    account.challenge.as_mut().unwrap().phase = Phase::Open;
    let account_lock = f.store.accounts.lock(BOB).unwrap();
    save(&account_lock, &account).unwrap();
    drop(account_lock);
    let next = start(1060);
    assert_eq!(f.mail.sent.borrow().len(), 1);
    let actual: ChallengeIndex =
        serde_json::from_slice(&f.store.challenges.read("abc").unwrap().unwrap()).unwrap();
    assert_eq!(actual.id, next.challenge_id);
    assert_eq!(actual.account, ALICE);
}

struct Both<'a>(&'a Native);
impl Authority for Both<'_> {
    fn eligible(&self, _: &str, deadline: Instant) -> Result<Option<EligibleAccount>, Error> {
        self.0.eligible(ALICE, deadline)
    }
}
struct Tokens(RefCell<std::collections::VecDeque<String>>);
impl RandomSource for Tokens {
    fn fill_bytes(&self, output: &mut [u8]) -> Result<(), crate::session::SessionError> {
        let token = self
            .0
            .borrow_mut()
            .pop_front()
            .expect("bounded public nonce fixture");
        assert_eq!(output.len(), 32);
        for (at, value) in output.iter_mut().enumerate() {
            *value = u8::from_str_radix(&token[at * 2..at * 2 + 2], 16).unwrap();
        }
        Ok(())
    }
}
#[test]
fn grant_slots_never_replace_processing_but_reclaim_expired_settled_grants() {
    for uncertain in [false, true] {
        let f = Fixture::new();
        let old = f.grant();
        let expected = if uncertain {
            Err(Error::Unconfirmed)
        } else {
            Ok(())
        };
        assert_eq!(
            f.store.consume_grant(
                old.token(),
                FLOW,
                102,
                Fixture::deadline(),
                &f.native,
                |_| if uncertain {
                    Err(Error::Unavailable)
                } else {
                    Ok(())
                }
            ),
            expected
        );
        let old_key = token_key(old.token()).unwrap();
        let old_raw = f.store.grants.read(slot(&old_key)).unwrap().unwrap();
        let collision = (1..100000u64)
            .map(|n| format!("{n:064x}"))
            .find(|token| {
                token != old.token() && slot(&token_key(token).unwrap()) == slot(&old_key)
            })
            .expect("public hash-slot fixture");
        let fallback = (100000..200000u64)
            .map(|n| format!("{n:064x}"))
            .find(|token| slot(&token_key(token).unwrap()) != slot(&old_key))
            .unwrap();
        let authority = Both(&f.native);
        let challenge = f
            .store
            .start_random(
                Start {
                    account: BOB,
                    source: "192.0.2.1",
                    flow: FLOW,
                    now: 1000,
                    deadline: Fixture::deadline(),
                },
                &authority,
                &f.mail,
                &f.random,
            )
            .unwrap();
        let code = f.mail.sent.borrow().last().unwrap().1.clone();
        let random = Tokens(RefCell::new([collision.clone(), fallback.clone()].into()));
        let new = f
            .store
            .verify_random(
                Verify {
                    account: BOB,
                    source: "192.0.2.1",
                    flow: FLOW,
                    challenge_id: &challenge.challenge_id,
                    email_code: &code,
                    now: 1001,
                    deadline: Fixture::deadline(),
                },
                &authority,
                &random,
            )
            .unwrap();
        assert_eq!(new.binding.account, BOB);
        if uncertain {
            assert_eq!(new.token(), fallback);
            assert_eq!(
                f.store.grants.read(slot(&old_key)).unwrap().unwrap(),
                old_raw
            );
        } else {
            assert_eq!(new.token(), collision);
            assert_eq!(
                f.store
                    .lookup_grant(old.token(), FLOW, 1002, Fixture::deadline(), &authority)
                    .unwrap_err(),
                Error::Denied
            );
        }
    }
}
