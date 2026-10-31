// Synthetic metadata follows the same parser and account projection as the runtime.
pub(super) fn outcome(mode: &str, account: &str) -> BrowserPublicInventoryOutcome {
    let owner = if matches!(mode, "KeyInventoryForeign" | "KeyInventoryPracticalForeign") {
        "bob@example.com"
    } else {
        account
    };
    let inventory = if matches!(
        mode,
        "KeyInventoryUnavailable" | "KeyInventoryPracticalUnavailable"
    ) || !mode.starts_with("KeyInventory")
    {
        None
    } else {
        let material = |fingerprint: &str, expires: u64, sign: bool, encrypt: bool| {
            serde_json::json!({
                "fingerprint": fingerprint, "algorithm": 1, "bits": 3072,
                "created": 1704067200u64, "expires": expires, "revoked": false,
                "expired": false, "disabled": false, "invalid": false,
                "can_sign": sign, "can_encrypt": encrypt, "can_certify": sign,
                "can_authenticate": false
            })
        };
        let mut keys = if mode == "KeyInventoryEmpty" {
            vec![]
        } else {
            vec![serde_json::json!({
                "primary": material("0123456789ABCDEF0123456789ABCDEF01234567", 0, true, false),
                "subkeys": [material("89ABCDEF0123456789ABCDEF0123456789ABCDEF", 1800000000, false, true)]
            })]
        };
        if mode.starts_with("KeyInventoryPractical") && mode != "KeyInventoryPracticalMissing" {
            keys.push(serde_json::json!({
                "primary": material("FEDCBA9876543210FEDCBA9876543210FEDCBA98",0,true,false),
                "subkeys": [material("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",1800000000,false,true)]
            }));
        }
        Some(
            crate::openpgp_inventory::Inventory::parse(
                &serde_json::to_vec(&serde_json::json!({
                    "version": 1, "ok": true, "protocol": "openpgp", "gpgme_version": "2.0.1",
                    "engine_version": "2.5.18", "keys": keys
                }))
                .unwrap(),
            )
            .unwrap(),
        )
    };
    BrowserPublicInventoryOutcome {
        canonical_username: owner.into(),
        inventory,
        audit_events: vec![],
    }
}
