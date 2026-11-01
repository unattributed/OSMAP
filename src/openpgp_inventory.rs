//! Bounded public metadata only. Presence and usage flags confer no trust or private-key authority.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
pub const MAX_METADATA: usize = 65536;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    Invalid,
    Limit,
    Authentication,
    Expired,
    Replay,
    Capacity,
    Clock,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyMaterial {
    pub fingerprint: String,
    pub algorithm: u32,
    pub bits: u32,
    /// Authenticated engine-reported curve; absence does not qualify ECC use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    pub created: u64,
    pub expires: u64,
    pub revoked: bool,
    pub expired: bool,
    pub disabled: bool,
    pub invalid: bool,
    pub can_encrypt: bool,
    pub can_sign: bool,
    pub can_certify: bool,
    pub can_authenticate: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKey {
    pub primary: KeyMaterial,
    pub subkeys: Vec<KeyMaterial>,
    /// Engine-parsed public UID addr-specs, not display UIDs or verified trust.
    /// Older workers omit this field. Unsupported printable mailbox syntax is
    /// filtered on parse; control characters and exceeded bounds reject it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub email_addresses: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Available {
    version: u8,
    ok: bool,
    protocol: String,
    gpgme_version: String,
    engine_version: String,
    keys: Vec<PublicKey>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Unavailable {
    version: u8,
    ok: bool,
    error: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum Raw {
    Available(Available),
    Unavailable(Unavailable),
}
#[derive(Debug, Clone)]
pub struct Inventory(Raw);
impl Inventory {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_METADATA {
            return Err(Error::Limit);
        }
        let mut raw: Raw = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        match &mut raw {
            Raw::Unavailable(v)
                if v.version == 1 && !v.ok && v.error == "inventory_unavailable" => {}
            Raw::Available(v) if v.version == 1 && v.ok && v.protocol == "openpgp" => {
                for s in [&v.gpgme_version, &v.engine_version] {
                    if s.is_empty()
                        || s.len() > 64
                        || !s
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b".-+~".contains(&b))
                    {
                        return Err(Error::Invalid);
                    }
                }
                if v.keys.len() > 32 {
                    return Err(Error::Limit);
                }
                let mut seen = BTreeSet::new();
                for key in &mut v.keys {
                    if key.subkeys.len() > 8 || key.email_addresses.len() > 16 {
                        return Err(Error::Limit);
                    }
                    for address in &key.email_addresses {
                        if address.len() > 254 {
                            return Err(Error::Limit);
                        }
                        if address.chars().any(char::is_control) {
                            return Err(Error::Invalid);
                        }
                    }
                    let mut email_seen = BTreeSet::new();
                    key.email_addresses.retain(|address| {
                        crate::identity::MailboxIdentity::parse(address.clone()).is_ok()
                            && crate::mail_address::validate_address(
                                crate::send::ComposePolicy::default(),
                                address,
                            )
                            .is_ok()
                            && email_seen.insert(crate::mail_address::comparison_key(address))
                    });
                    for k in std::iter::once(&key.primary).chain(&key.subkeys) {
                        if !matches!(k.fingerprint.len(), 40 | 64)
                            || !k
                                .fingerprint
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
                            || !seen.insert(&k.fingerprint)
                            || !matches!(
                                k.algorithm,
                                1 | 2 | 3 | 8 | 16 | 17 | 18 | 20 | 301 | 302 | 303
                            )
                            || k.bits == 0
                            || k.curve.as_ref().is_some_and(|curve| {
                                curve.is_empty()
                                    || curve.len() > 32
                                    || !curve
                                        .bytes()
                                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                            })
                            || k.bits > 65536
                            || k.created > 253402300799
                            || k.expires > 253402300799
                            || (k.created != 0 && k.expires != 0 && k.expires < k.created)
                        {
                            return Err(Error::Invalid);
                        }
                    }
                }
            }
            _ => return Err(Error::Invalid),
        }
        Ok(Self(raw))
    }
    pub fn keys(&self) -> Option<&[PublicKey]> {
        match &self.0 {
            Raw::Available(v) => Some(&v.keys),
            _ => None,
        }
    }
    pub fn versions(&self) -> Option<(&str, &str)> {
        match &self.0 {
            Raw::Available(v) => Some((&v.gpgme_version, &v.engine_version)),
            _ => None,
        }
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&self.0).map_err(|_| Error::Invalid)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn public_metadata(addresses: Option<serde_json::Value>) -> Vec<u8> {
        let mut key = serde_json::json!({"primary": {
            "fingerprint":"A".repeat(40),"algorithm":1,"bits":3072,
            "created":1,"expires":0,"revoked":false,"expired":false,
            "disabled":false,"invalid":false,"can_encrypt":true,
            "can_sign":true,"can_certify":false,"can_authenticate":false,
        }, "subkeys":[]});
        if let Some(addresses) = addresses {
            key["email_addresses"] = addresses;
        }
        serde_json::to_vec(&serde_json::json!({
            "version":1,"ok":true,"protocol":"openpgp",
            "gpgme_version":"2.0.1","engine_version":"2.4.8","keys":[key],
        }))
        .unwrap()
    }
    #[test]
    fn public_uid_emails_are_optional_bounded_addr_specs_not_display_identity() {
        let old = Inventory::parse(&public_metadata(None)).unwrap();
        assert!(old.keys().unwrap()[0].email_addresses.is_empty());
        assert!(!String::from_utf8(old.to_bytes().unwrap())
            .unwrap()
            .contains("email_addresses"));
        let inventory = Inventory::parse(&public_metadata(Some(serde_json::json!([
            "Alice@EXAMPLE.test",
            "Alice@example.TEST",
            "alice@example.test",
            "Display Name <mallory@example.test>",
            "unsupported mailbox",
            "álîce@example.test",
            "bad@example",
            "Alice+tag@example.test",
            "slash/name@example.test",
        ]))))
        .unwrap();
        assert_eq!(
            inventory.keys().unwrap()[0].email_addresses,
            [
                "Alice@EXAMPLE.test",
                "alice@example.test",
                "Alice+tag@example.test",
                "slash/name@example.test",
            ]
        );
        let roundtrip = Inventory::parse(&inventory.to_bytes().unwrap()).unwrap();
        assert_eq!(
            roundtrip.keys().unwrap()[0].email_addresses,
            inventory.keys().unwrap()[0].email_addresses
        );
    }
    #[test]
    fn public_uid_email_limits_and_hostile_strings_refuse_without_trusting_uids() {
        for value in [
            "a\nb@example.test",
            "a\rb@example.test",
            "a\tb@example.test",
            "a\0b@example.test",
            "a\u{007f}b@example.test",
        ] {
            assert_eq!(
                Inventory::parse(&public_metadata(Some(serde_json::json!([value])))).unwrap_err(),
                Error::Invalid
            );
        }
        assert_eq!(
            Inventory::parse(&public_metadata(Some(serde_json::json!(["x".repeat(255)]))))
                .unwrap_err(),
            Error::Limit
        );
        assert_eq!(
            Inventory::parse(&public_metadata(Some(serde_json::json!([
                "x".repeat(250) + "@a.b"
            ]))))
            .unwrap()
            .keys()
            .unwrap()[0]
                .email_addresses
                .len(),
            0
        );
        let unsupported_labels = Inventory::parse(&public_metadata(Some(serde_json::json!([
            "a..b@example.test",
            ".ab@example.test",
            "ab.@example.test",
            "ab@-example.test",
            "ab@example-.test",
            "ab@example..test",
        ]))))
        .unwrap();
        assert!(unsupported_labels.keys().unwrap()[0]
            .email_addresses
            .is_empty());
        let sixteen = (0..16)
            .map(|index| format!("uid{index}@example.test"))
            .collect::<Vec<_>>();
        assert_eq!(
            Inventory::parse(&public_metadata(Some(serde_json::json!(sixteen))))
                .unwrap()
                .keys()
                .unwrap()[0]
                .email_addresses
                .len(),
            16
        );
        assert_eq!(
            Inventory::parse(&public_metadata(Some(serde_json::json!(
                vec!["a@example.test"; 17]
            ))))
            .unwrap_err(),
            Error::Limit
        );
        for invalid in [
            serde_json::json!("a@example.test"),
            serde_json::json!([null]),
            serde_json::json!([{}]),
        ] {
            assert!(Inventory::parse(&public_metadata(Some(invalid))).is_err());
        }
        // A printable unsupported UID must not make otherwise useful public
        // key metadata unavailable, nor become a display-name-derived address.
        let unsupported = Inventory::parse(&public_metadata(Some(serde_json::json!([
            "Nobody <not-an-address>"
        ]))))
        .unwrap();
        assert_eq!(unsupported.keys().unwrap().len(), 1);
        assert!(unsupported.keys().unwrap()[0].email_addresses.is_empty());
    }
    #[test]
    fn strict_inventory_boundaries() {
        let empty=br#"{"version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.5.18","keys":[]}"#;
        assert_eq!(Inventory::parse(empty).unwrap().keys().unwrap().len(), 0);
        assert!(
            Inventory::parse(br#"{"version":1,"ok":false,"error":"inventory_unavailable"}"#)
                .unwrap()
                .keys()
                .is_none()
        );
        for bad in [
            br#"{"version":1,"version":1,"ok":false,"error":"inventory_unavailable"}"#.as_slice(),
            br#"{"version":1,"ok":false,"error":"inventory_unavailable","keys":[]}"#,
            &vec![b' '; MAX_METADATA + 1],
        ] {
            assert!(Inventory::parse(bad).is_err())
        }
        let mut v: serde_json::Value = serde_json::from_slice(empty).unwrap();
        let k = serde_json::json!({"fingerprint":"A".repeat(40),"algorithm":1,"bits":3072,"created":1,"expires":0,"revoked":true,"expired":false,"disabled":false,"invalid":false,"can_encrypt":true,"can_sign":true,"can_certify":false,"can_authenticate":false});
        v["keys"] = serde_json::json!([{"primary":k,"subkeys":[]}]);
        assert!(Inventory::parse(&serde_json::to_vec(&v).unwrap()).is_ok());
        let mut modern = v.clone();
        modern["keys"][0]["primary"]["fingerprint"] = serde_json::json!("B".repeat(64));
        modern["keys"][0]["primary"]["algorithm"] = serde_json::json!(303);
        assert!(Inventory::parse(&serde_json::to_vec(&modern).unwrap()).is_ok());
        let mut time = v.clone();
        time["keys"][0]["primary"]["created"] = serde_json::json!(3);
        time["keys"][0]["primary"]["expires"] = serde_json::json!(2);
        assert!(Inventory::parse(&serde_json::to_vec(&time).unwrap()).is_err());
        for (field, value) in [
            ("curve", serde_json::json!("bad curve")),
            ("curve", serde_json::json!("A".repeat(33))),
            ("fingerprint", serde_json::json!("a".repeat(40))),
            ("algorithm", serde_json::json!(999)),
            ("created", serde_json::json!(u64::MAX)),
        ] {
            let mut bad = v.clone();
            bad["keys"][0]["primary"][field] = value;
            assert!(Inventory::parse(&serde_json::to_vec(&bad).unwrap()).is_err())
        }
        let mut duplicate = v.clone();
        duplicate["keys"]
            .as_array_mut()
            .unwrap()
            .push(v["keys"][0].clone());
        assert!(Inventory::parse(&serde_json::to_vec(&duplicate).unwrap()).is_err());
        let mut cap = v.clone();
        cap["keys"] = serde_json::Value::Array(vec![v["keys"][0].clone(); 33]);
        assert_eq!(
            Inventory::parse(&serde_json::to_vec(&cap).unwrap()).unwrap_err(),
            Error::Limit
        );
        cap = v.clone();
        cap["keys"][0]["subkeys"] =
            serde_json::Value::Array(vec![v["keys"][0]["primary"].clone(); 9]);
        assert_eq!(
            Inventory::parse(&serde_json::to_vec(&cap).unwrap()).unwrap_err(),
            Error::Limit
        );
    }
}
