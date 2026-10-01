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
        let raw: Raw = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        match &raw {
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
                for key in &v.keys {
                    if key.subkeys.len() > 8 {
                        return Err(Error::Limit);
                    }
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
