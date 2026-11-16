//! Authenticates the local nginx hop before trusting forwarded client metadata.
//! The token is loaded before confinement and never enters printable config.
use std::path::Path;
use std::sync::OnceLock;

use crate::config::RuntimeEnvironment;
use crate::http::HttpRequest;

const HEADER: &str = "x-osmap-proxy-token";
static AUTH: OnceLock<ProxyAuth> = OnceLock::new();

enum ProxyAuth {
    Disabled,
    Required(ProxyToken),
}

struct ProxyToken([u8; 64]);

impl std::fmt::Debug for ProxyToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProxyToken([redacted])")
    }
}

impl ProxyToken {
    fn load(path: &Path) -> Result<Self, &'static str> {
        if !path.is_absolute() {
            return Err("http proxy token path must be absolute");
        }
        let bytes = crate::private_account_file::read_record(path, 65)
            .map_err(|_| "http proxy token file unavailable or unsafe")?
            .ok_or("http proxy token file unavailable or unsafe")?;
        let bytes = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
        if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
            return Err("http proxy token must contain 64 hexadecimal bytes");
        }
        let mut token = [0; 64];
        token.copy_from_slice(bytes);
        Ok(Self(token))
    }
}

impl ProxyAuth {
    fn authenticate(&self, request: &mut HttpRequest) -> bool {
        // Remove the credential even when disabled or refused. Routes and their
        // diagnostics never receive the proxy's secret-bearing header.
        let supplied = request.headers.remove(HEADER);
        match self {
            Self::Disabled => true,
            Self::Required(token) => supplied.is_some_and(|value| {
                crate::http_support::constant_time_eq(&token.0, value.as_bytes())
            }),
        }
    }
}

pub(super) fn initialize(environment: RuntimeEnvironment) -> Result<(), String> {
    let auth = match std::env::var_os("OSMAP_PROXY_TOKEN_FILE") {
        Some(path) => {
            ProxyAuth::Required(ProxyToken::load(Path::new(&path)).map_err(str::to_owned)?)
        }
        None if environment == RuntimeEnvironment::Production => {
            return Err("production http runtime requires OSMAP_PROXY_TOKEN_FILE".into());
        }
        None => ProxyAuth::Disabled,
    };
    AUTH.set(auth)
        .map_err(|_| "http proxy authentication already initialized".to_string())
}

pub(super) fn authenticate(request: &mut HttpRequest) -> bool {
    match AUTH.get() {
        Some(auth) => auth.authenticate(request),
        None => {
            request.headers.remove(HEADER);
            // Unit tests invoke the connection handler without server startup.
            // A real runtime must complete initialization before serving.
            cfg!(test)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    const TOKEN: &[u8; 64] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn request(value: Option<&str>) -> HttpRequest {
        HttpRequest {
            notification_context: Default::default(),
            method: crate::http::HttpMethod::Get,
            path: "/healthz".into(),
            query_params: BTreeMap::new(),
            headers: value
                .map(|v| (HEADER.to_string(), v.to_string()))
                .into_iter()
                .collect(),
            body: Vec::new(),
        }
    }

    #[test]
    fn required_proxy_proof_accepts_only_exact_token_and_is_removed() {
        let auth = ProxyAuth::Required(ProxyToken(*TOKEN));
        for (value, expected) in [
            (Some(std::str::from_utf8(TOKEN).unwrap()), true),
            (Some("wrong"), false),
            (None, false),
        ] {
            let mut request = request(value);
            assert_eq!(auth.authenticate(&mut request), expected);
            assert!(!request.headers.contains_key(HEADER));
        }
        assert_eq!(
            format!("{:?}", ProxyToken(*TOKEN)),
            "ProxyToken([redacted])"
        );
    }

    #[test]
    #[cfg(unix)]
    fn token_file_is_bounded_private_regular_and_not_a_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};
        let root = std::env::temp_dir().join(format!(
            "osmap-proxy-auth-{}-{}",
            crate::draft::generate_draft_id().expect("random fixture id"),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("token");
        fs::write(&path, TOKEN).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ProxyToken::load(&path).is_ok());
        let link = root.join("link");
        symlink(&path, &link).unwrap();
        assert!(ProxyToken::load(&link).is_err());
        fs::write(&path, [b'a'; 66]).unwrap();
        assert!(ProxyToken::load(&path).is_err());
        fs::write(&path, TOKEN).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ProxyToken::load(&path).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
