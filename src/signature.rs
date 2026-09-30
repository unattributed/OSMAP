//! Ordinary authored footer text. This does not sign or encrypt a message.
use crate::private_account_file::PrivateAccountFile;
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::PathBuf,
    time::{Duration, Instant},
};
pub const MAX_CHARS: usize = 2000;
pub const MAX_TEXT_BYTES: usize = 8000;
const MAX_RECORD_BYTES: usize = 32 * 1024;
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureSelection {
    #[default]
    None,
    Default,
}
impl SignatureSelection {
    pub fn parse(v: &str) -> Option<Self> {
        match v {
            "none" => Some(Self::None),
            "default" => Some(Self::Default),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Default => "default",
        }
    }
}
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SignatureRecord {
    pub revision: u64,
    pub selection: SignatureSelection,
    pub text: String,
}
impl std::fmt::Debug for SignatureRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureRecord")
            .field("revision", &self.revision)
            .field("selection", &self.selection)
            .field("text_bytes", &self.text.len())
            .finish()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    Invalid,
    Corrupt,
    Stale,
    Unavailable,
    Unconfirmed,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u8,
    account: String,
    revision: u64,
    selection: SignatureSelection,
    text: String,
}
pub enum SignatureChange<'a> {
    Definition {
        selection: SignatureSelection,
        text: &'a str,
    },
    Selection(SignatureSelection),
}
fn valid_text(t: &str) -> bool {
    t.len() <= MAX_TEXT_BYTES
        && t.chars().count() <= MAX_CHARS
        && !t.chars().any(|c| c.is_control() && c != '\n' && c != '\t')
}
fn account_valid(a: &str) -> Result<(), SignatureError> {
    crate::identity::CanonicalUsername::parse(a)
        .map(|_| ())
        .map_err(|_| SignatureError::Invalid)
}
fn decode(a: &str, bytes: Option<Vec<u8>>) -> Result<SignatureRecord, SignatureError> {
    let Some(bytes) = bytes else {
        return Ok(SignatureRecord::default());
    };
    let r: Stored = serde_json::from_slice(&bytes).map_err(|_| SignatureError::Corrupt)?;
    if r.version != 1
        || r.account != a
        || r.revision == 0
        || !valid_text(&r.text)
        || r.selection == SignatureSelection::Default && r.text.is_empty()
    {
        return Err(SignatureError::Corrupt);
    }
    Ok(SignatureRecord {
        revision: r.revision,
        selection: r.selection,
        text: r.text,
    })
}
#[derive(Debug, Clone)]
pub struct SignatureStore {
    file: PrivateAccountFile,
}
impl SignatureStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(directory.into(), "osmap-signature-v1", MAX_RECORD_BYTES),
        }
    }
    pub fn load(&self, a: &str) -> Result<SignatureRecord, SignatureError> {
        account_valid(a)?;
        decode(
            a,
            self.file.read(a).map_err(|_| SignatureError::Unavailable)?,
        )
    }
    pub fn change(
        &self,
        a: &str,
        revision: u64,
        change: SignatureChange<'_>,
    ) -> Result<SignatureRecord, SignatureError> {
        account_valid(a)?;
        let start = Instant::now();
        let lock = loop {
            match self.file.lock(a) {
                Ok(v) => break v,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        && start.elapsed() < Duration::from_millis(500) =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err(SignatureError::Unavailable),
            }
        };
        let mut r = decode(a, lock.read().map_err(|_| SignatureError::Unavailable)?)?;
        if r.revision != revision {
            return Err(SignatureError::Stale);
        }
        match change {
            SignatureChange::Selection(v) => r.selection = v,
            SignatureChange::Definition { selection, text } => {
                if !valid_text(text) {
                    return Err(SignatureError::Invalid);
                }
                r.selection = selection;
                r.text = text.into();
            }
        }
        if r.selection == SignatureSelection::Default && r.text.is_empty() {
            return Err(SignatureError::Invalid);
        }
        r.revision = r.revision.checked_add(1).ok_or(SignatureError::Corrupt)?;
        let bytes = serde_json::to_vec(&Stored {
            version: 1,
            account: a.into(),
            revision: r.revision,
            selection: r.selection,
            text: r.text.clone(),
        })
        .map_err(|_| SignatureError::Unavailable)?;
        lock.write(&bytes)
            .map_err(|_| SignatureError::Unconfirmed)?;
        Ok(r)
    }
}
#[derive(Clone, Copy)]
pub enum InitialPlacement {
    Blank,
    AboveQuote,
    BelowQuote,
}
/// Only for initial composer construction. Never call at save/send/resume/recovery.
/// Existing text is returned untouched by the caller on refusal.
pub fn initial_body(
    r: &SignatureRecord,
    body: &str,
    format: crate::compose_format::BodyFormat,
    placement: InitialPlacement,
) -> Result<Option<String>, &'static str> {
    if r.selection == SignatureSelection::None {
        return Ok(None);
    }
    let footer = format!("-- \n{}", r.text);
    let body = match placement {
        InitialPlacement::Blank if !body.is_empty() => {
            return Err("Signature not inserted: the new message already contains text.")
        }
        InitialPlacement::Blank => format!("\n\n{footer}"),
        InitialPlacement::AboveQuote => format!(
            "\n\n{footer}\n\n{}",
            body.strip_prefix("\n\n")
                .ok_or("Signature not inserted: the quoted layout could not be verified.")?
        ),
        InitialPlacement::BelowQuote => format!("{body}{footer}"),
    };
    if body.len() > crate::send::DEFAULT_BODY_MAX_LEN {
        return Err("Signature not inserted: the message is already at its text limit.");
    }
    if format == crate::compose_format::BodyFormat::Formatted {
        let expected_html: String = body
            .split('\n')
            .map(|line| {
                format!(
                    "<div>{}</div>",
                    if line.is_empty() {
                        "<br>".into()
                    } else {
                        crate::html::EscapedHtml::new(line).to_string()
                    }
                )
            })
            .collect();
        if !crate::compose_format::render(&body)
            .is_ok_and(|v| v.plain == body && v.html == expected_html)
        {
            return Err("Signature not inserted for Formatted text: its notation would not remain literal. Choose Plain text and enter the signature manually, or use Plain as your default for a new message.");
        }
    }
    Ok(Some(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose_format::BodyFormat;
    #[test]
    fn signature_store_bounds_cas_owner_and_corrupt_refusal() {
        let root = std::env::temp_dir().join(format!(
            "signature-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let s = SignatureStore::new(&root);
        assert_eq!(s.load("alice").unwrap(), SignatureRecord::default());
        let text = "🦊".repeat(2000);
        let r = s
            .change(
                "alice",
                0,
                SignatureChange::Definition {
                    selection: SignatureSelection::Default,
                    text: &text,
                },
            )
            .unwrap();
        assert_eq!(SignatureStore::new(&root).load("alice").unwrap(), r);
        assert!(s.load("bob").unwrap().text.is_empty());
        let bytes = s.file.read("alice").unwrap().unwrap();
        for bad in [
            text.clone() + "x",
            "a".repeat(2001),
            "bad\0control".into(),
            "bare\rcarriage".into(),
        ] {
            assert_eq!(
                s.change(
                    "alice",
                    1,
                    SignatureChange::Definition {
                        selection: SignatureSelection::Default,
                        text: &bad
                    }
                ),
                Err(SignatureError::Invalid)
            );
            assert_eq!(s.file.read("alice").unwrap().unwrap(), bytes)
        }
        assert_eq!(
            s.change(
                "alice",
                0,
                SignatureChange::Selection(SignatureSelection::None)
            ),
            Err(SignatureError::Stale)
        );
        let r = s
            .change(
                "alice",
                1,
                SignatureChange::Selection(SignatureSelection::None),
            )
            .unwrap();
        assert_eq!(r.text, text);
        assert_eq!(r.revision, 2);
        s.file.lock("bob").unwrap().write(&bytes).unwrap();
        assert_eq!(s.load("bob"), Err(SignatureError::Corrupt));
        for bad in [
            b"{".to_vec(),
            String::from_utf8(bytes.clone())
                .unwrap()
                .replace("\"version\":1", "\"version\":2")
                .into_bytes(),
        ] {
            s.file.lock("alice").unwrap().write(&bad).unwrap();
            assert_eq!(s.load("alice"), Err(SignatureError::Corrupt));
            assert!(s
                .change(
                    "alice",
                    2,
                    SignatureChange::Selection(SignatureSelection::None)
                )
                .is_err());
            assert_eq!(s.file.read("alice").unwrap().unwrap(), bad)
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn signature_literal_insertion_proves_formatted_output_and_preserves_quote_placement() {
        let mut r = SignatureRecord {
            revision: 1,
            selection: SignatureSelection::Default,
            text: "<script>literal</script> & 🦊".into(),
        };
        let blank = initial_body(&r, "", BodyFormat::Formatted, InitialPlacement::Blank)
            .unwrap()
            .unwrap();
        assert_eq!(blank, "\n\n-- \n<script>literal</script> & 🦊");
        assert!(!crate::compose_format::render(&blank)
            .unwrap()
            .html
            .contains("<script>"));
        assert_eq!(
            initial_body(
                &r,
                "\n\n> quote",
                BodyFormat::Plain,
                InitialPlacement::AboveQuote
            )
            .unwrap()
            .unwrap(),
            format!("\n\n-- \n{}\n\n> quote", r.text)
        );
        assert_eq!(
            initial_body(
                &r,
                "> quote\n\n",
                BodyFormat::Plain,
                InitialPlacement::BelowQuote
            )
            .unwrap()
            .unwrap(),
            format!("> quote\n\n-- \n{}", r.text)
        );
        for text in [
            "**bold**",
            "__underline__",
            "- item",
            "[x](https://example.test)",
        ] {
            r.text = text.into();
            assert!(initial_body(&r, "", BodyFormat::Formatted, InitialPlacement::Blank).is_err());
            assert!(
                initial_body(&r, "", BodyFormat::Plain, InitialPlacement::Blank)
                    .unwrap()
                    .unwrap()
                    .ends_with(text)
            );
        }
        r.selection = SignatureSelection::None;
        assert_eq!(
            initial_body(&r, "existing", BodyFormat::Plain, InitialPlacement::Blank),
            Ok(None)
        );
    }
}
