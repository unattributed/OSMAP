//! Account-bound, read-only folder facts from a finite local IMAP exchange.
//!
//! Fixed commands: `N1 NAMESPACE`, `L1 LIST "" "*" RETURN (CHILDREN SPECIAL-USE)`,
//! `Z1 LOGOUT`. The caller must already have authenticated the account/helper
//! grant. A PREAUTH greeting is protocol state, never proof of account ownership.
use crate::identity::CanonicalUsername;
use std::collections::BTreeSet;
use std::fmt;

pub const MAX_TRANSCRIPT_BYTES: usize = 512 * 1024;
pub const MAX_FOLDERS: usize = 1024;
pub const MAX_NAMESPACES: usize = 32;
pub const MAX_NAME_BYTES: usize = 255;
const MAX_WIRE_STRING: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderMetadataError {
    InvalidAccount,
    WrongAccount,
    InvalidTranscript,
    Limit,
    InvalidName,
    NotFound,
}
impl fmt::Display for FolderMetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidAccount => "invalid folder account",
            Self::WrongAccount => "folder account mismatch",
            Self::InvalidTranscript => "invalid folder metadata transcript",
            Self::Limit => "folder metadata limit exceeded",
            Self::InvalidName => "invalid folder name",
            Self::NotFound => "folder metadata unavailable",
        })
    }
}
impl std::error::Error for FolderMetadataError {}
type Result<T> = std::result::Result<T, FolderMetadataError>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceKind {
    Private,
    Shared,
    Public,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderNamespace {
    kind: NamespaceKind,
    prefix: String,
    delimiter: Option<char>,
}
impl FolderNamespace {
    pub fn kind(&self) -> NamespaceKind {
        self.kind
    }
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
    pub fn delimiter(&self) -> Option<char> {
        self.delimiter
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderEntry {
    name: String,
    delimiter: Option<char>,
    flags: Vec<String>,
}
impl FolderEntry {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn delimiter(&self) -> Option<char> {
        self.delimiter
    }
    pub fn flags(&self) -> &[String] {
        &self.flags
    }
    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags.iter().any(|v| v.eq_ignore_ascii_case(flag))
    }
    /// Recognized special-use facts; these grant no mutation authority.
    pub fn special_use(&self) -> Vec<&str> {
        self.flags
            .iter()
            .filter(|flag| {
                [
                    "\\All",
                    "\\Archive",
                    "\\Drafts",
                    "\\Flagged",
                    "\\Junk",
                    "\\Sent",
                    "\\Trash",
                    "\\Important",
                ]
                .iter()
                .any(|known| flag.eq_ignore_ascii_case(known))
            })
            .map(String::as_str)
            .collect()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderSnapshot {
    account: String,
    namespaces: Vec<FolderNamespace>,
    folders: Vec<FolderEntry>,
    transcript: Vec<u8>,
}
impl FolderSnapshot {
    pub fn account(&self) -> &str {
        &self.account
    }
    pub fn namespaces(&self) -> &[FolderNamespace] {
        &self.namespaces
    }
    pub fn folders(&self) -> &[FolderEntry] {
        &self.folders
    }
    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }
    pub fn validate_for(&self, expected: &str) -> Result<()> {
        CanonicalUsername::parse(expected).map_err(|_| FolderMetadataError::InvalidAccount)?;
        if self.account == expected {
            Ok(())
        } else {
            Err(FolderMetadataError::WrongAccount)
        }
    }
    pub fn folder(&self, expected: &str, name: &str) -> Result<&FolderEntry> {
        self.validate_for(expected)?;
        validate_name(name, false)?;
        self.folders
            .iter()
            .find(|f| {
                f.name == name
                    || (f.name.eq_ignore_ascii_case("INBOX") && name.eq_ignore_ascii_case("INBOX"))
            })
            .ok_or(FolderMetadataError::NotFound)
    }
    pub fn parse(account: &str, transcript: &[u8]) -> Result<Self> {
        let account = CanonicalUsername::parse(account)
            .map_err(|_| FolderMetadataError::InvalidAccount)?
            .into_string();
        if transcript.len() > MAX_TRANSCRIPT_BYTES {
            return Err(FolderMetadataError::Limit);
        }
        let mut p = Parser {
            bytes: transcript,
            pos: 0,
        };
        p.status(b"* PREAUTH")?;
        p.take(b"* NAMESPACE ")?;
        let mut namespaces = Vec::new();
        for (index, kind) in [
            NamespaceKind::Private,
            NamespaceKind::Shared,
            NamespaceKind::Public,
        ]
        .into_iter()
        .enumerate()
        {
            if index > 0 {
                p.take(b" ")?;
            }
            if p.starts(b"NIL") {
                p.take(b"NIL")?;
                continue;
            }
            p.take(b"(")?;
            loop {
                if namespaces.len() == MAX_NAMESPACES {
                    return Err(FolderMetadataError::Limit);
                }
                p.take(b"(")?;
                let prefix = decode_name(&p.string(false)?)?;
                validate_name(&prefix, true)?;
                p.take(b" ")?;
                let delimiter = p.delimiter()?;
                p.take(b")")?;
                if !prefix.is_empty() && delimiter.is_some_and(|d| !prefix.ends_with(d)) {
                    return invalid();
                }
                if namespaces
                    .iter()
                    .any(|n: &FolderNamespace| n.prefix == prefix)
                {
                    return invalid();
                }
                namespaces.push(FolderNamespace {
                    kind,
                    prefix,
                    delimiter,
                });
                if p.starts(b")") {
                    p.take(b")")?;
                    break;
                }
                // Namespace descriptions are adjacent, not separated by spaces.
                if !p.starts(b"(") {
                    return invalid();
                }
            }
        }
        p.take(b"\r\n")?;
        p.status(b"N1 OK")?;
        let mut folders = Vec::new();
        let mut names = BTreeSet::new();
        while p.starts(b"* LIST ") {
            if folders.len() == MAX_FOLDERS {
                return Err(FolderMetadataError::Limit);
            }
            p.take(b"* LIST (")?;
            let start = p.pos;
            let mut flags = Vec::new();
            while !p.starts(b")") {
                if !flags.is_empty() {
                    p.take(b" ")?;
                }
                let flag = p.atom()?;
                if flag.is_empty()
                    || flag == b"\\"
                    || !flag
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || b"\\-_.".contains(b))
                {
                    return invalid();
                }
                let flag =
                    String::from_utf8(flag).map_err(|_| FolderMetadataError::InvalidTranscript)?;
                if flags.iter().any(|v: &String| v.eq_ignore_ascii_case(&flag)) {
                    return invalid();
                }
                flags.push(flag);
                if p.pos - start > 256 {
                    return Err(FolderMetadataError::Limit);
                }
            }
            p.take(b") ")?;
            let delimiter = p.delimiter()?;
            p.take(b" ")?;
            let name = decode_name(&p.string(true)?)?;
            validate_name(&name, false)?;
            p.take(b"\r\n")?;
            let key = if name.eq_ignore_ascii_case("INBOX") {
                "INBOX".into()
            } else {
                name.clone()
            };
            if !names.insert(key) {
                return invalid();
            }
            let namespace = namespaces
                .iter()
                .filter(|n| {
                    name.starts_with(&n.prefix)
                        || (name.eq_ignore_ascii_case("INBOX")
                            && n.kind == NamespaceKind::Private
                            && n.delimiter.is_some_and(|d| {
                                n.prefix.eq_ignore_ascii_case(&format!("INBOX{d}"))
                            }))
                })
                .max_by_key(|n| n.prefix.len())
                .ok_or(FolderMetadataError::InvalidTranscript)?;
            if namespace.delimiter != delimiter {
                return invalid();
            }
            let entry = FolderEntry {
                name,
                delimiter,
                flags,
            };
            if entry.has_flag("\\HasChildren") && entry.has_flag("\\HasNoChildren") {
                return invalid();
            }
            folders.push(entry);
        }
        p.status(b"L1 OK")?;
        p.status(b"* BYE")?;
        p.status(b"Z1 OK")?;
        if p.pos != transcript.len() {
            return invalid();
        }
        Ok(Self {
            account,
            namespaces,
            folders,
            transcript: transcript.to_vec(),
        })
    }
}
fn invalid<T>() -> Result<T> {
    Err(FolderMetadataError::InvalidTranscript)
}
fn validate_name(value: &str, empty: bool) -> Result<()> {
    if (!empty && value.is_empty())
        || value.len() > MAX_NAME_BYTES
        || value.chars().any(|c| c.is_control() || c == '\u{7f}')
    {
        return Err(FolderMetadataError::InvalidName);
    }
    Ok(())
}
struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl Parser<'_> {
    fn starts(&self, text: &[u8]) -> bool {
        self.bytes[self.pos..].starts_with(text)
    }
    fn take(&mut self, text: &[u8]) -> Result<()> {
        if !self.starts(text) {
            return invalid();
        }
        self.pos += text.len();
        Ok(())
    }
    fn status(&mut self, prefix: &[u8]) -> Result<()> {
        self.take(prefix)?;
        self.take(b" ")?;
        let start = self.pos;
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| (0x20..=0x7e).contains(b))
        {
            self.pos += 1;
            if self.pos - start > 4096 {
                return Err(FolderMetadataError::Limit);
            }
        }
        if self.pos == start {
            return invalid();
        }
        self.take(b"\r\n")
    }
    fn atom(&mut self) -> Result<Vec<u8>> {
        let start = self.pos;
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| (0x21..=0x7e).contains(b) && !b"(){ %*\"\r\n".contains(b))
        {
            self.pos += 1;
            if self.pos - start > MAX_WIRE_STRING {
                return Err(FolderMetadataError::Limit);
            }
        }
        if start == self.pos {
            return invalid();
        }
        Ok(self.bytes[start..self.pos].to_vec())
    }
    fn string(&mut self, atom: bool) -> Result<Vec<u8>> {
        if self.starts(b"\"") {
            self.pos += 1;
            let mut out = Vec::new();
            loop {
                let b = *self
                    .bytes
                    .get(self.pos)
                    .ok_or(FolderMetadataError::InvalidTranscript)?;
                self.pos += 1;
                match b {
                    b'"' => return Ok(out),
                    b'\\' => {
                        let escaped = *self
                            .bytes
                            .get(self.pos)
                            .ok_or(FolderMetadataError::InvalidTranscript)?;
                        self.pos += 1;
                        if !matches!(escaped, b'"' | b'\\') {
                            return invalid();
                        }
                        out.push(escaped);
                    }
                    0x20..=0x7e => out.push(b),
                    _ => return invalid(),
                }
                if out.len() > MAX_WIRE_STRING {
                    return Err(FolderMetadataError::Limit);
                }
            }
        }
        if self.starts(b"{") {
            self.pos += 1;
            let start = self.pos;
            let mut size = 0usize;
            while let Some(b'0'..=b'9') = self.bytes.get(self.pos) {
                if self.pos - start >= 4 {
                    return Err(FolderMetadataError::Limit);
                }
                size = size * 10 + usize::from(self.bytes[self.pos] - b'0');
                self.pos += 1;
            }
            if self.pos == start || (self.pos - start > 1 && self.bytes[start] == b'0') {
                return invalid();
            }
            if size > MAX_WIRE_STRING {
                return Err(FolderMetadataError::Limit);
            }
            self.take(b"}\r\n")?;
            let end = self
                .pos
                .checked_add(size)
                .ok_or(FolderMetadataError::Limit)?;
            let bytes = self
                .bytes
                .get(self.pos..end)
                .ok_or(FolderMetadataError::InvalidTranscript)?
                .to_vec();
            self.pos = end;
            return Ok(bytes);
        }
        if atom {
            let value = self.atom()?;
            Ok(value)
        } else {
            invalid()
        }
    }
    fn delimiter(&mut self) -> Result<Option<char>> {
        if self.starts(b"NIL") {
            self.take(b"NIL")?;
            return Ok(None);
        }
        let value = decode_name(&self.string(false)?)?;
        let mut chars = value.chars();
        let first = chars.next().ok_or(FolderMetadataError::InvalidTranscript)?;
        if chars.next().is_some() || first.is_control() {
            return invalid();
        }
        Ok(Some(first))
    }
}

// RFC 3501 modified UTF-7: direct printable ASCII, '&-' for ampersand;
// otherwise unpadded modified Base64 of UTF-16BE. No replacement decoding.
fn decode_name(wire: &[u8]) -> Result<String> {
    let mut out = String::new();
    let mut pos = 0;
    while pos < wire.len() {
        let b = wire[pos];
        pos += 1;
        if !(0x20..=0x7e).contains(&b) {
            return invalid();
        }
        if b != b'&' {
            out.push(char::from(b));
            continue;
        }
        let start = pos;
        while wire.get(pos).is_some_and(|b| *b != b'-') {
            pos += 1;
        }
        if pos == wire.len() {
            return invalid();
        }
        if pos == start {
            out.push('&');
            pos += 1;
            continue;
        }
        let mut data = Vec::new();
        let mut bits = 0u32;
        let mut count = 0u8;
        for b in &wire[start..pos] {
            let digit = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b',' => 63,
                _ => return invalid(),
            };
            bits = (bits << 6) | u32::from(digit);
            count += 6;
            if count >= 8 {
                count -= 8;
                data.push((bits >> count) as u8);
                bits &= (1 << count) - 1;
            }
        }
        if bits != 0 || count >= 6 || data.is_empty() || data.len() % 2 != 0 {
            return invalid();
        }
        let units = data
            .chunks_exact(2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]));
        for ch in char::decode_utf16(units) {
            let ch = ch.map_err(|_| FolderMetadataError::InvalidTranscript)?;
            if ch.is_ascii() || ch.is_control() {
                return invalid();
            }
            out.push(ch);
        }
        pos += 1;
        // Adjacent encoded runs are a noncanonical alternative spelling.
        if wire.get(pos) == Some(&b'&') && wire.get(pos + 1) != Some(&b'-') {
            return invalid();
        }
    }
    validate_name(&out, true)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn transcript(ns: &str, rows: &str) -> Vec<u8> {
        format!("* PREAUTH [CAPABILITY IMAP4rev1 NAMESPACE LIST-EXTENDED SPECIAL-USE] fixture\r\n* NAMESPACE {ns}\r\nN1 OK Namespace completed\r\n{rows}L1 OK List completed\r\n* BYE Logging out\r\nZ1 OK Logout completed\r\n").into_bytes()
    }
    fn parse(ns: &str, rows: &str) -> Result<FolderSnapshot> {
        FolderSnapshot::parse("fixture", &transcript(ns, rows))
    }
    #[test]
    fn native_dot_slash_flags_and_account_binding() {
        for d in ['.', '/'] {
            let ns = format!("((\"\" \"{d}\")) NIL NIL");
            let rows = format!("* LIST (\\HasNoChildren \\Sent) \"{d}\" Sent\r\n* LIST (\\NonExistent \\HasChildren) \"{d}\" Parent\r\n* LIST (\\HasNoChildren) \"{d}\" Parent{d}Child\r\n* LIST () \"{d}\" INBOX\r\n");
            let p = parse(&ns, &rows).unwrap();
            assert_eq!(p.namespaces()[0].delimiter(), Some(d));
            assert_eq!(p.folders().len(), 4);
            assert!(p
                .folder("fixture", "Parent")
                .unwrap()
                .has_flag("\\nonexistent"));
            assert_eq!(
                p.folder("fixture", "Sent").unwrap().special_use(),
                ["\\Sent"]
            );
            assert_eq!(p.folder("fixture", "inbox").unwrap().name(), "INBOX");
            assert_eq!(
                p.folder("other", "Sent"),
                Err(FolderMetadataError::WrongAccount)
            );
            assert_eq!(FolderSnapshot::parse("fixture", p.transcript()).unwrap(), p);
            assert_eq!(
                p.folder("fixture", "missing"),
                Err(FolderMetadataError::NotFound)
            );
        }
        assert_eq!(
            FolderSnapshot::parse("bad account", b""),
            Err(FolderMetadataError::InvalidAccount)
        );
    }
    #[test]
    fn nil_multiple_kinds_international_escaped_and_literal_names() {
        let p = parse("((\"\" NIL)) ((\"Shared/\" \"/\")) ((\"Public/\" \"/\"))", "* LIST (\\Unknown) NIL \"Flat.dot/slash\"\r\n* LIST () \"/\" \"Shared/&ZeVnLIqe-\"\r\n* LIST () \"/\" {10}\r\nPublic/A&B\r\n");
        // Literal ampersands also obey modified UTF-7; malformed alternate wire refused.
        assert!(p.is_err());
        let p = parse("((\"\" NIL)) ((\"Shared/\" \"/\")) ((\"Public/\" \"/\"))", "* LIST (\\Unknown) NIL \"Flat.dot/slash\"\r\n* LIST () \"/\" \"Shared/&ZeVnLIqe-\"\r\n* LIST () \"/\" {11}\r\nPublic/A&-B\r\n").unwrap();
        assert_eq!(p.namespaces()[1].kind(), NamespaceKind::Shared);
        assert_eq!(p.namespaces()[2].kind(), NamespaceKind::Public);
        assert_eq!(p.folders()[1].name(), "Shared/日本語");
        assert_eq!(p.folders()[2].name(), "Public/A&B");
        assert_eq!(p.folders()[0].delimiter(), None);
        assert!(p.folders()[0].special_use().is_empty());
        let q = parse(
            "((\"\" \".\")) NIL NIL",
            "* LIST () \".\" \"Quote\\\" Back\\\\\"\r\n",
        )
        .unwrap();
        assert_eq!(q.folders()[0].name(), "Quote\" Back\\");
        assert_eq!(decode_name(b"&2D3eAA-").unwrap(), "😀");
        assert!(parse("NIL NIL NIL", "").is_ok());
    }
    #[test]
    fn explicit_prefixed_inbox_unicode_delimiter_and_literal_boundaries() {
        let p = parse(
            "((\"INBOX.\" \".\")) NIL NIL",
            "* LIST () \".\" INBOX\r\n* LIST () \".\" INBOX.Child\r\n",
        )
        .unwrap();
        assert_eq!(p.folders().len(), 2);
        assert!(parse("((\"Other.\" \".\")) NIL NIL", "* LIST () \".\" INBOX\r\n").is_err());
        let p = parse("((\"\" \"&AOk-\")) NIL NIL", "* LIST () \"&AOk-\" NIL\r\n").unwrap();
        assert_eq!(p.folders()[0].name(), "NIL");
        assert_eq!(p.folders()[0].delimiter(), Some('é'));
        let bytes = transcript(
            "(({0}\r\n \".\")) NIL NIL",
            "* LIST () \".\" {3}\r\nA B\r\n",
        );
        assert_eq!(
            FolderSnapshot::parse("fixture", &bytes).unwrap().folders()[0].name(),
            "A B"
        );
        for end in 0..bytes.len() {
            assert!(FolderSnapshot::parse("fixture", &bytes[..end]).is_err());
        }
        assert!(validate_name(&"é".repeat(127), false).is_ok());
        assert_eq!(
            validate_name(&"é".repeat(128), false),
            Err(FolderMetadataError::InvalidName)
        );
    }

    #[test]
    fn finite_exchange_rejects_missing_extra_failed_and_truncated_responses() {
        let valid = transcript("((\"\" \".\")) NIL NIL", "* LIST () \".\" Inbox\r\n");
        for end in 0..valid.len() {
            assert!(
                FolderSnapshot::parse("fixture", &valid[..end]).is_err(),
                "prefix {end}"
            );
        }
        let text = String::from_utf8(valid).unwrap();
        for (from, to) in [
            ("N1 OK", "X1 OK"),
            ("N1 OK", "N1 NO"),
            ("L1 OK", "L1 BAD"),
            ("Z1 OK", "Z2 OK"),
            ("* PREAUTH", "* OK"),
            ("* BYE Logging out\r\n", ""),
            ("N1 OK", "* NAMESPACE NIL NIL NIL\r\nN1 OK"),
            ("L1 OK", "* 1 EXISTS\r\nL1 OK"),
        ] {
            assert!(
                FolderSnapshot::parse("fixture", text.replace(from, to).as_bytes()).is_err(),
                "{from} => {to}"
            );
        }
        assert!(FolderSnapshot::parse("fixture", format!("{text}extra\r\n").as_bytes()).is_err());
        assert!(FolderSnapshot::parse("fixture", text.replace("\r\n", "\n").as_bytes()).is_err());
    }
    #[test]
    fn rejects_ambiguous_facts_and_malformed_wire_strings() {
        for rows in [
            "* LIST () \"/\" INBOX\r\n",
            "* LIST () \".\" INBOX\r\n* LIST () \".\" inbox\r\n",
            "* LIST (\\Sent \\sent) \".\" Sent\r\n",
            "* LIST (\\HasChildren \\HasNoChildren) \".\" X\r\n",
            "* LIST () \".\" \"x\\z\"\r\n",
            "* LIST () \".\" {99999999999999999999}\r\nx\r\n",
            "* LIST () \".\" {01}\r\nx\r\n",
            "* LIST () \".\" \"é\"\r\n",
            "* LIST () \".\" {1}\r\n\0\r\n",
        ] {
            assert!(parse("((\"\" \".\")) NIL NIL", rows).is_err(), "{rows:?}");
        }
        for ns in [
            "((\"\" \".\")(\"\" \".\")) NIL NIL",
            "((\"\" \".\")) ((\"\" \".\")) NIL",
            "((\"Prefix\" \".\")) NIL NIL",
            "((\"\" \"..\")) NIL NIL",
            "((\"\" \".\" X)) NIL NIL",
        ] {
            assert!(parse(ns, "").is_err(), "{ns}");
        }
        for wire in [
            "&",
            "&AA-",
            "&A-",
            "&AGE-",
            "&2AA-",
            "&3AA-",
            "&ZeU=-",
            "&ZeV-",
            "&ZeU-&Zyw-",
            "&AB8-",
        ] {
            assert!(decode_name(wire.as_bytes()).is_err(), "{wire}");
        }
    }
    #[test]
    fn enforces_every_population_and_size_limit_without_truncation() {
        let ns = "((\"\" \".\")) NIL NIL";
        let rows = (0..MAX_FOLDERS)
            .map(|i| format!("* LIST () \".\" F{i}\r\n"))
            .collect::<String>();
        assert_eq!(parse(ns, &rows).unwrap().folders().len(), MAX_FOLDERS);
        assert_eq!(
            parse(ns, &format!("{rows}* LIST () \".\" extra\r\n")),
            Err(FolderMetadataError::Limit)
        );
        let names = (0..MAX_NAMESPACES)
            .map(|i| format!("(\"N{i}.\" \".\")"))
            .collect::<String>();
        assert_eq!(
            parse(&format!("({names}) NIL NIL"), "")
                .unwrap()
                .namespaces()
                .len(),
            MAX_NAMESPACES
        );
        assert_eq!(
            parse(&format!("({names}(\"extra.\" \".\")) NIL NIL"), ""),
            Err(FolderMetadataError::Limit)
        );
        assert!(parse(ns, &format!("* LIST () \".\" \"{}\"\r\n", "a".repeat(255))).is_ok());
        assert_eq!(
            parse(ns, &format!("* LIST () \".\" \"{}\"\r\n", "a".repeat(256))),
            Err(FolderMetadataError::InvalidName)
        );
        assert!(parse(ns, &format!("* LIST ({}) \".\" X\r\n", "x".repeat(256))).is_ok());
        assert_eq!(
            parse(ns, &format!("* LIST ({}) \".\" X\r\n", "x".repeat(257))),
            Err(FolderMetadataError::Limit)
        );
        assert_eq!(
            FolderSnapshot::parse("fixture", &vec![b'x'; MAX_TRANSCRIPT_BYTES + 1]),
            Err(FolderMetadataError::Limit)
        );
    }
}
