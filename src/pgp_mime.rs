//! Bounded RFC 3156 framing. Cryptography belongs to the isolated helper.
//!
//! Signed bytes come from a slice of the original message, never from the
//! display MIME parser. Only LF-to-CRLF canonicalization is permitted. The
//! CRLF introducing a MIME delimiter is not part of the signed entity.

use std::collections::BTreeMap;

pub const MAX_PGP_MIME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PgpMimePolicy {
    pub max_bytes: usize,
    pub max_parts: usize,
    pub max_depth: usize,
    pub max_headers: usize,
    pub max_header_bytes: usize,
    pub max_boundary_bytes: usize,
}

impl Default for PgpMimePolicy {
    fn default() -> Self {
        Self {
            max_bytes: MAX_PGP_MIME_BYTES,
            max_parts: 64,
            max_depth: 4,
            max_headers: 256,
            max_header_bytes: 4096,
            max_boundary_bytes: 200,
        }
    }
}

/// Reasons contain no message content, key data or engine diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PgpMimeError {
    SizeLimit,
    PartLimit,
    DepthLimit,
    HeaderLimit,
    MalformedHeaders,
    AmbiguousHeaders,
    MalformedContentType,
    AmbiguousParameter,
    MalformedLineEnding,
    MissingBoundary,
    MalformedBoundary,
    TruncatedMultipart,
    UnexpectedPartCount,
    UnsupportedProtocol,
    UnsupportedDigest,
    UnsupportedTransferEncoding,
    InvalidTransferEncoding,
    InvalidControlPart,
    EmptyPayload,
    NestedProtection,
    InvalidArmor,
    BoundaryCollision,
}

/// Original source remains borrowed and unchanged, including outer headers.
/// A signed result is a framing classification, not a verification claim.
#[derive(PartialEq, Eq)]
pub enum PgpMimeMessage<'a> {
    Unprotected {
        source: &'a [u8],
    },
    Signed {
        source: &'a [u8],
        entity: &'a [u8],
        canonical_entity: Vec<u8>,
        signature: Vec<u8>,
        digest: SignatureDigest,
    },
    Encrypted {
        source: &'a [u8],
        ciphertext: Vec<u8>,
    },
}

impl std::fmt::Debug for PgpMimeMessage<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unprotected { source } => f
                .debug_struct("Unprotected")
                .field("source_bytes", &source.len())
                .finish(),
            Self::Signed {
                entity,
                signature,
                digest,
                ..
            } => f
                .debug_struct("Signed")
                .field("entity_bytes", &entity.len())
                .field("signature_bytes", &signature.len())
                .field("digest", digest)
                .finish(),
            Self::Encrypted { ciphertext, .. } => f
                .debug_struct("Encrypted")
                .field("ciphertext_bytes", &ciphertext.len())
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureDigest {
    Sha256,
    Sha512,
}

impl SignatureDigest {
    pub fn micalg(self) -> &'static str {
        match self {
            Self::Sha256 => "pgp-sha256",
            Self::Sha512 => "pgp-sha512",
        }
    }
}

struct Headers {
    values: BTreeMap<String, Vec<u8>>,
}

impl Headers {
    fn value(&self, name: &str) -> Option<&[u8]> {
        self.values.get(name).map(Vec::as_slice)
    }

    fn text(&self, name: &str) -> Result<Option<&str>, PgpMimeError> {
        self.value(name)
            .map(|v| std::str::from_utf8(v).map_err(|_| PgpMimeError::MalformedHeaders))
            .transpose()
    }
}

struct Entity<'a> {
    raw: &'a [u8],
    body: &'a [u8],
    headers: Headers,
    content_type: ContentType,
}

struct ContentType {
    media_type: String,
    parameters: BTreeMap<String, String>,
}

/// Inspect the exact RFC 5322 source fetched for this authenticated message.
/// Ordinary multipart content is walked only for structural bounds and hidden
/// protected envelopes; existing rendering and sanitization remain separate.
pub fn classify(source: &[u8], policy: PgpMimePolicy) -> Result<PgpMimeMessage<'_>, PgpMimeError> {
    if source.len() > policy.max_bytes || source.len() > MAX_PGP_MIME_BYTES {
        return Err(PgpMimeError::SizeLimit);
    }
    let entity = parse_entity(source, policy)?;
    let mut parts_seen = 0;
    check_tree(&entity, policy, 0, &mut parts_seen, true)?;
    match entity.content_type.media_type.as_str() {
        "multipart/signed" => {
            check_protocol(&entity, "application/pgp-signature")?;
            let digest = match entity
                .content_type
                .parameters
                .get("micalg")
                .map(String::as_str)
            {
                Some(v) if v.eq_ignore_ascii_case("pgp-sha256") => SignatureDigest::Sha256,
                Some(v) if v.eq_ignore_ascii_case("pgp-sha512") => SignatureDigest::Sha512,
                _ => return Err(PgpMimeError::UnsupportedDigest),
            };
            let parts = multipart_parts(&entity, policy)?;
            if parts.len() != 2 {
                return Err(PgpMimeError::UnexpectedPartCount);
            }
            let signed = parse_entity(parts[0], policy)?;
            let signature = parse_entity(parts[1], policy)?;
            if signature.content_type.media_type != "application/pgp-signature" {
                return Err(PgpMimeError::UnsupportedProtocol);
            }
            let canonical_entity = canonical_signed_entity(signed.raw, policy.max_bytes)?;
            let signature = decode_payload(&signature, policy)?;
            if canonical_entity.len().saturating_add(signature.len()) > policy.max_bytes {
                return Err(PgpMimeError::SizeLimit);
            }
            Ok(PgpMimeMessage::Signed {
                source,
                entity: signed.raw,
                canonical_entity,
                signature,
                digest,
            })
        }
        "multipart/encrypted" => {
            check_protocol(&entity, "application/pgp-encrypted")?;
            let parts = multipart_parts(&entity, policy)?;
            if parts.len() != 2 {
                return Err(PgpMimeError::UnexpectedPartCount);
            }
            let control = parse_entity(parts[0], policy)?;
            let encrypted = parse_entity(parts[1], policy)?;
            if control.content_type.media_type != "application/pgp-encrypted"
                || encrypted.content_type.media_type != "application/octet-stream"
            {
                return Err(PgpMimeError::UnsupportedProtocol);
            }
            // The version part is ASCII protocol data, not free-form MIME text.
            if !matches!(transfer_encoding(&control)?.as_str(), "" | "7bit")
                || trim_ascii(control.body) != b"Version: 1"
            {
                return Err(PgpMimeError::InvalidControlPart);
            }
            Ok(PgpMimeMessage::Encrypted {
                source,
                ciphertext: decode_payload(&encrypted, policy)?,
            })
        }
        "application/pgp-encrypted" | "application/pgp-signature" => {
            Err(PgpMimeError::UnsupportedProtocol)
        }
        _ => Ok(PgpMimeMessage::Unprotected { source }),
    }
}

fn check_protocol(entity: &Entity<'_>, expected: &str) -> Result<(), PgpMimeError> {
    if entity
        .content_type
        .parameters
        .get("protocol")
        .is_some_and(|v| v.eq_ignore_ascii_case(expected))
        && matches!(transfer_encoding(entity)?.as_str(), "" | "7bit" | "8bit")
    {
        Ok(())
    } else {
        Err(PgpMimeError::UnsupportedProtocol)
    }
}

/// Preserve every byte other than canonicalizing bare LF to CRLF. Bare CR is
/// ambiguous and refused. No trimming, unfolding, decoding or newline append.
pub fn canonical_signed_entity(bytes: &[u8], max_bytes: usize) -> Result<Vec<u8>, PgpMimeError> {
    let max_bytes = max_bytes.min(MAX_PGP_MIME_BYTES);
    if bytes.len() > max_bytes {
        return Err(PgpMimeError::SizeLimit);
    }
    let mut result = Vec::with_capacity(bytes.len());
    for (i, &byte) in bytes.iter().enumerate() {
        match byte {
            b'\r' if bytes.get(i + 1) != Some(&b'\n') => {
                return Err(PgpMimeError::MalformedLineEnding);
            }
            b'\n' if i == 0 || bytes[i - 1] != b'\r' => result.extend_from_slice(b"\r\n"),
            _ => result.push(byte),
        }
        if result.len() > max_bytes {
            return Err(PgpMimeError::SizeLimit);
        }
    }
    Ok(result)
}

fn parse_entity(raw: &[u8], policy: PgpMimePolicy) -> Result<Entity<'_>, PgpMimeError> {
    let mut pos = 0;
    let mut count = 0;
    let mut values: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut previous: Option<String> = None;
    let body;
    loop {
        let (line, next, ended) = next_line(raw, pos)?;
        if !ended {
            return Err(PgpMimeError::MalformedHeaders);
        }
        pos = next;
        if line.is_empty() {
            body = &raw[pos..];
            break;
        }
        if line.contains(&b'\r') {
            return Err(PgpMimeError::MalformedLineEnding);
        }
        if line.iter().any(|&b| b < 32 && b != b'\t' || b == 127) {
            return Err(PgpMimeError::MalformedHeaders);
        }
        if line.len() > policy.max_header_bytes {
            return Err(PgpMimeError::HeaderLimit);
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            let name = previous.as_ref().ok_or(PgpMimeError::MalformedHeaders)?;
            let value = values.get_mut(name).ok_or(PgpMimeError::MalformedHeaders)?;
            value.push(b' ');
            value.extend_from_slice(trim_ascii(line));
            if value.len() > policy.max_header_bytes {
                return Err(PgpMimeError::HeaderLimit);
            }
            continue;
        }
        count += 1;
        if count > policy.max_headers {
            return Err(PgpMimeError::HeaderLimit);
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or(PgpMimeError::MalformedHeaders)?;
        if colon == 0
            || !line[..colon]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return Err(PgpMimeError::MalformedHeaders);
        }
        let name = std::str::from_utf8(&line[..colon])
            .map_err(|_| PgpMimeError::MalformedHeaders)?
            .to_ascii_lowercase();
        let value = trim_ascii(&line[colon + 1..]);
        if value.iter().any(|&b| b < 32 && b != b'\t' || b == 127) {
            return Err(PgpMimeError::MalformedHeaders);
        }
        if values.contains_key(&name)
            && matches!(
                name.as_str(),
                "content-type"
                    | "content-transfer-encoding"
                    | "content-disposition"
                    | "mime-version"
            )
        {
            return Err(PgpMimeError::AmbiguousHeaders);
        }
        values.insert(name.clone(), value.to_vec());
        previous = Some(name);
    }
    let headers = Headers { values };
    let content_type = parse_content_type(headers.text("content-type")?.unwrap_or("text/plain"))?;
    Ok(Entity {
        raw,
        body,
        headers,
        content_type,
    })
}

fn next_line(raw: &[u8], start: usize) -> Result<(&[u8], usize, bool), PgpMimeError> {
    let end = raw[start..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| start + p);
    let Some(end) = end else {
        let line = &raw[start..];
        return Ok((line, raw.len(), false));
    };
    let line = if end > start && raw[end - 1] == b'\r' {
        &raw[start..end - 1]
    } else {
        &raw[start..end]
    };
    Ok((line, end + 1, true))
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn parse_content_type(value: &str) -> Result<ContentType, PgpMimeError> {
    let bytes = value.as_bytes();
    if !bytes.is_ascii() {
        return Err(PgpMimeError::MalformedContentType);
    }
    let mut pieces = value.splitn(2, ';');
    let media_type = pieces.next().unwrap_or("").trim().to_ascii_lowercase();
    let Some((major, minor)) = media_type.split_once('/') else {
        return Err(PgpMimeError::MalformedContentType);
    };
    if major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(token)
        || !minor.bytes().all(token)
    {
        return Err(PgpMimeError::MalformedContentType);
    }
    let params = pieces.next().unwrap_or("").as_bytes();
    let mut i = 0;
    let mut parameters = BTreeMap::new();
    while i < params.len() {
        while i < params.len() && params[i].is_ascii_whitespace() {
            i += 1;
        }
        let begin = i;
        while i < params.len() && token(params[i]) {
            i += 1;
        }
        if i == begin {
            return Err(PgpMimeError::MalformedContentType);
        }
        let name = String::from_utf8(params[begin..i].to_vec())
            .map_err(|_| PgpMimeError::MalformedContentType)?
            .to_ascii_lowercase();
        while i < params.len() && params[i].is_ascii_whitespace() {
            i += 1;
        }
        if params.get(i) != Some(&b'=') {
            return Err(PgpMimeError::MalformedContentType);
        }
        i += 1;
        while i < params.len() && params[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut parsed = Vec::new();
        if params.get(i) == Some(&b'"') {
            i += 1;
            let mut closed = false;
            while i < params.len() {
                match params[i] {
                    b'"' => {
                        i += 1;
                        closed = true;
                        break;
                    }
                    b'\\' => {
                        i += 1;
                        let &b = params.get(i).ok_or(PgpMimeError::MalformedContentType)?;
                        parsed.push(b);
                        i += 1;
                    }
                    b if b < 32 || b == 127 => return Err(PgpMimeError::MalformedContentType),
                    b => {
                        parsed.push(b);
                        i += 1;
                    }
                }
            }
            if !closed {
                return Err(PgpMimeError::MalformedContentType);
            }
        } else {
            while i < params.len() && token(params[i]) {
                parsed.push(params[i]);
                i += 1;
            }
            if parsed.is_empty() {
                return Err(PgpMimeError::MalformedContentType);
            }
        }
        let parsed = String::from_utf8(parsed).map_err(|_| PgpMimeError::MalformedContentType)?;
        if parameters.insert(name, parsed).is_some() {
            return Err(PgpMimeError::AmbiguousParameter);
        }
        while i < params.len() && params[i].is_ascii_whitespace() {
            i += 1;
        }
        if i == params.len() {
            break;
        }
        if params[i] != b';' {
            return Err(PgpMimeError::MalformedContentType);
        }
        i += 1;
        if i == params.len() {
            return Err(PgpMimeError::MalformedContentType);
        }
    }
    Ok(ContentType {
        media_type,
        parameters,
    })
}

fn multipart_parts<'a>(
    entity: &Entity<'a>,
    policy: PgpMimePolicy,
) -> Result<Vec<&'a [u8]>, PgpMimeError> {
    let boundary = entity
        .content_type
        .parameters
        .get("boundary")
        .ok_or(PgpMimeError::MissingBoundary)?;
    validate_boundary(boundary, policy.max_boundary_bytes)?;
    let marker = format!("--{boundary}").into_bytes();
    let closing = format!("--{boundary}--").into_bytes();
    let mut pos = 0;
    let mut start = None;
    let mut parts = Vec::new();
    let mut closed = false;
    while pos < entity.body.len() {
        let line_start = pos;
        let (line, next, ended) = next_line(entity.body, pos)?;
        pos = next;
        // RFC 2046 allows SP/HTAB padding after a delimiter, never leading padding.
        let mut delimiter = line;
        while matches!(delimiter.last(), Some(b' ' | b'\t')) {
            delimiter = &delimiter[..delimiter.len() - 1];
        }
        if delimiter != marker && delimiter != closing {
            continue;
        }
        if closed {
            return Err(PgpMimeError::MalformedBoundary);
        }
        if let Some(begin) = start.take() {
            let mut end = line_start;
            if end > begin && entity.body[end - 1] == b'\n' {
                end -= 1;
                if end > begin && entity.body[end - 1] == b'\r' {
                    end -= 1;
                }
            }
            if end <= begin {
                return Err(PgpMimeError::MalformedHeaders);
            }
            parts.push(&entity.body[begin..end]);
            if parts.len() > policy.max_parts {
                return Err(PgpMimeError::PartLimit);
            }
        }
        if delimiter == closing {
            if parts.is_empty() {
                return Err(PgpMimeError::UnexpectedPartCount);
            }
            closed = true;
        } else {
            if !ended {
                return Err(PgpMimeError::TruncatedMultipart);
            }
            start = Some(next);
        }
    }
    if !closed || start.is_some() {
        return Err(PgpMimeError::TruncatedMultipart);
    }
    Ok(parts)
}

fn validate_boundary(boundary: &str, max_bytes: usize) -> Result<(), PgpMimeError> {
    if boundary.is_empty()
        || boundary.len() > max_bytes
        || boundary.ends_with(' ')
        || !boundary
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&b))
    {
        return Err(PgpMimeError::MalformedBoundary);
    }
    Ok(())
}

fn check_tree(
    entity: &Entity<'_>,
    policy: PgpMimePolicy,
    depth: usize,
    seen: &mut usize,
    root: bool,
) -> Result<(), PgpMimeError> {
    *seen += 1;
    if *seen > policy.max_parts {
        return Err(PgpMimeError::PartLimit);
    }
    if depth > policy.max_depth {
        return Err(PgpMimeError::DepthLimit);
    }
    if !root
        && matches!(
            entity.content_type.media_type.as_str(),
            "multipart/signed" | "multipart/encrypted"
        )
    {
        return Err(PgpMimeError::NestedProtection);
    }
    if entity.content_type.media_type.starts_with("multipart/") {
        for part in multipart_parts(entity, policy)? {
            check_tree(&parse_entity(part, policy)?, policy, depth + 1, seen, false)?;
        }
    }
    Ok(())
}

fn transfer_encoding(entity: &Entity<'_>) -> Result<String, PgpMimeError> {
    Ok(entity
        .headers
        .text("content-transfer-encoding")?
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase())
}

fn decode_payload(entity: &Entity<'_>, policy: PgpMimePolicy) -> Result<Vec<u8>, PgpMimeError> {
    let output = match transfer_encoding(entity)?.as_str() {
        "" | "7bit" | "8bit" | "binary" => entity.body.to_vec(),
        "base64" => decode_base64(entity.body)?,
        _ => return Err(PgpMimeError::UnsupportedTransferEncoding),
    };
    if output.is_empty() {
        return Err(PgpMimeError::EmptyPayload);
    }
    if output.len() > policy.max_bytes {
        return Err(PgpMimeError::SizeLimit);
    }
    Ok(output)
}

fn decode_base64(bytes: &[u8]) -> Result<Vec<u8>, PgpMimeError> {
    let input: Vec<_> = bytes
        .iter()
        .copied()
        .filter(|b| !matches!(b, b'\r' | b'\n' | b' ' | b'\t'))
        .collect();
    if input.len() % 4 != 0 {
        return Err(PgpMimeError::InvalidTransferEncoding);
    }
    let mut output = Vec::with_capacity(input.len() / 4 * 3);
    let chunks = input.len() / 4;
    for (index, chunk) in input.chunks_exact(4).enumerate() {
        let mut values = [0u32; 4];
        for (n, &b) in chunk.iter().enumerate() {
            values[n] = match b {
                b'A'..=b'Z' => u32::from(b - b'A'),
                b'a'..=b'z' => u32::from(b - b'a') + 26,
                b'0'..=b'9' => u32::from(b - b'0') + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if n >= 2 => 0,
                _ => return Err(PgpMimeError::InvalidTransferEncoding),
            };
        }
        let padding = usize::from(chunk[3] == b'=') + usize::from(chunk[2] == b'=');
        if padding > 0 && index + 1 != chunks
            || chunk[2] == b'=' && chunk[3] != b'='
            || padding == 1 && values[2] & 3 != 0
            || padding == 2 && values[1] & 15 != 0
        {
            return Err(PgpMimeError::InvalidTransferEncoding);
        }
        let joined = values[0] << 18 | values[1] << 12 | values[2] << 6 | values[3];
        output.push((joined >> 16) as u8);
        if padding < 2 {
            output.push((joined >> 8) as u8);
        }
        if padding == 0 {
            output.push(joined as u8);
        }
    }
    Ok(output)
}

/// Wrap already signed canonical bytes. The helper signs exactly `entity`;
/// this builder refuses noncanonical input instead of changing signed bytes.
/// Returns a MIME entity without outer From/To/Subject or any Bcc header.
pub fn build_signed(
    entity: &[u8],
    signature_armor: &[u8],
    digest: SignatureDigest,
    boundary: &str,
    policy: PgpMimePolicy,
) -> Result<Vec<u8>, PgpMimeError> {
    validate_boundary(boundary, policy.max_boundary_bytes)?;
    if canonical_signed_entity(entity, policy.max_bytes)? != entity {
        return Err(PgpMimeError::MalformedLineEnding);
    }
    let entity_view = parse_entity(entity, policy)?;
    check_tree(&entity_view, policy, 0, &mut 0, true)?;
    if matches!(
        entity_view.content_type.media_type.as_str(),
        "multipart/signed" | "multipart/encrypted"
    ) {
        return Err(PgpMimeError::NestedProtection);
    }
    let signature_armor = canonical_signed_entity(signature_armor, policy.max_bytes)?;
    validate_armor(&signature_armor, "SIGNATURE")?;
    refuse_boundary_collision(entity, boundary)?;
    refuse_boundary_collision(&signature_armor, boundary)?;
    let mut out = format!("Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg={}; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\n", digest.micalg()).into_bytes();
    append_bounded(&mut out, entity, policy)?;
    append_bounded(&mut out, format!("\r\n--{boundary}\r\nContent-Type: application/pgp-signature\r\nContent-Transfer-Encoding: 7bit\r\n\r\n").as_bytes(), policy)?;
    append_bounded(&mut out, &signature_armor, policy)?;
    append_bounded(
        &mut out,
        format!("\r\n--{boundary}--\r\n").as_bytes(),
        policy,
    )?;
    Ok(out)
}

/// Wrap ASCII-armoured encrypted output, including sign-then-encrypt output.
/// Recipient addressing remains in the separately authorized SMTP envelope.
pub fn build_encrypted(
    ciphertext_armor: &[u8],
    boundary: &str,
    policy: PgpMimePolicy,
) -> Result<Vec<u8>, PgpMimeError> {
    validate_boundary(boundary, policy.max_boundary_bytes)?;
    let ciphertext_armor = canonical_signed_entity(ciphertext_armor, policy.max_bytes)?;
    validate_armor(&ciphertext_armor, "MESSAGE")?;
    refuse_boundary_collision(&ciphertext_armor, boundary)?;
    let mut out = format!("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\nContent-Type: application/pgp-encrypted\r\nContent-Transfer-Encoding: 7bit\r\n\r\nVersion: 1\r\n\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: 7bit\r\n\r\n").into_bytes();
    append_bounded(&mut out, &ciphertext_armor, policy)?;
    append_bounded(
        &mut out,
        format!("\r\n--{boundary}--\r\n").as_bytes(),
        policy,
    )?;
    Ok(out)
}

fn append_bounded(
    out: &mut Vec<u8>,
    bytes: &[u8],
    policy: PgpMimePolicy,
) -> Result<(), PgpMimeError> {
    if out.len().saturating_add(bytes.len()) > policy.max_bytes.min(MAX_PGP_MIME_BYTES) {
        return Err(PgpMimeError::SizeLimit);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn validate_armor(armor: &[u8], label: &str) -> Result<(), PgpMimeError> {
    if armor.is_empty()
        || !armor.is_ascii()
        || armor
            .iter()
            .any(|b| *b < 32 && !matches!(b, b'\r' | b'\n' | b'\t') || *b == 127)
    {
        return Err(PgpMimeError::InvalidArmor);
    }
    let mut pos = 0;
    let mut lines = Vec::new();
    while pos < armor.len() {
        let (line, next, _) = next_line(armor, pos)?;
        pos = next;
        lines.push(line);
    }
    let begin = format!("-----BEGIN PGP {label}-----");
    let end = format!("-----END PGP {label}-----");
    if lines.len() < 3
        || lines.first().copied() != Some(begin.as_bytes())
        || lines.last().copied() != Some(end.as_bytes())
        || lines[1..lines.len() - 1]
            .iter()
            .any(|l| l.starts_with(b"-----BEGIN") || l.starts_with(b"-----END"))
    {
        return Err(PgpMimeError::InvalidArmor);
    }
    Ok(())
}

fn refuse_boundary_collision(bytes: &[u8], boundary: &str) -> Result<(), PgpMimeError> {
    let marker = format!("--{boundary}");
    let mut pos = 0;
    while pos < bytes.len() {
        let (line, next, _) = next_line(bytes, pos)?;
        pos = next;
        if line.starts_with(marker.as_bytes()) {
            return Err(PgpMimeError::BoundaryCollision);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "pgp_mime_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "pgp_mime_native_tests.rs"]
mod native_tests;
