use super::*;

const ENTITY: &[u8] = b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nDo not trim =20\r\nlast line";
const SIGNATURE: &[u8] =
    b"-----BEGIN PGP SIGNATURE-----\n\nZml4dHVyZQ==\n-----END PGP SIGNATURE-----\n";
const CIPHERTEXT: &[u8] =
    b"-----BEGIN PGP MESSAGE-----\n\nZml4dHVyZQ==\n-----END PGP MESSAGE-----\n";

fn signed(entity: &[u8]) -> Vec<u8> {
    build_signed(
        entity,
        SIGNATURE,
        SignatureDigest::Sha256,
        "signed-test",
        PgpMimePolicy::default(),
    )
    .unwrap()
}

fn encrypted() -> Vec<u8> {
    build_encrypted(CIPHERTEXT, "encrypted-test", PgpMimePolicy::default()).unwrap()
}

fn replace(bytes: &[u8], old: &str, new: &str) -> Vec<u8> {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace(old, new)
        .into_bytes()
}

#[test]
fn pgp_mime_signed_retains_source_and_exact_entity_without_boundary_crlf() {
    let wire = signed(ENTITY);
    let PgpMimeMessage::Signed {
        source,
        entity,
        canonical_entity,
        signature,
        digest,
    } = classify(&wire, PgpMimePolicy::default()).unwrap()
    else {
        panic!("expected signed frame")
    };
    assert_eq!(source.as_ptr(), wire.as_ptr());
    assert_eq!(source, wire);
    assert_eq!(entity, ENTITY);
    assert_eq!(canonical_entity, ENTITY);
    assert_eq!(signature, canonical_signed_entity(SIGNATURE, 1024).unwrap());
    assert_eq!(digest, SignatureDigest::Sha256);
}

#[test]
fn pgp_mime_trailing_entity_crlf_survives_delimiter_separation() {
    for ending in [b"".as_slice(), b"\r\n", b"\r\n\r\n"] {
        let mut expected = ENTITY.to_vec();
        expected.extend_from_slice(ending);
        let wire = signed(&expected);
        let PgpMimeMessage::Signed {
            entity,
            canonical_entity,
            ..
        } = classify(&wire, PgpMimePolicy::default()).unwrap()
        else {
            panic!("signed")
        };
        assert_eq!(entity, expected);
        assert_eq!(canonical_entity, expected);
    }
}

#[test]
fn pgp_mime_lf_source_canonicalizes_without_rewriting_signed_content() {
    let wire = replace(&signed(ENTITY), "\r\n", "\n");
    let PgpMimeMessage::Signed {
        source,
        entity,
        canonical_entity,
        ..
    } = classify(&wire, PgpMimePolicy::default()).unwrap()
    else {
        panic!("signed")
    };
    assert_eq!(source, wire);
    assert_eq!(entity, replace(ENTITY, "\r\n", "\n"));
    assert_eq!(canonical_entity, ENTITY);
}

#[test]
fn pgp_mime_header_folding_whitespace_transfer_bytes_and_binary_survive() {
    let entity = b"Content-Type: text/plain;\r\n\tcharset=utf-8\r\nX-Exact:  two  spaces \t\r\n\r\ntrailing \t\r\n\xff\xfe";
    let wire = signed(entity);
    let PgpMimeMessage::Signed {
        canonical_entity, ..
    } = classify(&wire, PgpMimePolicy::default()).unwrap()
    else {
        panic!("signed")
    };
    assert_eq!(canonical_entity, entity);
}

#[test]
fn pgp_mime_tampering_changes_exact_verification_input() {
    let original = signed(ENTITY);
    let changed = replace(&original, "last line", "tampered!");
    let input = |wire: &[u8]| match classify(wire, PgpMimePolicy::default()).unwrap() {
        PgpMimeMessage::Signed {
            canonical_entity, ..
        } => canonical_entity,
        _ => panic!("signed"),
    };
    assert_ne!(input(&original), input(&changed));
    // Cryptographic rejection is the helper's responsibility, not inferred here.
}

#[test]
fn pgp_mime_encrypted_roundtrip_is_opaque_and_not_verification() {
    let wire = encrypted();
    let PgpMimeMessage::Encrypted { source, ciphertext } =
        classify(&wire, PgpMimePolicy::default()).unwrap()
    else {
        panic!("encrypted")
    };
    assert_eq!(source, wire);
    assert_eq!(
        ciphertext,
        canonical_signed_entity(CIPHERTEXT, 1024).unwrap()
    );
    assert!(!wire.windows(5).any(|w| w == b"Bcc: "));
}

#[test]
fn pgp_mime_protected_payload_base64_strict_decoding() {
    let wire = b"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=e\r\n\r\n--e\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--e\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nAAH/\r\n--e--\r\n";
    let PgpMimeMessage::Encrypted { ciphertext, .. } =
        classify(wire, PgpMimePolicy::default()).unwrap()
    else {
        panic!("encrypted")
    };
    assert_eq!(ciphertext, [0, 1, 255]);
    for invalid in [
        "AB==",
        "AAB=",
        "AA==AAAA",
        "AA=A",
        "!!!=",
        "AAA",
        "AA==\u{b}",
    ] {
        let bad = replace(wire, "AAH/", invalid);
        assert_eq!(
            classify(&bad, PgpMimePolicy::default()).unwrap_err(),
            PgpMimeError::InvalidTransferEncoding
        );
    }
}

#[test]
fn pgp_mime_raw_binary_ciphertext_is_not_text_normalized() {
    let mut wire = b"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=e\r\n\r\n--e\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--e\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n".to_vec();
    let expected = [0, 255, 13, 1, 10, 128];
    wire.extend_from_slice(&expected);
    wire.extend_from_slice(b"\r\n--e--\r\n");
    let PgpMimeMessage::Encrypted { ciphertext, .. } =
        classify(&wire, PgpMimePolicy::default()).unwrap()
    else {
        panic!("encrypted")
    };
    assert_eq!(ciphertext, expected);
}

#[test]
fn pgp_mime_duplicate_authority_headers_and_parameters_refuse() {
    let wire = signed(ENTITY);
    for modified in [
        replace(
            &wire,
            "micalg=pgp-sha256;",
            "micalg=pgp-sha256; MICALG=pgp-sha512;",
        ),
        replace(
            &wire,
            "boundary=\"signed-test\"",
            "boundary=\"signed-test\"; BOUNDARY=other",
        ),
        replace(
            &wire,
            "Content-Transfer-Encoding: 7bit",
            "Content-Transfer-Encoding: 7bit\r\ncontent-transfer-encoding: base64",
        ),
        replace(
            &wire,
            "Content-Type: application/pgp-signature\r\n",
            "Content-Type: application/pgp-signature\r\nCONTENT-TYPE: text/plain\r\n",
        ),
    ] {
        assert!(matches!(
            classify(&modified, PgpMimePolicy::default()),
            Err(PgpMimeError::AmbiguousHeaders | PgpMimeError::AmbiguousParameter)
        ));
    }
}

#[test]
fn pgp_mime_wrong_protocol_digest_control_and_encoding_refuse() {
    assert_eq!(
        classify(
            &replace(&signed(ENTITY), "pgp-sha256", "pgp-sha1"),
            PgpMimePolicy::default()
        )
        .unwrap_err(),
        PgpMimeError::UnsupportedDigest
    );
    assert_eq!(
        classify(
            &replace(
                &signed(ENTITY),
                "application/pgp-signature",
                "application/pkcs7-signature"
            ),
            PgpMimePolicy::default()
        )
        .unwrap_err(),
        PgpMimeError::UnsupportedProtocol
    );
    assert_eq!(
        classify(
            &replace(&encrypted(), "Version: 1", "Version: 2"),
            PgpMimePolicy::default()
        )
        .unwrap_err(),
        PgpMimeError::InvalidControlPart
    );
    assert_eq!(
        classify(
            &replace(&encrypted(), "Version: 1", "Version: 1\r\nOther: value"),
            PgpMimePolicy::default()
        )
        .unwrap_err(),
        PgpMimeError::InvalidControlPart
    );
    assert_eq!(
        classify(
            &replace(
                &signed(ENTITY),
                "Content-Transfer-Encoding: 7bit",
                "Content-Transfer-Encoding: quoted-printable"
            ),
            PgpMimePolicy::default()
        )
        .unwrap_err(),
        PgpMimeError::UnsupportedTransferEncoding
    );
}

#[test]
fn pgp_mime_truncated_extra_part_empty_payload_and_reopened_boundary_refuse() {
    let wire = signed(ENTITY);
    let truncated = replace(&wire, "--signed-test--\r\n", "");
    assert_eq!(
        classify(&truncated, PgpMimePolicy::default()).unwrap_err(),
        PgpMimeError::TruncatedMultipart
    );
    let three = replace(
        &wire,
        "--signed-test--",
        "--signed-test\r\nContent-Type: text/plain\r\n\r\nthird\r\n--signed-test--",
    );
    assert_eq!(
        classify(&three, PgpMimePolicy::default()).unwrap_err(),
        PgpMimeError::UnexpectedPartCount
    );
    let reopened = replace(
        &wire,
        "--signed-test--\r\n",
        "--signed-test--\r\n--signed-test\r\n",
    );
    assert_eq!(
        classify(&reopened, PgpMimePolicy::default()).unwrap_err(),
        PgpMimeError::MalformedBoundary
    );
}

#[test]
fn pgp_mime_delimiter_padding_is_only_space_or_tab_and_not_prefix() {
    let wire = signed(ENTITY);
    let padded = replace(&wire, "--signed-test\r\n", "--signed-test \t\r\n");
    assert!(matches!(
        classify(&padded, PgpMimePolicy::default()),
        Ok(PgpMimeMessage::Signed { .. })
    ));
    for bad in [
        "--signed-test\u{b}\r\n",
        "--signed-testX\r\n",
        " --signed-test\r\n",
    ] {
        let malformed = replace(&wire, "--signed-test\r\n", bad);
        assert!(classify(&malformed, PgpMimePolicy::default()).is_err());
    }
}

#[test]
fn pgp_mime_byte_header_part_and_depth_bounds_are_global() {
    let wire = signed(ENTITY);
    assert_eq!(
        classify(
            &wire,
            PgpMimePolicy {
                max_bytes: wire.len() - 1,
                ..PgpMimePolicy::default()
            }
        )
        .unwrap_err(),
        PgpMimeError::SizeLimit
    );
    assert_eq!(
        classify(
            &wire,
            PgpMimePolicy {
                max_parts: 2,
                ..PgpMimePolicy::default()
            }
        )
        .unwrap_err(),
        PgpMimeError::PartLimit
    );
    assert_eq!(
        classify(
            &wire,
            PgpMimePolicy {
                max_depth: 0,
                ..PgpMimePolicy::default()
            }
        )
        .unwrap_err(),
        PgpMimeError::DepthLimit
    );
    assert_eq!(
        classify(
            &wire,
            PgpMimePolicy {
                max_headers: 1,
                ..PgpMimePolicy::default()
            }
        )
        .unwrap_err(),
        PgpMimeError::HeaderLimit
    );
    assert_eq!(
        classify(
            &wire,
            PgpMimePolicy {
                max_header_bytes: 5,
                ..PgpMimePolicy::default()
            }
        )
        .unwrap_err(),
        PgpMimeError::HeaderLimit
    );
    assert_eq!(
        canonical_signed_entity(b"a\nb\n", 5).unwrap_err(),
        PgpMimeError::SizeLimit
    );
}

#[test]
fn pgp_mime_nested_protection_is_not_silently_called_unprotected() {
    let protected = signed(ENTITY);
    let mut mixed = b"Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\n".to_vec();
    mixed.extend_from_slice(&protected);
    mixed.extend_from_slice(b"\r\n--outer--\r\n");
    assert_eq!(
        classify(&mixed, PgpMimePolicy::default()).unwrap_err(),
        PgpMimeError::NestedProtection
    );
}

#[test]
fn pgp_mime_signed_attachment_entity_remains_exact_and_undecoded() {
    let mixed = b"Content-Type: multipart/mixed; boundary=inner\r\n\r\n--inner\r\nContent-Type: text/plain\r\n\r\nbody\r\n--inner\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=synthetic.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAAH/\r\n--inner--\r\n";
    let wire = signed(mixed);
    let PgpMimeMessage::Signed {
        canonical_entity, ..
    } = classify(&wire, PgpMimePolicy::default()).unwrap()
    else {
        panic!("signed")
    };
    assert_eq!(canonical_entity, mixed);
    assert_eq!(
        classify(
            &wire,
            PgpMimePolicy {
                max_parts: 4,
                ..PgpMimePolicy::default()
            }
        )
        .unwrap_err(),
        PgpMimeError::PartLimit
    );
}

#[test]
fn pgp_mime_builder_rejects_boundary_collision_and_altered_signed_bytes() {
    let collision = b"Content-Type: text/plain\r\n\r\n--signed-test\r\n";
    assert_eq!(
        build_signed(
            collision,
            SIGNATURE,
            SignatureDigest::Sha256,
            "signed-test",
            PgpMimePolicy::default()
        )
        .unwrap_err(),
        PgpMimeError::BoundaryCollision
    );
    assert_eq!(
        build_signed(
            &replace(ENTITY, "\r\n", "\n"),
            SIGNATURE,
            SignatureDigest::Sha256,
            "signed-test",
            PgpMimePolicy::default()
        )
        .unwrap_err(),
        PgpMimeError::MalformedLineEnding
    );
    assert_eq!(
        canonical_signed_entity(b"header\rbody", 1024).unwrap_err(),
        PgpMimeError::MalformedLineEnding
    );
    for bad in ["", "bad\r\nheader", "has\"quote", "trailing "] {
        assert_eq!(
            build_encrypted(CIPHERTEXT, bad, PgpMimePolicy::default()).unwrap_err(),
            PgpMimeError::MalformedBoundary
        );
    }
}

#[test]
fn pgp_mime_builder_emits_crlf_and_rejects_invalid_armor_or_aggregate_size() {
    let wire = encrypted();
    assert_eq!(canonical_signed_entity(&wire, 4096).unwrap(), wire);
    assert_eq!(
        build_encrypted(b"arbitrary bytes", "e", PgpMimePolicy::default()).unwrap_err(),
        PgpMimeError::InvalidArmor
    );
    assert_eq!(
        build_signed(
            ENTITY,
            SIGNATURE,
            SignatureDigest::Sha256,
            "s",
            PgpMimePolicy {
                max_bytes: 200,
                ..PgpMimePolicy::default()
            }
        )
        .unwrap_err(),
        PgpMimeError::SizeLimit
    );
}

#[test]
fn pgp_mime_plain_source_and_debug_never_expose_content() {
    let source = b"Subject: synthetic\r\n\r\nprivate fixture marker";
    let message = classify(source, PgpMimePolicy::default()).unwrap();
    assert_eq!(message, PgpMimeMessage::Unprotected { source });
    assert!(!format!("{message:?}").contains("private fixture marker"));
    assert!(!format!(
        "{:?}",
        classify(&signed(ENTITY), PgpMimePolicy::default()).unwrap()
    )
    .contains("Do not trim"));
}
