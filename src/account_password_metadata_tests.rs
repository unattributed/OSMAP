use super::*;
use std::time::Duration;

fn end() -> Instant {
    Instant::now() + Duration::from_secs(1)
}
fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).into()).collect()
}
fn argv(values: &[&[u8]]) -> (Vec<u8>, usize) {
    let word = std::mem::size_of::<usize>();
    let mut raw =
        vec![0u8; (values.len() + 1) * word + values.iter().map(|v| v.len() + 1).sum::<usize>()];
    let address = raw.as_ptr() as usize;
    let mut offset = (values.len() + 1) * word;
    for (index, value) in values.iter().enumerate() {
        raw[index * word..(index + 1) * word].copy_from_slice(&(address + offset).to_ne_bytes());
        raw[offset..offset + value.len()].copy_from_slice(value);
        offset += value.len() + 1;
    }
    (raw, address)
}

#[test]
fn native_ps_keeps_exact_three_shapes_and_kernel_buffer_bounds() {
    assert_eq!(
        request(&strings(&[
            "-ax",
            "-o",
            crate::account_password_peer::PS_FIELDS
        ]))
        .unwrap(),
        Request::All
    );
    assert_eq!(
        request(&strings(&[
            "-p",
            "123",
            "-o",
            crate::account_password_peer::PS_FIELDS
        ]))
        .unwrap(),
        Request::Row(123)
    );
    assert_eq!(
        request(&strings(&["-p", "123", "-o", "args="])).unwrap(),
        Request::Arguments(123)
    );
    for values in [
        vec!["-p", "0123", "-o", "args="],
        vec!["-p", "1", "-o", "args="],
        vec!["-p", "123", "-o", "env="],
        vec!["-ax", "-o", "args="],
    ] {
        assert!(request(&strings(&values)).is_err());
    }
    assert_eq!(row_count(128, 256, 64).unwrap(), 2);
    for (length, capacity, width) in [
        (0, 256, 64),
        (65, 256, 64),
        (257, 256, 64),
        (1, 256, 0),
        (4097, 4097, 1),
    ] {
        assert!(row_count(length, capacity, width).is_err());
    }
}

#[test]
fn native_argv_checks_actual_owned_pointer_framing_and_never_environment() {
    let (raw, address) = argv(&[b"dovecot", b"-c", b"/etc/dovecot/dovecot.conf"]);
    assert_eq!(
        arguments(&raw, address, BYTES, end()).unwrap(),
        "dovecot -c /etc/dovecot/dovecot.conf\n"
    );
    let word = std::mem::size_of::<usize>();
    let mut outside = raw.clone();
    outside[..word].copy_from_slice(&(address + raw.len()).to_ne_bytes());
    let mut table = raw.clone();
    table[..word].copy_from_slice(&address.to_ne_bytes());
    let mut no_null = raw.clone();
    *no_null.last_mut().unwrap() = b'x';
    let mut no_terminal = raw.clone();
    no_terminal[3 * word..4 * word].copy_from_slice(&(address + 4 * word).to_ne_bytes());
    for bad in [&outside, &table, &no_null, &no_terminal] {
        assert!(arguments(bad, address, BYTES, end()).is_err());
    }
    for value in [
        b"bad\nvalue".as_slice(),
        b"bad\rvalue",
        b"bad\tvalue",
        b"bad\xffvalue",
    ] {
        let (bad, base) = argv(&[value]);
        assert!(arguments(&bad, base, BYTES, end()).is_err());
    }
    assert!(arguments(&raw, address, 4, end()).is_err());
    assert!(arguments(&raw, address, BYTES, Instant::now()).is_err());
    assert!(arguments(&vec![0; BYTES + 1], address, BYTES, end()).is_err());
}

#[test]
fn native_row_preserves_effective_identity_birth_and_existing_peer_parser() {
    let rendered = render_row(
        ProcessRow {
            pid: 123,
            parent: 1,
            group: 123,
            uid: 518,
            gid: 518,
            started: 1_700_000_000,
            valid: true,
            command: b"auth\0",
        },
        end(),
    )
    .unwrap();
    let fields: Vec<_> = rendered.split_whitespace().collect();
    assert_eq!(&fields[..5], ["123", "1", "123", "518", "518"]);
    assert_eq!(fields.len(), 11);
    assert_eq!(fields[10], "auth");
    assert_eq!(fields[9], "2023");
    for command in [b"auth".as_slice(), b"bad name\0", b"bad\xff\0", b"\0"] {
        assert!(render_row(
            ProcessRow {
                pid: 123,
                parent: 1,
                group: 123,
                uid: 518,
                gid: 518,
                started: 1_700_000_000,
                valid: true,
                command
            },
            end()
        )
        .is_err());
    }
    assert!(render_row(
        ProcessRow {
            pid: 123,
            parent: 1,
            group: 123,
            uid: 518,
            gid: 518,
            started: 1_700_000_000,
            valid: false,
            command: b"auth\0"
        },
        end()
    )
    .is_err());
    assert!(render_row(
        ProcessRow {
            pid: 123,
            parent: 1,
            group: 123,
            uid: 518,
            gid: 518,
            started: 1_700_000_000,
            valid: true,
            command: b"auth\0"
        },
        Instant::now()
    )
    .is_err());
}
