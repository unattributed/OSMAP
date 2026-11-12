//! Fixed PS-shaped process observations after the real password parent seal.
//! Existing pre-seal PS captures and all peer parsers remain the authority.
use std::io;
use std::time::Instant;

pub(crate) const ROWS: usize = 4096;
pub(crate) const BYTES: usize = 65536;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Request {
    All,
    Row(i32),
    Arguments(i32),
}
pub(crate) fn refused() -> io::Error {
    io::ErrorKind::InvalidData.into()
}
pub(crate) fn before(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::ErrorKind::TimedOut.into())
    } else {
        Ok(())
    }
}
pub(crate) fn request(args: &[String]) -> io::Result<Request> {
    if !crate::account_password_process::fixed_metadata_args("/bin/ps", args) {
        return Err(refused());
    }
    if args[0] == "-ax" {
        return Ok(Request::All);
    }
    let pid = args[1].parse().map_err(|_| refused())?;
    Ok(if args[3] == "args=" {
        Request::Arguments(pid)
    } else {
        Request::Row(pid)
    })
}
pub(crate) fn bounded(text: String, cap: usize, deadline: Instant) -> io::Result<String> {
    before(deadline)?;
    if text.is_empty() || text.len() > cap || !text.is_ascii() || text.contains('\0') {
        Err(refused())
    } else {
        Ok(text)
    }
}
pub(crate) struct ProcessRow<'a> {
    pub(crate) pid: i32,
    pub(crate) parent: i32,
    pub(crate) group: i32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) started: u64,
    pub(crate) valid: bool,
    pub(crate) command: &'a [u8],
}
pub(crate) fn render_row(row: ProcessRow<'_>, deadline: Instant) -> io::Result<String> {
    before(deadline)?;
    let end = row
        .command
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(refused)?;
    let command = &row.command[..end];
    if row.pid < 0
        || row.parent < 0
        || row.group < 0
        || row.uid == u32::MAX
        || row.gid == u32::MAX
        || !row.valid
        || command.is_empty()
        || command.iter().any(|b| !b.is_ascii_graphic())
    {
        return Err(refused());
    }
    let birth = crate::openbsd::password_process_birth(row.started)?;
    bounded(
        format!(
            "{} {} {} {} {} {} {}\n",
            row.pid,
            row.parent,
            row.group,
            row.uid,
            row.gid,
            birth,
            std::str::from_utf8(command).map_err(|_| refused())?
        ),
        BYTES,
        deadline,
    )
}

// OpenBSD KERN_PROC_ARGV returns a native pointer table into this same caller
// buffer followed by NUL-terminated argument bytes. Never dereference a kernel
// returned pointer: convert checked offsets and inspect only this owned slice.
pub(crate) fn arguments(
    raw: &[u8],
    address: usize,
    cap: usize,
    deadline: Instant,
) -> io::Result<String> {
    before(deadline)?;
    let word = std::mem::size_of::<usize>();
    if raw.len() > BYTES || raw.len() < word * 2 || word != 8 {
        return Err(refused());
    }
    let mut offsets = Vec::new();
    let mut table_end = None;
    for (index, bytes) in raw.chunks_exact(word).take(ROWS + 1).enumerate() {
        before(deadline)?;
        let pointer = usize::from_ne_bytes(bytes.try_into().map_err(|_| refused())?);
        if pointer == 0 {
            table_end = Some((index + 1) * word);
            break;
        }
        offsets.push(pointer.checked_sub(address).ok_or_else(refused)?);
    }
    let mut next = table_end.ok_or_else(refused)?;
    if offsets.is_empty() || offsets.len() > ROWS {
        return Err(refused());
    }
    let mut result = String::new();
    for (index, offset) in offsets.into_iter().enumerate() {
        before(deadline)?;
        if offset != next || offset >= raw.len() {
            return Err(refused());
        }
        let tail = &raw[offset..];
        let size = tail.iter().position(|b| *b == 0).ok_or_else(refused)?;
        let value = &tail[..size];
        if value.iter().any(|b| !matches!(b, 0x20..=0x7e)) {
            return Err(refused());
        }
        if index != 0 {
            result.push(' ');
        }
        result.push_str(std::str::from_utf8(value).map_err(|_| refused())?);
        next = offset.checked_add(size + 1).ok_or_else(refused)?;
    }
    if next != raw.len() {
        return Err(refused());
    }
    result.push('\n');
    bounded(result, cap, deadline)
}

pub(crate) fn row_count(length: usize, capacity: usize, width: usize) -> io::Result<usize> {
    if width == 0 || length == 0 || length > capacity || length % width != 0 {
        Err(refused())
    } else {
        let count = length / width;
        if count > ROWS {
            Err(refused())
        } else {
            Ok(count)
        }
    }
}

#[cfg(test)]
#[path = "account_password_metadata_tests.rs"]
mod tests;
