// Encode synthetic LIST names exactly as a real IMAP server does.
pub(super) fn wire_name(name: &str) -> String {
    const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";
    let mut out = String::new();
    let mut run = Vec::new();
    let flush = |out: &mut String, run: &mut Vec<u8>| {
        if run.is_empty() { return; }
        out.push('&');
        let (mut bits, mut count) = (0u32, 0u32);
        for byte in run.drain(..) {
            bits = (bits << 8) | u32::from(byte);
            count += 8;
            while count >= 6 {
                count -= 6;
                out.push(char::from(BASE64[((bits >> count) & 63) as usize]));
            }
            bits &= (1 << count) - 1;
        }
        if count > 0 { out.push(char::from(BASE64[((bits << (6 - count)) & 63) as usize])); }
        out.push('-');
    };
    for ch in name.chars() {
        if ch.is_ascii() {
            flush(&mut out, &mut run);
            if ch == '&' { out.push_str("&-"); } else { out.push(ch); }
        } else {
            for unit in ch.encode_utf16(&mut [0; 2]) { run.extend_from_slice(&unit.to_be_bytes()); }
        }
    }
    flush(&mut out, &mut run);
    serde_json::to_string(&out).unwrap()
}
