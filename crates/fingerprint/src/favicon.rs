use std::io::Cursor;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// Compute the Shodan-style favicon hash of raw icon bytes.
///
/// The algorithm (matching Shodan / most Chinese ASM tooling):
/// 1. base64-encode the bytes the way Python's `base64.encodebytes` does — a
///    newline every 76 characters *and* a trailing newline.
/// 2. murmur3 x86 32-bit hash (seed 0) of that ASCII text.
/// 3. reinterpret the u32 as a signed i32 (the value people paste into
///    `http.favicon.hash:` queries).
pub fn favicon_hash(icon: &[u8]) -> i32 {
    let b64 = encodebytes(icon);
    // murmur3_32 reads from a `Read`; encoding is ASCII so bytes == chars.
    let hash = murmur3::murmur3_32(&mut Cursor::new(b64.as_bytes()), 0)
        .expect("in-memory cursor reads are infallible");
    hash as i32
}

/// Mirror of Python `base64.encodebytes`: standard base64 with a `\n` inserted
/// every 76 output characters and a trailing `\n`.
fn encodebytes(data: &[u8]) -> String {
    let raw = STANDARD.encode(data);
    let mut out = String::with_capacity(raw.len() + raw.len() / 76 + 1);
    for chunk in raw.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    if out.is_empty() {
        // encodebytes(b"") == b"\n"
        out.push('\n');
    }
    out
}

/// Illustrative known-favicon-hash → product map. Real deployments extend this
/// from a fingerprint database (e.g. FingerprintHub). Entries here are examples
/// of the shape, not an authoritative list.
pub fn product_for_favicon(hash: i32) -> Option<&'static str> {
    match hash {
        116323821 => Some("Apache Tomcat"),
        -1521040127 => Some("Gitea"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_matches_python_encodebytes() {
        // Python: base64.encodebytes(b"") == b"\n"
        assert_eq!(encodebytes(b""), "\n");
    }

    #[test]
    fn wraps_at_76_chars_with_trailing_newline() {
        // 60 bytes -> 80 base64 chars -> one wrap at 76 + trailing newline.
        let s = encodebytes(&[0u8; 60]);
        assert_eq!(s.matches('\n').count(), 2);
        assert!(s.lines().next().unwrap().len() == 76);
    }

    #[test]
    fn hash_is_deterministic_and_input_sensitive() {
        let a = favicon_hash(b"\x00\x01\x02 favicon bytes");
        let b = favicon_hash(b"\x00\x01\x02 favicon bytes");
        let c = favicon_hash(b"different bytes");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
