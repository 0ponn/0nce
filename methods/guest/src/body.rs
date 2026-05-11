//! SPEC.md §4 step 4: SHA-256 the canonicalized body, assert equality with
//! `bh` from the DKIM-Signature header.
//!
//! Also exposes `find_body_start` for callers that need to locate the
//! body region within an RFC 5322 message. The body begins immediately
//! after the first `\r\n\r\n` (the header/body separator).

use sha2::{Digest, Sha256};

use crate::canonical;

/// Returns the byte offset of the first byte of the body within `email`.
///
/// RFC 5322: headers and body are separated by an empty line, i.e. the
/// first occurrence of `\r\n\r\n`. Body starts at the byte immediately
/// after. If no separator is found, the message has no body and this
/// returns `email.len()`.
pub fn find_body_start(email: &[u8]) -> usize {
    let mut i = 0;
    while i + 3 < email.len() {
        if &email[i..i + 4] == b"\r\n\r\n" {
            return i + 4;
        }
        i += 1;
    }
    email.len()
}

/// SPEC.md §4 step 4.
///
/// Locates the body in `email`, applies relaxed body canonicalization
/// (RFC 6376 §3.4.4), SHA-256s the result, and asserts byte-equality
/// with `expected_body_hash`, which is the base64-decoded `bh` from
/// the §4.2 parser.
///
/// Panics (= guest aborts = no proof) on mismatch. SPEC.md §7 must-pass
/// #4 (`email_with_tampered_body_bh_mismatch_guest_panics`) is the test
/// that exercises this path.
pub fn verify_body_hash(email: &[u8], expected_body_hash: &[u8]) {
    let body_start = find_body_start(email);
    let body = &email[body_start..];
    let canonical_body = canonical::canonicalize_body_relaxed(body);
    let computed = Sha256::digest(&canonical_body);
    assert_eq!(
        computed.as_slice(),
        expected_body_hash,
        "computed body hash does not match bh"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256(data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }

    // -- find_body_start --

    #[test]
    fn find_body_start_after_separator() {
        let email = b"From: a@b\r\nSubject: x\r\n\r\nHello body\r\n";
        let start = find_body_start(email);
        assert_eq!(&email[start..], b"Hello body\r\n");
    }

    #[test]
    fn find_body_start_no_separator() {
        // No CRLF CRLF found, message is effectively all-headers, no body.
        let email = b"From: a@b\r\nSubject: x\r\n";
        assert_eq!(find_body_start(email), email.len());
    }

    #[test]
    fn find_body_start_empty_body_after_separator() {
        // Separator present, but nothing after it.
        let email = b"From: a@b\r\n\r\n";
        assert_eq!(find_body_start(email), email.len());
    }

    #[test]
    fn find_body_start_handles_separator_at_start() {
        // Pathological: no headers at all, message is just the separator
        // plus body.
        let email = b"\r\n\r\nBody";
        let start = find_body_start(email);
        assert_eq!(&email[start..], b"Body");
    }

    // -- verify_body_hash --

    #[test]
    fn verify_body_hash_matches_normal_body() {
        let email = b"From: a@b\r\n\r\nHello body\r\n";
        // The body "Hello body\r\n" canonicalizes to itself.
        let expected = sha256(b"Hello body\r\n");
        verify_body_hash(email, &expected);
    }

    #[test]
    fn verify_body_hash_matches_empty_body() {
        // RFC 6376 §3.4.3/§3.4.4: empty body canonicalizes to b"\r\n".
        let email = b"From: a@b\r\n\r\n";
        let expected = sha256(b"\r\n");
        verify_body_hash(email, &expected);
    }

    #[test]
    fn verify_body_hash_matches_canonicalized_body() {
        // Body has internal WSP that canonicalization collapses; `bh` must
        // reflect the canonicalized form, not the raw bytes.
        let email = b"From: a@b\r\n\r\nHello   world\t\t!\r\n";
        let expected = sha256(b"Hello world !\r\n");
        verify_body_hash(email, &expected);
    }

    #[test]
    #[should_panic(expected = "computed body hash does not match bh")]
    fn verify_body_hash_panics_on_tampered_body() {
        // SPEC.md §7 must-pass #4 path.
        let email = b"From: a@b\r\n\r\nHello body\r\n";
        let wrong_bh = sha256(b"different content");
        verify_body_hash(email, &wrong_bh);
    }

    #[test]
    #[should_panic(expected = "computed body hash does not match bh")]
    fn verify_body_hash_panics_on_wrong_size_bh() {
        // Defensive: even an obviously-wrong-size bh must fail clearly,
        // not silently truncate or match a prefix.
        let email = b"From: a@b\r\n\r\nHello\r\n";
        verify_body_hash(email, b"too short");
    }
}
