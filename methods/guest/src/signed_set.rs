//! SPEC.md §4 step 5 — construct the canonicalized header set that gets
//! SHA-256'd and RSA-verified in §4.6.
//!
//! Per RFC 6376 §5.4:
//!   1. For each header field name in the `h=` tag (in the order they
//!      appear), find the corresponding header in the email above the
//!      DKIM-Signature, canonicalize it (relaxed), append to output.
//!      Multiple occurrences of the same name in `h=` consume successive
//!      occurrences top-to-bottom in the email (§5.4.2). A name in `h=`
//!      that does not match any header is treated as an empty value
//!      (§5.4 paragraph "Signers MAY claim ...").
//!
//!   2. Append the canonicalized DKIM-Signature header with the `b=` tag
//!      value emptied and NO trailing CRLF (§3.7 and §5.4 step 2).

use crate::body;
use crate::bytes_util::{bytes_eq_case_insensitive, strip_trailing_crlf, trim_wsp_crlf};
use crate::canonical;

/// SPEC.md §4 step 5. Returns the bytes that get SHA-256'd in §4.6.
pub fn build_signed_data(
    email: &[u8],
    h_tag_value: &[u8],
    dkim_header_start: usize,
    dkim_header_end: usize,
) -> Vec<u8> {
    let mut output = Vec::new();

    // RFC 6376 §5.4 says verifier consumes occurrences of each h= name
    // top-to-bottom across the FULL header block, treating missing
    // occurrences as null strings. In practice real-world DKIM signers
    // (Gmail tested here) and verifiers (dkimpy) instead search
    // bottom-to-top with a per-name lastindex cursor, and SKIP missing
    // occurrences rather than emitting empty `name:\r\n` placeholders.
    // Match real-world behavior so we can actually verify real emails;
    // the soundness story is unchanged because oversigning still works
    // (the signer just doesn't emit empty rows for missing names).
    let body_start = body::find_body_start(email);
    let headers = parse_headers(&email[..body_start]);

    // h= can be folded across lines, leaving CRLF + WSP inside a split piece.
    let names: Vec<&[u8]> = h_tag_value
        .split(|&c| c == b':')
        .map(trim_wsp_crlf)
        .filter(|n| !n.is_empty())
        .collect();

    // dkimpy-style: for each name in h=, scan headers from `lastindex[name]`
    // (default = headers.len()) downward, find the first match, append, and
    // update lastindex to the matched position.
    let mut last_index: Vec<(Vec<u8>, usize)> = Vec::new();
    for include_name in &names {
        let lc: Vec<u8> = include_name.iter().map(|b| b.to_ascii_lowercase()).collect();
        let mut i = last_index
            .iter()
            .find(|(k, _)| *k == lc)
            .map(|(_, v)| *v)
            .unwrap_or(headers.len());
        let mut matched: Option<usize> = None;
        while i > 0 {
            i -= 1;
            if bytes_eq_case_insensitive(headers[i].name, include_name) {
                matched = Some(i);
                break;
            }
        }
        if let Some(idx) = matched {
            let h = &headers[idx];
            let canonicalized = canonical::canonicalize_header_relaxed(h.name, h.value);
            output.extend_from_slice(&canonicalized);
            if let Some(entry) = last_index.iter_mut().find(|(k, _)| *k == lc) {
                entry.1 = idx;
            } else {
                last_index.push((lc, idx));
            }
        }
        // If no match, skip (NOT emit empty). Matches dkimpy and real signers.
    }

    // Append the DKIM-Signature header with b= emptied, no trailing CRLF.
    let dkim_header = &email[dkim_header_start..dkim_header_end];
    let (name, value) = split_header_name_value(dkim_header);
    let canonicalized = canonical::canonicalize_header_relaxed(name, value);
    let b_emptied = null_b_tag(&canonicalized);
    let no_crlf = strip_trailing_crlf(&b_emptied);
    output.extend_from_slice(no_crlf);

    output
}

/// v1 design §4.9. True if `name` (lowercase) is one of the header field
/// names listed in the `h=` tag value, i.e. the header is covered by the
/// DKIM signature. Case-insensitive; tolerates folding WSP/CRLF in `h=`.
pub fn h_contains(h_tag_value: &[u8], name: &[u8]) -> bool {
    h_tag_value
        .split(|&c| c == b':')
        .map(trim_wsp_crlf)
        .filter(|n| !n.is_empty())
        .any(|n| bytes_eq_case_insensitive(n, name))
}

/// v1 design §4.9. Return the raw value bytes of the **bottom-most** header
/// in the message header block matching `name` (case-insensitive). For a
/// header listed once in `h=`, that bottom-most occurrence is exactly the
/// instance the signature covers (RFC 6376 §5.4.2 bottom-up selection, as
/// implemented in `build_signed_data`). Reading the signed instance — never
/// an unsigned prepended duplicate — is what makes disclosure header-prepend
/// safe: a `From:` prepended above the signed one is not returned here, and a
/// `From:` appended below it would change the signed data and fail RSA verify.
///
/// Returns `None` if no header with that name exists in the block.
///
/// Parses the *entire* header block (same as `build_signed_data`), so the
/// instance returned here is byte-identical to the one `build_signed_data`
/// fed to RSA for this name's first `h=` mention. That consistency is what
/// guarantees we disclose exactly the signed bytes.
pub fn signed_header_value(email: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    let body_start = body::find_body_start(email);
    let headers = parse_headers(&email[..body_start]);
    headers
        .iter()
        .rev()
        .find(|h| bytes_eq_case_insensitive(h.name, name))
        .map(|h| h.value.to_vec())
}

// -- helpers ---------------------------------------------------------------

/// One parsed header from the message header block: name (case preserved)
/// and value (no leading WSP unstripped, no trailing CRLF; continuation
/// CRLF+WSP preserved so the canonicalizer unfolds them).
struct ParsedHeader<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

/// Parse the header block into individual headers in message order.
fn parse_headers(headers_block: &[u8]) -> Vec<ParsedHeader<'_>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < headers_block.len() {
        let line_end = find_field_end(headers_block, i);
        if let Some(c) = headers_block[i..line_end].iter().position(|&b| b == b':') {
            let name = &headers_block[i..i + c];
            let value_start = i + c + 1;
            let value_end = if line_end >= 2 && &headers_block[line_end - 2..line_end] == b"\r\n" {
                line_end - 2
            } else {
                line_end
            };
            out.push(ParsedHeader {
                name,
                value: &headers_block[value_start..value_end],
            });
        }
        i = line_end;
    }
    out
}

/// RFC 5322 header bound: end of header = CRLF not followed by WSP, or EOF.
fn find_field_end(block: &[u8], from: usize) -> usize {
    let mut i = from;
    while i + 1 < block.len() {
        if block[i] == b'\r' && block[i + 1] == b'\n' {
            let next = i + 2;
            if next >= block.len() || (block[next] != b' ' && block[next] != b'\t') {
                return next;
            }
        }
        i += 1;
    }
    block.len()
}

/// Split a single complete header (name:value...CRLF) into name and value.
fn split_header_name_value(header: &[u8]) -> (&[u8], &[u8]) {
    let colon = header.iter().position(|&c| c == b':').expect("header has no colon");
    let name = &header[..colon];
    let value_end = if header.len() >= 2 && &header[header.len() - 2..] == b"\r\n" {
        header.len() - 2
    } else {
        header.len()
    };
    let value = &header[colon + 1..value_end];
    (name, value)
}

/// Given a canonicalized header (name:value\r\n or name:value), produce a
/// copy with the `b=` tag value emptied. Used per RFC 6376 §3.7 to compute
/// the DKIM-Signature contribution to the signed data.
fn null_b_tag(canonicalized: &[u8]) -> Vec<u8> {
    let colon = canonicalized.iter().position(|&c| c == b':').expect("no colon");
    let mut out = Vec::with_capacity(canonicalized.len());
    out.extend_from_slice(&canonicalized[..=colon]);

    let value_part = &canonicalized[colon + 1..];
    let (vp, trailing) = if value_part.ends_with(b"\r\n") {
        (&value_part[..value_part.len() - 2], &b"\r\n"[..])
    } else {
        (value_part, &b""[..])
    };

    let pieces: Vec<&[u8]> = vp.split(|&c| c == b';').collect();
    for (idx, piece) in pieces.iter().enumerate() {
        if idx > 0 {
            out.push(b';');
        }
        if let Some(eq) = piece.iter().position(|&c| c == b'=') {
            let tag_name = trim_wsp_crlf(&piece[..eq]);
            if tag_name == b"b" {
                out.extend_from_slice(&piece[..=eq]);
                // value dropped
            } else {
                out.extend_from_slice(piece);
            }
        } else {
            out.extend_from_slice(piece);
        }
    }
    out.extend_from_slice(trailing);
    out
}

// -- unit tests ------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds (email_bytes, dkim_start, dkim_end) for tests.
    fn make_email(headers_before: &[u8], dkim: &[u8], body: &[u8]) -> (Vec<u8>, usize, usize) {
        let mut email = Vec::new();
        email.extend_from_slice(headers_before);
        let dkim_start = email.len();
        email.extend_from_slice(dkim);
        let dkim_end = email.len();
        email.extend_from_slice(b"\r\n");
        email.extend_from_slice(body);
        (email, dkim_start, dkim_end)
    }

    #[test]
    fn single_header_canonicalized_and_appended() {
        let (email, ds, de) = make_email(
            b"From: alice@example.com\r\n",
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; \
              d=example.com; s=sel; h=From; bh=xx; b=signature\r\n",
            b"body",
        );
        let out = build_signed_data(&email, b"From", ds, de);
        let expected = b"from:alice@example.com\r\n\
                         dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; \
d=example.com; s=sel; h=From; bh=xx; b=";
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn multiple_headers_in_h_tag() {
        let (email, ds, de) = make_email(
            b"From: a@b\r\nTo: c@d\r\nSubject: hi\r\n",
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; \
              d=example.com; s=sel; h=From:To:Subject; bh=xx; b=sig\r\n",
            b"body",
        );
        let out = build_signed_data(&email, b"From:To:Subject", ds, de);
        // Each header canonicalized in h= order, then DKIM-Signature with b= empty no CRLF.
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("from:a@b\r\nto:c@d\r\nsubject:hi\r\n"));
        assert!(s.ends_with("b="));
        assert!(s.contains("dkim-signature:"));
    }

    #[test]
    fn missing_header_in_h_tag_is_skipped() {
        // dkimpy-style: a name in h= that doesn't match any header is SKIPPED,
        // not emitted as empty. Matches real-world signers (Gmail, etc.).
        // RFC 6376 §5.4 text says "treat as null string" but the practical
        // convention diverges.
        let (email, ds, de) = make_email(
            b"From: a@b\r\n",
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; \
              d=example.com; s=sel; h=From:Date; bh=xx; b=sig\r\n",
            b"body",
        );
        let out = build_signed_data(&email, b"From:Date", ds, de);
        let s = std::str::from_utf8(&out).unwrap();
        // "from:a@b\r\n" then directly DKIM-Signature (no "date:\r\n" inserted).
        assert!(s.starts_with("from:a@b\r\ndkim-signature:"), "got: {:?}", &s[..s.len().min(60)]);
    }

    #[test]
    fn multiple_occurrences_bottom_to_top() {
        // dkimpy convention: with two From headers and h=From:From, the FIRST
        // mention in h= picks the LAST occurrence in the message (bottom), the
        // SECOND mention picks the one above it. Matches dkimpy's select_headers.
        let (email, ds, de) = make_email(
            b"From: first@x\r\nFrom: second@y\r\n",
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; \
              d=example.com; s=sel; h=From:From; bh=xx; b=sig\r\n",
            b"body",
        );
        let out = build_signed_data(&email, b"From:From", ds, de);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("from:second@y\r\nfrom:first@x\r\n"));
    }

    #[test]
    fn case_insensitive_header_name_match() {
        // The email header is "from:" (lowercase), the h= value names "FROM"
        // (uppercase). Matching is case-insensitive, and relaxed
        // canonicalization always lowercases the field name in the output.
        let (email, ds, de) = make_email(
            b"from: lowercase@x\r\n",
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; \
              d=example.com; s=sel; h=FROM; bh=xx; b=sig\r\n",
            b"body",
        );
        let out = build_signed_data(&email, b"FROM", ds, de);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("from:lowercase@x\r\n"));
    }

    #[test]
    fn null_b_tag_with_b_at_end() {
        // canonicalized: "dkim-signature:v=1; b=abc"
        let inp = b"dkim-signature:v=1; b=abc\r\n";
        let out = null_b_tag(inp);
        assert_eq!(out, b"dkim-signature:v=1; b=\r\n");
    }

    #[test]
    fn null_b_tag_with_b_in_middle() {
        let inp = b"dkim-signature:v=1; b=abc; bh=xyz\r\n";
        let out = null_b_tag(inp);
        assert_eq!(out, b"dkim-signature:v=1; b=; bh=xyz\r\n");
    }

    #[test]
    fn null_b_tag_with_b_first_tag() {
        let inp = b"dkim-signature:b=abc; v=1\r\n";
        let out = null_b_tag(inp);
        assert_eq!(out, b"dkim-signature:b=; v=1\r\n");
    }

    #[test]
    fn null_b_tag_does_not_touch_bh_tag() {
        // The tag name 'bh' shares a prefix with 'b' but is a different tag.
        let inp = b"dkim-signature:v=1; bh=xyz; b=abc\r\n";
        let out = null_b_tag(inp);
        assert_eq!(out, b"dkim-signature:v=1; bh=xyz; b=\r\n");
    }

    #[test]
    fn parse_headers_extracts_name_and_value() {
        let block = b"From: alice@x\r\nTo: bob@y\r\n";
        let h = parse_headers(block);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].name, b"From");
        assert_eq!(h[0].value, b" alice@x");
        assert_eq!(h[1].name, b"To");
        assert_eq!(h[1].value, b" bob@y");
    }

    #[test]
    fn h_contains_matches_case_insensitively_and_tolerates_wsp() {
        assert!(h_contains(b"from : to : subject : date", b"from"));
        assert!(h_contains(b"From:To:Subject", b"to"));
        assert!(!h_contains(b"to:subject:date", b"from"));
    }

    #[test]
    fn signed_header_value_returns_bottom_most_instance() {
        // Two From headers (a prepended attacker line above the real one).
        // Bottom-most = the signed instance.
        let email = b"From: attacker@evil.test\r\n\
                      From: real@corp.test\r\n\
                      To: ops@corp.test\r\n\
                      \r\nbody";
        assert_eq!(
            signed_header_value(email, b"from").unwrap(),
            b" real@corp.test".to_vec()
        );
        assert_eq!(
            signed_header_value(email, b"to").unwrap(),
            b" ops@corp.test".to_vec()
        );
        assert!(signed_header_value(email, b"subject").is_none());
    }

    #[test]
    fn output_ends_without_crlf() {
        // The DKIM-Signature canonicalized chunk MUST NOT end with CRLF
        // (RFC 6376 §3.7 / §5.4 step 2).
        let (email, ds, de) = make_email(
            b"From: a@b\r\n",
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; \
              d=example.com; s=sel; h=From; bh=xx; b=sig\r\n",
            b"body",
        );
        let out = build_signed_data(&email, b"From", ds, de);
        assert!(!out.ends_with(b"\r\n"), "signed data must not end with CRLF");
    }
}
