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

use crate::bytes_util::{bytes_eq_case_insensitive, strip_trailing_crlf, trim_wsp};
use crate::canonical;

/// SPEC.md §4 step 5. Returns the bytes that get SHA-256'd in §4.6.
pub fn build_signed_data(
    email: &[u8],
    h_tag_value: &[u8],
    dkim_header_start: usize,
    dkim_header_end: usize,
) -> Vec<u8> {
    let mut output = Vec::new();

    // Per §5.4.2 the verifier consumes occurrences top-to-bottom; we look
    // only at headers above DKIM-Signature so an attacker cannot inject a
    // duplicate header below it and influence the signed set.
    let headers_above = &email[..dkim_header_start];

    let names: Vec<&[u8]> = h_tag_value
        .split(|&c| c == b':')
        .map(trim_wsp)
        .filter(|n| !n.is_empty())
        .collect();

    // Track how many of each name we've already consumed. h= typically has
    // 5..10 names; a linear scan beats a HashMap for both readability and
    // line count.
    let mut counts: Vec<(Vec<u8>, usize)> = Vec::new();

    for name in &names {
        let lc: Vec<u8> = name.iter().map(|b| b.to_ascii_lowercase()).collect();
        let n = counts.iter().find(|(k, _)| *k == lc).map(|(_, v)| *v).unwrap_or(0);
        let value = find_nth_header_value(headers_above, name, n).unwrap_or(&[]);
        let canonicalized = canonical::canonicalize_header_relaxed(name, value);
        output.extend_from_slice(&canonicalized);
        if let Some(entry) = counts.iter_mut().find(|(k, _)| *k == lc) {
            entry.1 += 1;
        } else {
            counts.push((lc, 1));
        }
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

// -- helpers ---------------------------------------------------------------

/// Return the value bytes of the `n`-th (0-indexed) occurrence of a header
/// named `name` (case-insensitive) in `headers_block`. Value is the bytes
/// after the colon, before the trailing CRLF, with internal continuation
/// CRLFs preserved (canonicalization handles them).
fn find_nth_header_value<'a>(
    headers_block: &'a [u8],
    name: &[u8],
    n: usize,
) -> Option<&'a [u8]> {
    let mut found = 0;
    let mut i = 0;
    while i < headers_block.len() {
        let line_end = find_field_end(headers_block, i);
        if let Some(c) = headers_block[i..line_end].iter().position(|&b| b == b':') {
            let this_name = &headers_block[i..i + c];
            if bytes_eq_case_insensitive(this_name, name) {
                if found == n {
                    let value_start = i + c + 1;
                    let value_end = if line_end >= 2 && &headers_block[line_end - 2..line_end] == b"\r\n" {
                        line_end - 2
                    } else {
                        line_end
                    };
                    return Some(&headers_block[value_start..value_end]);
                }
                found += 1;
            }
        }
        i = line_end;
    }
    None
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
            let tag_name = trim_wsp(&piece[..eq]);
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
    fn missing_header_in_h_tag_is_empty() {
        // h= names a header that doesn't appear in the email — RFC 6376 says
        // treat as empty.
        let (email, ds, de) = make_email(
            b"From: a@b\r\n",
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; \
              d=example.com; s=sel; h=From:Date; bh=xx; b=sig\r\n",
            b"body",
        );
        let out = build_signed_data(&email, b"From:Date", ds, de);
        let s = std::str::from_utf8(&out).unwrap();
        // "from:a@b\r\n" then "date:\r\n" then DKIM-Signature
        assert!(s.starts_with("from:a@b\r\ndate:\r\n"));
    }

    #[test]
    fn multiple_occurrences_top_to_bottom() {
        // Two From headers; h=From:From should pick first, then second.
        let (email, ds, de) = make_email(
            b"From: first@x\r\nFrom: second@y\r\n",
            b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; \
              d=example.com; s=sel; h=From:From; bh=xx; b=sig\r\n",
            b"body",
        );
        let out = build_signed_data(&email, b"From:From", ds, de);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("from:first@x\r\nfrom:second@y\r\n"));
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
    fn find_nth_header_value_zeroth() {
        let block = b"From: alice@x\r\nTo: bob@y\r\n";
        let v = find_nth_header_value(block, b"From", 0).unwrap();
        assert_eq!(v, b" alice@x");
    }

    #[test]
    fn find_nth_header_value_missing() {
        let block = b"From: alice@x\r\n";
        assert!(find_nth_header_value(block, b"Subject", 0).is_none());
    }

    #[test]
    fn find_nth_header_value_first_occurrence_of_two() {
        let block = b"From: a@x\r\nFrom: b@y\r\n";
        let v0 = find_nth_header_value(block, b"From", 0).unwrap();
        let v1 = find_nth_header_value(block, b"From", 1).unwrap();
        assert_eq!(v0, b" a@x");
        assert_eq!(v1, b" b@y");
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
