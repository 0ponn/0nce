//! SPEC.md §4 step 3 — relaxed/relaxed canonicalization (RFC 6376 §3.4).
//!
//! Two pure functions:
//!   - [`canonicalize_header_relaxed`] for RFC 6376 §3.4.2
//!   - [`canonicalize_body_relaxed`]   for RFC 6376 §3.4.4
//!
//! v0 supports only `relaxed/relaxed`. The caller (the guest pipeline) is
//! responsible for asserting `c=relaxed/relaxed` before invoking these
//! functions; this module assumes that check has passed.
//!
//! Implementation notes:
//!   - Byte-level only. No UTF-8 assumptions. RFC 5322 is 7-bit ASCII for
//!     header field names; values may contain 8-bit data with appropriate
//!     transfer encoding, but canonicalization is byte-level either way.
//!   - WSP per RFC 5234: SP (0x20) and HTAB (0x09).
//!   - CRLF per RFC 5322: the two-byte sequence 0x0D 0x0A.

/// Apply RFC 6376 §3.4.2 "relaxed" header canonicalization to a single
/// header field, returning the canonicalized bytes including the final CRLF.
///
/// `name` is the field name (e.g. `b"Subject"`), without the trailing colon.
/// `value` is the field value, WITHOUT the trailing CRLF that terminates the
/// header in the original message. Internal CRLFs (continuation folding) MUST
/// remain in `value` and will be unfolded by this function.
///
/// RFC 6376 §3.4.2 algorithm, in order:
///   1. Lowercase the field name.
///   2. Unfold continuation lines (CRLF followed by WSP → WSP only).
///   3. Collapse all WSP runs (across the now-unfolded value) to a single SP.
///   4. Strip WSP at end of value.
///   5. Strip WSP around the colon (i.e. strip leading WSP of the value;
///      the field name has no trailing WSP by construction).
///
/// Output format: `<lowercased name>`:`<canonicalized value>`\r\n
pub fn canonicalize_header_relaxed(name: &[u8], value: &[u8]) -> Vec<u8> {
    let unfolded = unfold(value);
    let collapsed = collapse_wsp(&unfolded);
    let trimmed = trim_wsp(&collapsed);

    let mut out = Vec::with_capacity(name.len() + 1 + trimmed.len() + 2);
    for &b in name {
        out.push(b.to_ascii_lowercase());
    }
    out.push(b':');
    out.extend_from_slice(trimmed);
    out.extend_from_slice(b"\r\n");
    out
}

/// Apply RFC 6376 §3.4.4 "relaxed" body canonicalization.
///
/// Algorithm:
///   1. For each line (split by CRLF): collapse WSP runs to a single SP, then
///      strip trailing WSP.
///   2. Ignore all empty lines at the end of the message body.
///   3. If the resulting body is non-empty, terminate it with exactly one
///      CRLF. If empty, the canonicalized body is empty (zero bytes).
///
/// Note: RFC 6376 §3.4.3 (simple canonicalization) and §3.4.4 (relaxed) both
/// specify that "an empty body is canonicalized as a single CRLF." This is
/// frequently misread. The v0 reading: a body with no non-empty lines yields
/// zero bytes here, and the caller (the SHA-256 step) must handle the
/// "empty body" convention if it matters for `bh` matching. The SPEC.md §4.4
/// assertion `SHA-256(canonicalized body) == bh` is what closes the loop —
/// real DKIM signers vary in how they handle empty bodies, so the test
/// suite (§7) is the final arbiter of correctness here.
pub fn canonicalize_body_relaxed(body: &[u8]) -> Vec<u8> {
    // Split on CRLF. A trailing CRLF produces a final empty line which we'll
    // strip; a body with no trailing CRLF puts its last partial line in the
    // vec — that's fine, we still process it the same way.
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i + 1 < body.len() {
        if body[i] == b'\r' && body[i + 1] == b'\n' {
            lines.push(&body[start..i]);
            start = i + 2;
            i += 2;
        } else {
            i += 1;
        }
    }
    if start < body.len() {
        lines.push(&body[start..]);
    }

    // Process each line.
    let mut processed: Vec<Vec<u8>> = lines
        .into_iter()
        .map(|line| {
            let collapsed = collapse_wsp(line);
            strip_trailing_wsp(&collapsed).to_vec()
        })
        .collect();

    // Strip trailing empty lines.
    while processed.last().map_or(false, |l| l.is_empty()) {
        processed.pop();
    }

    // Rejoin with CRLF, append final CRLF if non-empty.
    let mut out = Vec::new();
    for (idx, line) in processed.iter().enumerate() {
        if idx > 0 {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(line);
    }
    if !processed.is_empty() {
        out.extend_from_slice(b"\r\n");
    }
    out
}

// --- internal helpers ------------------------------------------------------

/// Replace each `CRLF WSP` sequence with a single SP. Returns a new Vec.
/// (Subsequent WSP after the unfold boundary is left in place; the caller's
/// next step is collapse_wsp which deals with runs.)
fn unfold(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if i + 2 < input.len()
            && input[i] == b'\r'
            && input[i + 1] == b'\n'
            && is_wsp(input[i + 2])
        {
            // Drop CRLF, keep the following WSP byte verbatim.
            out.push(input[i + 2]);
            i += 3;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

/// Collapse any run of WSP (SP or HTAB) to a single SP.
fn collapse_wsp(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut in_wsp = false;
    for &b in input {
        if is_wsp(b) {
            if !in_wsp {
                out.push(b' ');
                in_wsp = true;
            }
        } else {
            out.push(b);
            in_wsp = false;
        }
    }
    out
}

/// Strip leading and trailing WSP.
fn trim_wsp(input: &[u8]) -> &[u8] {
    let start = input.iter().position(|&b| !is_wsp(b)).unwrap_or(input.len());
    let end = input
        .iter()
        .rposition(|&b| !is_wsp(b))
        .map(|i| i + 1)
        .unwrap_or(0);
    if start <= end {
        &input[start..end]
    } else {
        &[]
    }
}

/// Strip trailing WSP only.
fn strip_trailing_wsp(input: &[u8]) -> &[u8] {
    let end = input
        .iter()
        .rposition(|&b| !is_wsp(b))
        .map(|i| i + 1)
        .unwrap_or(0);
    &input[..end]
}

#[inline]
fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

// --- unit tests ------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- header canonicalization --

    #[test]
    fn header_lowercases_field_name() {
        assert_eq!(
            canonicalize_header_relaxed(b"From", b"alice@example.com"),
            b"from:alice@example.com\r\n".to_vec()
        );
    }

    #[test]
    fn header_preserves_value_case() {
        assert_eq!(
            canonicalize_header_relaxed(b"SUBJECT", b"AbC"),
            b"subject:AbC\r\n".to_vec()
        );
    }

    #[test]
    fn header_collapses_internal_whitespace() {
        assert_eq!(
            canonicalize_header_relaxed(b"Subject", b"hello   world\t\tfoo"),
            b"subject:hello world foo\r\n".to_vec()
        );
    }

    #[test]
    fn header_strips_leading_wsp_after_colon() {
        // "From:  alice" → "from:alice"
        assert_eq!(
            canonicalize_header_relaxed(b"From", b"  alice@example.com"),
            b"from:alice@example.com\r\n".to_vec()
        );
    }

    #[test]
    fn header_strips_trailing_wsp() {
        assert_eq!(
            canonicalize_header_relaxed(b"From", b"alice@example.com   \t"),
            b"from:alice@example.com\r\n".to_vec()
        );
    }

    #[test]
    fn header_unfolds_continuation_line() {
        // Value with internal CRLF + WSP (a folded continuation line) must
        // unfold and collapse to a single SP between the parts.
        assert_eq!(
            canonicalize_header_relaxed(b"B", b"Y\r\n\tZ  "),
            b"b:Y Z\r\n".to_vec()
        );
    }

    #[test]
    fn header_unfolds_multiple_continuations() {
        assert_eq!(
            canonicalize_header_relaxed(b"H", b"a\r\n b\r\n  c"),
            b"h:a b c\r\n".to_vec()
        );
    }

    #[test]
    fn header_empty_value() {
        assert_eq!(
            canonicalize_header_relaxed(b"X-Empty", b""),
            b"x-empty:\r\n".to_vec()
        );
    }

    // -- body canonicalization --

    #[test]
    fn body_empty_is_empty() {
        assert_eq!(canonicalize_body_relaxed(b""), b"".to_vec());
    }

    #[test]
    fn body_only_crlfs_is_empty() {
        // All trailing empty lines stripped → empty body → zero bytes.
        assert_eq!(canonicalize_body_relaxed(b"\r\n\r\n\r\n"), b"".to_vec());
    }

    #[test]
    fn body_single_line_gets_terminating_crlf() {
        assert_eq!(
            canonicalize_body_relaxed(b"Hello\r\n"),
            b"Hello\r\n".to_vec()
        );
    }

    #[test]
    fn body_trailing_empty_lines_stripped() {
        assert_eq!(
            canonicalize_body_relaxed(b"Hello\r\n\r\n\r\n"),
            b"Hello\r\n".to_vec()
        );
    }

    #[test]
    fn body_strips_trailing_wsp_per_line() {
        assert_eq!(
            canonicalize_body_relaxed(b"Hello   \r\nWorld\t\r\n"),
            b"Hello\r\nWorld\r\n".to_vec()
        );
    }

    #[test]
    fn body_collapses_internal_wsp() {
        assert_eq!(
            canonicalize_body_relaxed(b"a  b\t\tc\r\n"),
            b"a b c\r\n".to_vec()
        );
    }

    #[test]
    fn body_preserves_internal_empty_lines() {
        // An empty line BETWEEN non-empty lines is preserved; only trailing
        // empty lines are stripped.
        assert_eq!(
            canonicalize_body_relaxed(b"a\r\n\r\nb\r\n"),
            b"a\r\n\r\nb\r\n".to_vec()
        );
    }

    #[test]
    fn body_no_trailing_crlf_still_terminated() {
        // RFC 6376 §3.4.4: canonicalized body always ends with CRLF if non-empty.
        // Defensive: if caller gave us a body without trailing CRLF, emit one.
        assert_eq!(
            canonicalize_body_relaxed(b"Hello"),
            b"Hello\r\n".to_vec()
        );
    }
}
