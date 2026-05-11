//! Byte-slice helpers shared by the parsing / canonicalization modules.
//! Consolidated here so the trim/strip logic exists in exactly one place
//! and can't drift between modules (the failure mode would be
//! "canonicalization disagrees with DKIM parse," which produces a
//! valid-looking proof that doesn't actually prove SPEC.md §2).

/// SP (0x20) or HTAB (0x09).
#[inline]
pub fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// SP, HTAB, CR, or LF.
#[inline]
pub fn is_wsp_or_crlf(b: u8) -> bool {
    is_wsp(b) || b == b'\r' || b == b'\n'
}

/// Strip leading and trailing SP/HTAB only. CRLF is left intact.
pub fn trim_wsp(input: &[u8]) -> &[u8] {
    let start = input.iter().position(|&b| !is_wsp(b)).unwrap_or(input.len());
    let end = input.iter().rposition(|&b| !is_wsp(b)).map(|i| i + 1).unwrap_or(0);
    if start <= end { &input[start..end] } else { &[] }
}

/// Strip leading and trailing SP/HTAB/CR/LF.
pub fn trim_wsp_crlf(input: &[u8]) -> &[u8] {
    let start = input.iter().position(|&b| !is_wsp_or_crlf(b)).unwrap_or(input.len());
    let end = input.iter().rposition(|&b| !is_wsp_or_crlf(b)).map(|i| i + 1).unwrap_or(0);
    if start <= end { &input[start..end] } else { &[] }
}

/// Return a new Vec containing only the non-WSP, non-CRLF bytes. Used for
/// RFC 6376 §3.5 stripping of whitespace inside base64 tag values.
pub fn strip_wsp_crlf(input: &[u8]) -> Vec<u8> {
    input.iter().copied().filter(|b| !is_wsp_or_crlf(*b)).collect()
}

/// Strip a trailing CRLF if present. Returns the input unchanged otherwise.
pub fn strip_trailing_crlf(input: &[u8]) -> &[u8] {
    if input.ends_with(b"\r\n") {
        &input[..input.len() - 2]
    } else {
        input
    }
}

/// ASCII-case-insensitive byte-slice equality.
pub fn bytes_eq_case_insensitive(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}
