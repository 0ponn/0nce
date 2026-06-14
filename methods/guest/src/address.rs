//! v1 design §4.10 — parse the disclosed identity header's email address.
//!
//! Restricted grammar (v1 only; assert-and-fail otherwise, mirroring v0's
//! relaxed/relaxed-only discipline):
//!
//!   header-value = [ display-name ] "<" addr-spec ">" / addr-spec
//!   addr-spec    = local-part "@" domain
//!   local-part   = dot-atom            ; ASCII atext + "."
//!   domain       = dot-atom of LDH labels
//!
//! No quoted strings, comments, groups, multiple addresses, or folding
//! *inside* the addr-spec. A `display-name <addr>` wrapper IS allowed.
//!
//! `extract_address` panics (= guest aborts = no proof) on anything outside
//! the grammar. Every panic is intended: a malformed address must not yield
//! a proof.
//!
//! Note (v1 design refinement): the guest does NOT assert that the address
//! domain equals `claimed_domain`. Real-world mail is frequently signed by a
//! provider whose `d=` differs from the From domain (Gmail/Workspace sign
//! `d=google.com` over `From: you@yourcompany.com`). Whether the disclosed
//! address aligns with the signing domain is a *policy* decision the verifier
//! makes from the two public values (`claimed_domain`, `disclosed_address`);
//! see the host verifier. The soundness guarantee — that the address comes
//! from the DKIM-signed header set, not a forged one — lives in §4.9.

/// Parse the disclosed header value and return the canonical `local@domain`
/// bytes with the domain lowercased (local-part case preserved, per
/// RFC 5321 §2.4).
pub fn extract_address(header_value: &[u8]) -> Vec<u8> {
    // Unfold: drop CR/LF so folded values become single-line. Internal WSP
    // is preserved here; the addr-spec extraction below handles it.
    let unfolded: Vec<u8> = header_value
        .iter()
        .copied()
        .filter(|&b| b != b'\r' && b != b'\n')
        .collect();
    let trimmed = trim_wsp(&unfolded);

    // Extract the addr-spec: either inside the last `<...>`, or the whole
    // token when there is no angle-bracket wrapper.
    let addr = if let Some(lt) = trimmed.iter().position(|&b| b == b'<') {
        let gt = trimmed
            .iter()
            .rposition(|&b| b == b'>')
            .expect("address has '<' without matching '>'");
        assert!(gt > lt, "malformed angle-bracket address");
        trim_wsp(&trimmed[lt + 1..gt])
    } else {
        trimmed
    };

    // A bare addr-spec must contain no internal whitespace.
    assert!(
        !addr.iter().any(|&b| b == b' ' || b == b'\t'),
        "addr-spec contains whitespace"
    );

    // Split on the single '@'.
    let at = addr.iter().position(|&b| b == b'@').expect("addr-spec has no '@'");
    assert!(
        !addr[at + 1..].iter().any(|&b| b == b'@'),
        "addr-spec has more than one '@'"
    );
    let local = &addr[..at];
    let domain = &addr[at + 1..];

    assert!(is_dot_atom_local(local), "invalid local-part");
    assert!(is_ldh_domain(domain), "invalid domain");

    let domain_lower: Vec<u8> = domain.iter().map(|b| b.to_ascii_lowercase()).collect();

    let mut out = Vec::with_capacity(local.len() + 1 + domain_lower.len());
    out.extend_from_slice(local);
    out.push(b'@');
    out.extend_from_slice(&domain_lower);
    out
}

fn trim_wsp(b: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = b.len();
    while start < end && (b[start] == b' ' || b[start] == b'\t') {
        start += 1;
    }
    while end > start && (b[end - 1] == b' ' || b[end - 1] == b'\t') {
        end -= 1;
    }
    &b[start..end]
}

/// RFC 5322 atext plus '.', with no leading/trailing/consecutive dots.
fn is_dot_atom_local(s: &[u8]) -> bool {
    if s.is_empty() || s[0] == b'.' || s[s.len() - 1] == b'.' {
        return false;
    }
    let mut prev_dot = false;
    for &c in s {
        if c == b'.' {
            if prev_dot {
                return false;
            }
            prev_dot = true;
            continue;
        }
        prev_dot = false;
        if !is_atext(c) {
            return false;
        }
    }
    true
}

fn is_atext(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'/' | b'='
                | b'?' | b'^' | b'_' | b'`' | b'{' | b'|' | b'}' | b'~' | b'-'
        )
}

/// Dot-separated LDH (letter/digit/hyphen) labels; each label non-empty and
/// not starting or ending with a hyphen.
fn is_ldh_domain(s: &[u8]) -> bool {
    if s.is_empty() {
        return false;
    }
    for label in s.split(|&b| b == b'.') {
        if label.is_empty() || label[0] == b'-' || label[label.len() - 1] == b'-' {
            return false;
        }
        if !label.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-') {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_addr_spec() {
        assert_eq!(extract_address(b" alice@example.com"), b"alice@example.com");
    }

    #[test]
    fn display_name_wrapped() {
        assert_eq!(
            extract_address(b" Display Name <bob@example.com>"),
            b"bob@example.com"
        );
    }

    #[test]
    fn domain_lowercased_local_preserved() {
        assert_eq!(
            extract_address(b"Bob.Smith <Bob.Smith@Example.COM>"),
            b"Bob.Smith@example.com"
        );
    }

    #[test]
    fn folded_value_unfolded() {
        assert_eq!(
            extract_address(b" Name\r\n <a@sub.example.com>"),
            b"a@sub.example.com"
        );
    }

    #[test]
    #[should_panic(expected = "no '@'")]
    fn no_at_sign_panics() {
        extract_address(b"not-an-address");
    }

    #[test]
    #[should_panic(expected = "more than one '@'")]
    fn double_at_panics() {
        extract_address(b"a@b@example.com");
    }

    #[test]
    #[should_panic(expected = "whitespace")]
    fn bare_internal_space_panics() {
        extract_address(b"no at sign here@example.com");
    }

    #[test]
    #[should_panic(expected = "invalid local-part")]
    fn empty_local_panics() {
        extract_address(b"@example.com");
    }

    #[test]
    #[should_panic(expected = "without matching '>'")]
    fn open_angle_without_close_panics() {
        extract_address(b"Name <a@example.com");
    }

    #[test]
    #[should_panic(expected = "invalid local-part")]
    fn leading_dot_local_panics() {
        extract_address(b".alice@example.com");
    }
}
