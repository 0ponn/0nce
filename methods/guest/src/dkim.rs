//! SPEC.md §4 steps 1 + 2 — locate the DKIM-Signature header in
//! `email_raw` and parse/validate its tag-value list.
//!
//! Hand-rolled per SPEC.md §9 "guest under 500 lines, hand-readable."
//! No external dep beyond `base64` for decoding `b=` and `bh=`.

use base64::{engine::general_purpose, Engine};

const HEADER_NAME: &[u8] = b"DKIM-Signature:";

/// v0 supports only `relaxed/relaxed`. Other modes panic in step 2.
#[derive(Debug, PartialEq, Eq)]
pub enum Canonicalization {
    RelaxedRelaxed,
}

/// Validated DKIM-Signature header with required tags extracted and `b`/`bh`
/// base64-decoded.
#[derive(Debug)]
pub struct DkimHeader {
    pub canonicalization: Canonicalization,
    pub domain: Vec<u8>,
    pub selector: Vec<u8>,
    /// Raw bytes of the `h=` tag value (colon-separated list of header field
    /// names). Whitespace is preserved; parsing into individual names belongs
    /// to §4.5 (header set construction), not here.
    pub signed_headers_raw: Vec<u8>,
    /// Base64-decoded `bh=`.
    pub body_hash: Vec<u8>,
    /// Base64-decoded `b=` — the RSA signature.
    pub signature: Vec<u8>,
    /// Byte offset of `DKIM-Signature:` in `email_raw`.
    pub header_start: usize,
    /// Exclusive end of the full DKIM-Signature header (past the trailing
    /// CRLF that terminates it).
    pub header_end: usize,
}

/// SPEC.md §4 steps 1 + 2.
///
/// Locates the DKIM-Signature header at `offset`, bounds it (handling RFC
/// 5322 continuation lines), parses its tag-value list per RFC 6376 §3.2,
/// and applies every assertion enumerated in SPEC.md §4 step 2.
///
/// Panics (= guest aborts = no proof) on any assertion failure. Every panic
/// here is the intended behavior for an invalid prover input or a host that
/// lied about the witness.
pub fn locate_and_parse(
    email_raw: &[u8],
    offset: u32,
    claimed_domain: &[u8],
    witnessed_selector: &[u8],
    witnessed_signature_b64: &[u8],
    witnessed_body_hash_b64: &[u8],
) -> DkimHeader {
    let start = offset as usize;

    // §4.1: bounds + magic-byte check.
    assert!(
        start + HEADER_NAME.len() <= email_raw.len(),
        "dkim_header_index out of bounds"
    );
    assert!(
        bytes_eq_case_insensitive(&email_raw[start..start + HEADER_NAME.len()], HEADER_NAME),
        "bytes at dkim_header_index are not 'DKIM-Signature:'"
    );

    // §4.1: find end of header.
    let value_start = start + HEADER_NAME.len();
    let header_end = find_header_end(email_raw, value_start);
    let value_end = if header_end >= 2 && &email_raw[header_end - 2..header_end] == b"\r\n" {
        header_end - 2
    } else {
        header_end
    };
    let header_value = &email_raw[value_start..value_end];

    // §4.2: parse tag-value list per RFC 6376 §3.2.
    let tags = parse_tag_list(header_value);

    let v = lookup(&tags, b"v").expect("v= missing");
    let a = lookup(&tags, b"a").expect("a= missing");
    let c = lookup(&tags, b"c").expect("c= missing");
    let d = lookup(&tags, b"d").expect("d= missing");
    let s = lookup(&tags, b"s").expect("s= missing");
    let h = lookup(&tags, b"h").expect("h= missing");
    let bh = lookup(&tags, b"bh").expect("bh= missing");
    let b_tag = lookup(&tags, b"b").expect("b= missing");

    // v0 restriction: `l=` (body-length-limit) tag is not supported.
    // SPEC.md doesn't enumerate it, but accepting it without honoring it
    // would let an attacker truncate the body-hash scope. Reject it here.
    assert!(lookup(&tags, b"l").is_none(), "l= tag not supported in v0");

    // §4.2: protocol version.
    assert_eq!(trim_wsp(v), b"1", "v tag must be 1");

    // §4.2: algorithm — v0 supports only rsa-sha256.
    assert_eq!(trim_wsp(a), b"rsa-sha256", "a tag must be rsa-sha256");

    // §4.2 ∩ §4.3 v0 restriction: relaxed/relaxed only.
    assert_eq!(
        trim_wsp(c),
        b"relaxed/relaxed",
        "c tag must be relaxed/relaxed (v0)"
    );

    // §4.2 SOUNDNESS-CRITICAL: d == claimed_domain.
    // This is the public-input binding probed by SPEC.md §7 adversarial #2.
    // If this assertion is weakened or removed, the proof becomes vacuously
    // trivial — a prover could claim any domain.
    assert_eq!(
        trim_wsp(d),
        claimed_domain,
        "d tag does not match claimed_domain (public-input binding)"
    );

    // §4.2: s == witnessed_selector.
    assert_eq!(trim_wsp(s), witnessed_selector, "s tag != witnessed selector");

    // §4.2 / SPEC.md §5 host-trust guard: b and bh in the header must match
    // what the host put in the witness. Compare after WSP/CRLF strip (RFC
    // 6376 §3.5 allows whitespace within base64 values).
    let b_clean = strip_wsp_crlf(b_tag);
    let bh_clean = strip_wsp_crlf(bh);
    let wb_clean = strip_wsp_crlf(witnessed_signature_b64);
    let wbh_clean = strip_wsp_crlf(witnessed_body_hash_b64);

    assert_eq!(b_clean, wb_clean, "b tag does not match witnessed signature");
    assert_eq!(
        bh_clean, wbh_clean,
        "bh tag does not match witnessed body_hash"
    );

    // Decode base64.
    let signature = general_purpose::STANDARD
        .decode(&b_clean)
        .expect("b= tag is not valid base64");
    let body_hash = general_purpose::STANDARD
        .decode(&bh_clean)
        .expect("bh= tag is not valid base64");

    DkimHeader {
        canonicalization: Canonicalization::RelaxedRelaxed,
        domain: trim_wsp(d).to_vec(),
        selector: trim_wsp(s).to_vec(),
        signed_headers_raw: trim_wsp(h).to_vec(),
        body_hash,
        signature,
        header_start: start,
        header_end,
    }
}

// --- helpers ----------------------------------------------------------------

fn bytes_eq_case_insensitive(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Returns exclusive byte offset just past the CRLF that ends the header.
/// RFC 5322: header ends at CRLF not followed by WSP, or EOF.
fn find_header_end(email_raw: &[u8], from: usize) -> usize {
    let mut i = from;
    while i + 1 < email_raw.len() {
        if email_raw[i] == b'\r' && email_raw[i + 1] == b'\n' {
            let next = i + 2;
            if next >= email_raw.len() || !is_wsp(email_raw[next]) {
                return next;
            }
        }
        i += 1;
    }
    email_raw.len()
}

/// RFC 6376 §3.2: tag-list = tag-spec *( ";" tag-spec ) [";"]
/// We split on `;` then on the first `=`. Tag values are NOT trimmed here
/// because some tags (h=, bh=, b=) carry whitespace that must be preserved
/// or specially stripped at use-site. Per-tag trimming is the caller's job.
fn parse_tag_list(input: &[u8]) -> Vec<(&[u8], &[u8])> {
    let mut tags = Vec::new();
    for piece in input.split(|&b| b == b';') {
        if piece.iter().all(|b| is_wsp_or_crlf(*b)) {
            continue;
        }
        let eq_idx = piece
            .iter()
            .position(|&b| b == b'=')
            .expect("malformed DKIM tag (no '=')");
        let name = trim_wsp(&piece[..eq_idx]);
        let value = &piece[eq_idx + 1..];
        tags.push((name, value));
    }
    tags
}

fn lookup<'a>(tags: &'a [(&'a [u8], &'a [u8])], name: &[u8]) -> Option<&'a [u8]> {
    tags.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

fn trim_wsp(input: &[u8]) -> &[u8] {
    let start = input
        .iter()
        .position(|&b| !is_wsp_or_crlf(b))
        .unwrap_or(input.len());
    let end = input
        .iter()
        .rposition(|&b| !is_wsp_or_crlf(b))
        .map(|i| i + 1)
        .unwrap_or(0);
    if start <= end {
        &input[start..end]
    } else {
        &[]
    }
}

fn strip_wsp_crlf(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .copied()
        .filter(|b| !is_wsp_or_crlf(*b))
        .collect()
}

fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn is_wsp_or_crlf(b: u8) -> bool {
    is_wsp(b) || b == b'\r' || b == b'\n'
}

// --- unit tests -------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // SHA-256 of empty input, base64 — a valid 32-byte body hash (44 chars + '=').
    const BH_VALID: &[u8] = b"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
    // 192 zero bytes encoded as base64 — exactly 256 chars, no padding needed
    // (192 % 3 == 0). Stand-in RSA signature; real RSA verify is §4.6.
    const B_VALID: &[u8] =
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
          AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
          AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
          AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn header_bytes(
        v: &[u8],
        a: &[u8],
        c: &[u8],
        d: &[u8],
        s: &[u8],
        h: &[u8],
        bh: &[u8],
        b: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::from(b"DKIM-Signature: ".as_slice());
        for (k, val) in [
            (&b"v"[..], v), (b"a", a), (b"c", c), (b"d", d),
            (b"s", s), (b"h", h), (b"bh", bh), (b"b", b),
        ] {
            out.extend_from_slice(k);
            out.push(b'=');
            out.extend_from_slice(val);
            out.extend_from_slice(b"; ");
        }
        // Trim trailing "; " and end with CRLF.
        out.truncate(out.len() - 2);
        out.extend_from_slice(b"\r\n");
        out
    }

    fn default_header() -> Vec<u8> {
        header_bytes(
            b"1", b"rsa-sha256", b"relaxed/relaxed",
            b"example.com", b"selector1", b"From:To:Subject",
            BH_VALID, B_VALID,
        )
    }

    // -- happy path ---

    #[test]
    fn happy_path_valid_header_parses() {
        let header = default_header();
        let r = locate_and_parse(
            &header, 0, b"example.com", b"selector1", B_VALID, BH_VALID,
        );
        assert_eq!(r.domain, b"example.com");
        assert_eq!(r.selector, b"selector1");
        assert_eq!(r.signed_headers_raw, b"From:To:Subject");
        assert_eq!(r.canonicalization, Canonicalization::RelaxedRelaxed);
        assert_eq!(r.header_start, 0);
        assert!(r.header_end <= header.len());
        assert_eq!(r.body_hash.len(), 32); // SHA-256 output size
        assert!(!r.signature.is_empty());
    }

    #[test]
    fn case_insensitive_header_name() {
        let mut header = default_header();
        // Lowercase "DKIM-Signature:" prefix.
        for byte in &mut header[..15] {
            byte.make_ascii_lowercase();
        }
        let r = locate_and_parse(
            &header, 0, b"example.com", b"selector1", B_VALID, BH_VALID,
        );
        assert_eq!(r.domain, b"example.com");
    }

    #[test]
    fn finds_header_end_before_next_header() {
        let mut block = default_header();
        block.extend_from_slice(b"Other-Header: bar\r\n");
        let r = locate_and_parse(
            &block, 0, b"example.com", b"selector1", B_VALID, BH_VALID,
        );
        // DKIM header should end exactly where Other-Header begins.
        assert_eq!(&block[r.header_end..r.header_end + 12], b"Other-Header");
    }

    #[test]
    fn continuation_lines_in_header_value() {
        // Tags split across continuation lines (WSP after CRLF means same header).
        let header: Vec<u8> = format!(
            "DKIM-Signature: v=1; a=rsa-sha256;\r\n c=relaxed/relaxed; \
             d=example.com;\r\n\ts=selector1; h=From; bh={}; b={}\r\n",
            std::str::from_utf8(BH_VALID).unwrap(),
            std::str::from_utf8(B_VALID).unwrap(),
        )
        .into_bytes();
        let r = locate_and_parse(
            &header, 0, b"example.com", b"selector1", B_VALID, BH_VALID,
        );
        assert_eq!(r.domain, b"example.com");
    }

    // -- bounds + magic ---

    #[test]
    #[should_panic(expected = "dkim_header_index out of bounds")]
    fn offset_past_end_panics() {
        locate_and_parse(b"short", 100, b"example.com", b"sel", B_VALID, BH_VALID);
    }

    #[test]
    #[should_panic(expected = "not 'DKIM-Signature:'")]
    fn wrong_magic_panics() {
        locate_and_parse(
            b"Not-A-Header:    \r\n",
            0, b"example.com", b"sel", B_VALID, BH_VALID,
        );
    }

    // -- tag-value assertions ---

    #[test]
    #[should_panic(expected = "v tag must be 1")]
    fn v_not_1_panics() {
        let header = header_bytes(
            b"2", b"rsa-sha256", b"relaxed/relaxed",
            b"example.com", b"selector1", b"From", BH_VALID, B_VALID,
        );
        locate_and_parse(&header, 0, b"example.com", b"selector1", B_VALID, BH_VALID);
    }

    #[test]
    #[should_panic(expected = "a tag must be rsa-sha256")]
    fn a_not_rsa_sha256_panics() {
        let header = header_bytes(
            b"1", b"rsa-sha1", b"relaxed/relaxed",
            b"example.com", b"selector1", b"From", BH_VALID, B_VALID,
        );
        locate_and_parse(&header, 0, b"example.com", b"selector1", B_VALID, BH_VALID);
    }

    #[test]
    #[should_panic(expected = "c tag must be relaxed/relaxed")]
    fn c_simple_simple_panics() {
        let header = header_bytes(
            b"1", b"rsa-sha256", b"simple/simple",
            b"example.com", b"selector1", b"From", BH_VALID, B_VALID,
        );
        locate_and_parse(&header, 0, b"example.com", b"selector1", B_VALID, BH_VALID);
    }

    // -- THE soundness-critical test (SPEC.md §7 adversarial #2) ---

    #[test]
    #[should_panic(expected = "public-input binding")]
    fn d_mismatch_panics_SOUNDNESS_CRITICAL() {
        let header = default_header();
        // Prover passes a valid email signed by example.com but lies about
        // the claimed_domain public input.
        locate_and_parse(
            &header, 0, b"different.com", b"selector1", B_VALID, BH_VALID,
        );
    }

    #[test]
    #[should_panic(expected = "witnessed selector")]
    fn s_mismatch_panics() {
        let header = default_header();
        locate_and_parse(
            &header, 0, b"example.com", b"wrong-selector", B_VALID, BH_VALID,
        );
    }

    // -- host-trust guards ---

    #[test]
    #[should_panic(expected = "witnessed signature")]
    fn b_mismatch_with_host_panics() {
        let header = default_header();
        locate_and_parse(
            &header, 0, b"example.com", b"selector1",
            b"AAAA", // host lies about what b= contains
            BH_VALID,
        );
    }

    #[test]
    #[should_panic(expected = "witnessed body_hash")]
    fn bh_mismatch_with_host_panics() {
        let header = default_header();
        locate_and_parse(
            &header, 0, b"example.com", b"selector1",
            B_VALID,
            b"AAAA",
        );
    }

    // -- v0 restrictions ---

    #[test]
    #[should_panic(expected = "l= tag not supported")]
    fn l_tag_rejected() {
        let mut header = default_header();
        // Insert `; l=42` before the final CRLF.
        let cr_idx = header.len() - 2;
        let insertion = b"; l=42";
        header.splice(cr_idx..cr_idx, insertion.iter().copied());
        locate_and_parse(
            &header, 0, b"example.com", b"selector1", B_VALID, BH_VALID,
        );
    }

    #[test]
    #[should_panic(expected = "b= missing")]
    fn required_tag_missing_panics() {
        // Hand-construct a header without b=.
        let header: Vec<u8> = format!(
            "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; \
             d=example.com; s=selector1; h=From; bh={}\r\n",
            std::str::from_utf8(BH_VALID).unwrap(),
        ).into_bytes();
        locate_and_parse(
            &header, 0, b"example.com", b"selector1", B_VALID, BH_VALID,
        );
    }

    // -- base64 whitespace handling (RFC 6376 §3.5) ---

    #[test]
    fn whitespace_inside_base64_b_is_stripped_before_decode() {
        // Build a header with whitespace inserted in the middle of b=.
        let b_with_ws: Vec<u8> = {
            let mut v = Vec::new();
            for (i, ch) in B_VALID.iter().enumerate() {
                v.push(*ch);
                if i > 0 && i % 64 == 0 {
                    v.extend_from_slice(b"\r\n\t");
                }
            }
            v
        };
        let header = header_bytes(
            b"1", b"rsa-sha256", b"relaxed/relaxed",
            b"example.com", b"selector1", b"From",
            BH_VALID, &b_with_ws,
        );
        // Host gives clean witness; whitespace-stripped comparison should match.
        let r = locate_and_parse(
            &header, 0, b"example.com", b"selector1", B_VALID, BH_VALID,
        );
        assert!(!r.signature.is_empty());
    }
}
