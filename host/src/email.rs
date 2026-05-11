//! Email parser, host side. Just enough to extract the four DKIM-Signature
//! fields the host needs to populate the witness: domain (`d=`), selector
//! (`s=`), signature (`b=`), and body hash (`bh=`), plus the byte offset
//! of the `DKIM-Signature:` header in the raw email for the witness.
//!
//! The guest does the full validation against public inputs and the host-
//! supplied witness (`methods/guest/src/dkim.rs`). If the host's parse here
//! disagrees with the guest's parse, the guest panics and no proof is
//! produced. So this parser only needs to be accurate enough to populate
//! the witness for well-formed inputs; it does NOT need to assert
//! soundness properties.

use anyhow::{anyhow, bail, Context, Result};

const HEADER_NAME: &[u8] = b"DKIM-Signature:";

#[derive(Debug)]
pub struct ExtractedFields {
    pub header_index: u32,
    pub domain: Vec<u8>,
    pub selector: Vec<u8>,
    pub signature_b64: Vec<u8>,
    pub body_hash_b64: Vec<u8>,
}

pub fn extract(email_raw: &[u8]) -> Result<ExtractedFields> {
    let header_index = find_dkim_signature(email_raw)
        .context("no DKIM-Signature header found in email")?;
    let value_start = header_index + HEADER_NAME.len();
    let header_end = find_header_end(email_raw, value_start);
    let value_end = if header_end >= 2 && &email_raw[header_end - 2..header_end] == b"\r\n" {
        header_end - 2
    } else {
        header_end
    };
    let header_value = &email_raw[value_start..value_end];

    let tags = parse_tag_list(header_value)?;
    let lookup = |name: &[u8]| -> Result<Vec<u8>> {
        tags.iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| trim_wsp(v).to_vec())
            .ok_or_else(|| anyhow!("DKIM-Signature missing {} tag", std::str::from_utf8(name).unwrap()))
    };

    Ok(ExtractedFields {
        header_index: header_index as u32,
        domain: lookup(b"d")?,
        selector: lookup(b"s")?,
        signature_b64: strip_wsp_crlf(&lookup_raw(&tags, b"b")?),
        body_hash_b64: strip_wsp_crlf(&lookup_raw(&tags, b"bh")?),
    })
}

fn lookup_raw(tags: &[(Vec<u8>, Vec<u8>)], name: &[u8]) -> Result<Vec<u8>> {
    tags.iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.clone())
        .ok_or_else(|| anyhow!("DKIM-Signature missing {} tag", std::str::from_utf8(name).unwrap()))
}

fn find_dkim_signature(email: &[u8]) -> Option<usize> {
    // First match wins. Case-insensitive on the header name.
    let mut i = 0;
    while i + HEADER_NAME.len() <= email.len() {
        let candidate = &email[i..i + HEADER_NAME.len()];
        if candidate
            .iter()
            .zip(HEADER_NAME)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            // Must be at the start of a line (start of file, or after CRLF).
            let at_line_start = i == 0
                || (i >= 2 && email[i - 2] == b'\r' && email[i - 1] == b'\n');
            if at_line_start {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn find_header_end(email: &[u8], from: usize) -> usize {
    let mut i = from;
    while i + 1 < email.len() {
        if email[i] == b'\r' && email[i + 1] == b'\n' {
            let next = i + 2;
            if next >= email.len() || (email[next] != b' ' && email[next] != b'\t') {
                return next;
            }
        }
        i += 1;
    }
    email.len()
}

fn parse_tag_list(input: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut tags = Vec::new();
    for piece in input.split(|&b| b == b';') {
        if piece.iter().all(|b| is_wsp_or_crlf(*b)) {
            continue;
        }
        let eq = piece
            .iter()
            .position(|&b| b == b'=')
            .ok_or_else(|| anyhow!("malformed DKIM tag (no =)"))?;
        let name = trim_wsp(&piece[..eq]).to_vec();
        let value = piece[eq + 1..].to_vec();
        tags.push((name, value));
    }
    if tags.is_empty() {
        bail!("DKIM-Signature has no tags");
    }
    Ok(tags)
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

fn is_wsp_or_crlf(b: u8) -> bool {
    b == b' ' || b == b'\t' || b == b'\r' || b == b'\n'
}
