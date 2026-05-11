//! DNS resolution for DKIM public keys.
//!
//! Per SPEC.md §6 step 2 the public key is out of the trust boundary, so
//! we delegate to the system `dig` rather than pulling a pure-Rust DNS
//! client + async runtime for a single TXT lookup. The verifier operator
//! is expected to confirm the resolved key.

use anyhow::{anyhow, bail, Context, Result};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct RsaPubKeyBytes {
    pub n: Vec<u8>, // modulus, big-endian
    pub e: Vec<u8>, // exponent, big-endian
}

/// Look up `selector._domainkey.domain` via `dig +short TXT`, concatenate
/// the joined chunks (DKIM TXT records are commonly split into "..." "..."
/// quoted segments), parse the `v=DKIM1; ...; p=<base64>` record, decode
/// the public key.
pub fn lookup(domain: &[u8], selector: &[u8]) -> Result<RsaPubKeyBytes> {
    let qname = format!(
        "{}._domainkey.{}",
        std::str::from_utf8(selector)?,
        std::str::from_utf8(domain)?
    );
    let output = Command::new("dig")
        .args(["+short", "TXT", &qname])
        .output()
        .context("invoking `dig`; install dnsutils/bind-utils or use --pubkey-tag")?;
    if !output.status.success() {
        bail!(
            "dig failed for {}: {}",
            qname,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8(output.stdout)?;
    let tag = join_dig_txt(&stdout);
    if tag.is_empty() {
        bail!("no TXT record at {} (DKIM selector may not be published or DNS may be blocked)", qname);
    }
    parse_dkim_tag(&tag)
}

/// `dig +short TXT` prints lines like `"v=DKIM1; ...; p=ABC" "DEF..."` for
/// multi-chunk records. Strip quotes, concatenate, drop leading/trailing
/// whitespace. If multiple TXT records came back, take the first (DKIM
/// expects one record per selector).
fn join_dig_txt(stdout: &str) -> String {
    let first_line = stdout.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let mut out = String::new();
    let mut in_quote = false;
    for ch in first_line.chars() {
        if ch == '"' {
            in_quote = !in_quote;
        } else if in_quote {
            out.push(ch);
        }
    }
    out
}

/// Parse a `v=DKIM1; k=rsa; p=<base64-DER-spki>` record.
pub fn parse_dkim_tag(tag: &str) -> Result<RsaPubKeyBytes> {
    let mut p_value: Option<String> = None;
    let mut v_ok = false;
    let mut k_ok = true; // k= is optional; default rsa.
    for tag_spec in tag.split(';') {
        let tag_spec = tag_spec.trim();
        if let Some(eq) = tag_spec.find('=') {
            let (name, value) = tag_spec.split_at(eq);
            let value = &value[1..];
            match name.trim() {
                "v" => v_ok = value.trim() == "DKIM1",
                "k" => k_ok = matches!(value.trim(), "rsa" | "RSA"),
                "p" => p_value = Some(value.trim().chars().filter(|c| !c.is_whitespace()).collect()),
                _ => {}
            }
        }
    }
    if !v_ok {
        bail!("DKIM TXT record missing v=DKIM1 (got: {tag})");
    }
    if !k_ok {
        bail!("DKIM TXT record has non-RSA key type (v0 supports rsa-sha256 only)");
    }
    let p = p_value.ok_or_else(|| anyhow!("DKIM TXT record has no p= public key"))?;
    let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, p.as_bytes())
        .context("p= value is not valid base64")?;
    extract_modulus_exponent_from_spki(&der)
}

/// Minimal DER walker that extracts (modulus, exponent) from a SubjectPublicKeyInfo
/// containing an RSA public key. This is enough for DKIM's published key format
/// without pulling a full ASN.1 dep. If the DER doesn't match the expected shape
/// we fail with a clear message — operator can then use --pubkey-tag to override.
fn extract_modulus_exponent_from_spki(der: &[u8]) -> Result<RsaPubKeyBytes> {
    // SPKI = SEQUENCE { algId AlgorithmIdentifier, subjectPublicKey BIT STRING }
    // Inside the BIT STRING (after 1 byte of unused-bits-count = 0):
    //   RSAPublicKey = SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    let (spki_body, _) = read_sequence(der)?;
    // Skip AlgorithmIdentifier.
    let (_, after_alg) = read_sequence(spki_body)?;
    // Read BIT STRING.
    if after_alg.is_empty() || after_alg[0] != 0x03 {
        bail!("expected BIT STRING in SubjectPublicKeyInfo");
    }
    let (bs_body, _) = read_tlv(after_alg)?;
    if bs_body.is_empty() || bs_body[0] != 0x00 {
        bail!("BIT STRING has unexpected unused-bits count");
    }
    let rsa_pubkey_der = &bs_body[1..];
    let (rsa_body, _) = read_sequence(rsa_pubkey_der)?;
    let (modulus_bytes, after_n) = read_integer(rsa_body)?;
    let (exponent_bytes, _) = read_integer(after_n)?;
    Ok(RsaPubKeyBytes {
        n: modulus_bytes.to_vec(),
        e: exponent_bytes.to_vec(),
    })
}

fn read_sequence(input: &[u8]) -> Result<(&[u8], &[u8])> {
    if input.is_empty() || input[0] != 0x30 {
        bail!("expected SEQUENCE tag (0x30), got 0x{:02x}", input.first().unwrap_or(&0));
    }
    read_tlv(input)
}

fn read_integer(input: &[u8]) -> Result<(&[u8], &[u8])> {
    if input.is_empty() || input[0] != 0x02 {
        bail!("expected INTEGER tag (0x02)");
    }
    let (body, rest) = read_tlv(input)?;
    // Strip a single leading 0x00 if it's just a sign-pad byte for a positive
    // integer (DER encodes INTEGERs as signed).
    let body = if body.len() > 1 && body[0] == 0x00 { &body[1..] } else { body };
    Ok((body, rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn join_dig_txt_handles_single_quoted_chunk() {
        let stdout = "\"v=DKIM1; k=rsa; p=ABC\"\n";
        assert_eq!(join_dig_txt(stdout), "v=DKIM1; k=rsa; p=ABC");
    }

    #[test]
    fn join_dig_txt_handles_multiple_quoted_chunks() {
        // Real DKIM records are commonly split across multiple "..." chunks
        // because TXT record string max is 255 bytes.
        let stdout = "\"v=DKIM1; k=rsa; p=PART1\" \"PART2\" \"PART3\"\n";
        assert_eq!(join_dig_txt(stdout), "v=DKIM1; k=rsa; p=PART1PART2PART3");
    }

    #[test]
    fn parse_dkim_tag_rejects_missing_v() {
        assert!(parse_dkim_tag("k=rsa; p=abc").is_err());
    }

    #[test]
    fn parse_dkim_tag_rejects_non_dkim1_v() {
        assert!(parse_dkim_tag("v=DKIM2; k=rsa; p=abc").is_err());
    }

    #[test]
    fn parse_dkim_tag_rejects_non_rsa_k() {
        // v0 supports rsa-sha256 only. Ed25519 (RFC 8463) is a v1 candidate.
        assert!(parse_dkim_tag("v=DKIM1; k=ed25519; p=abc").is_err());
    }

    #[test]
    fn parse_dkim_tag_rejects_missing_p() {
        assert!(parse_dkim_tag("v=DKIM1; k=rsa").is_err());
    }

    #[test]
    fn der_walker_extracts_modulus_and_exponent() {
        // Synthetic SubjectPublicKeyInfo for an RSA key with small modulus
        // and exponent 65537 (AQAB). The walker treats modulus and exponent
        // as opaque byte slices; this test only verifies that DER navigation
        // works (skipping AlgorithmIdentifier, descending into BIT STRING +
        // RSAPublicKey SEQUENCE, then reading two INTEGERs).
        let der: Vec<u8> = vec![
            0x30, 0x20, // SEQUENCE, 32 bytes
                0x30, 0x0D, // AlgorithmIdentifier SEQUENCE, 13 bytes
                    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // OID rsaEncryption
                    0x05, 0x00, // NULL
                0x03, 0x0F, // BIT STRING, 15 bytes
                    0x00, // unused bits = 0
                    0x30, 0x0C, // RSAPublicKey SEQUENCE, 12 bytes
                        0x02, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, // modulus INTEGER with sign-pad 0x00
                        0x02, 0x03, 0x01, 0x00, 0x01, // exponent INTEGER (65537)
        ];
        let r = extract_modulus_exponent_from_spki(&der).unwrap();
        // The leading sign-pad 0x00 is stripped per read_integer.
        assert_eq!(r.n, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(r.e, vec![0x01, 0x00, 0x01]); // = 65537
    }

    #[test]
    fn parse_dkim_tag_decodes_synthetic_record() {
        // End-to-end: build the synthetic SPKI bytes, base64-encode, wrap in
        // a v=DKIM1 record, parse, recover (n, e).
        let der: Vec<u8> = vec![
            0x30, 0x20,
                0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
                0x01, 0x01, 0x01, 0x05, 0x00,
                0x03, 0x0F, 0x00,
                    0x30, 0x0C,
                        0x02, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04,
                        0x02, 0x03, 0x01, 0x00, 0x01,
        ];
        let p_b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let tag = format!("v=DKIM1; k=rsa; p={}", p_b64);
        let r = parse_dkim_tag(&tag).unwrap();
        assert_eq!(r.n, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(r.e, vec![0x01, 0x00, 0x01]);
    }
}

fn read_tlv(input: &[u8]) -> Result<(&[u8], &[u8])> {
    if input.len() < 2 {
        bail!("truncated DER");
    }
    let first_len_byte = input[1];
    let (len, header_size) = if first_len_byte & 0x80 == 0 {
        (first_len_byte as usize, 2)
    } else {
        let n_bytes = (first_len_byte & 0x7f) as usize;
        if n_bytes == 0 || n_bytes > 4 || input.len() < 2 + n_bytes {
            bail!("unsupported DER length encoding");
        }
        let mut len = 0usize;
        for i in 0..n_bytes {
            len = (len << 8) | (input[2 + i] as usize);
        }
        (len, 2 + n_bytes)
    };
    if input.len() < header_size + len {
        bail!("DER length exceeds available bytes");
    }
    let body = &input[header_size..header_size + len];
    let rest = &input[header_size + len..];
    Ok((body, rest))
}
