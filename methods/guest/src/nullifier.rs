//! SPEC.md §4 step 7 — Poseidon-based replay nullifier.
//!
//! `nullifier = Poseidon(domain_separator_v0, claimed_domain, signature)`,
//! where each of the three byte-string inputs is compressed to a single
//! BN254 field element via SHA-256 (then reduced mod the BN254 prime),
//! and Poseidon is the Circom/Iden3-parameterized BN254 instance via
//! the `light-poseidon` crate.
//!
//! Per SPEC.md §3 the output is a 32-byte field element written into the
//! `PublicOutputs::nullifier` slot.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use sha2::{Digest, Sha256};

/// SPEC.md §4 step 7.
pub fn compute_nullifier(
    domain_separator_v0: &[u8],
    claimed_domain: &[u8],
    signature: &[u8],
) -> [u8; 32] {
    let f1 = bytes_to_field(domain_separator_v0);
    let f2 = bytes_to_field(claimed_domain);
    let f3 = bytes_to_field(signature);

    let mut hasher = Poseidon::<Fr>::new_circom(3).expect("poseidon init for t=4");
    let result = hasher.hash(&[f1, f2, f3]).expect("poseidon hash failed");

    let be_bytes = result.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32 - be_bytes.len();
    out[start..].copy_from_slice(&be_bytes);
    out
}

/// Compress arbitrary-length bytes to one BN254 field element.
///
/// SHA-256 first (one-way + uniform 256-bit digest), then reduce mod the
/// BN254 base-field prime via `from_be_bytes_mod_order`. The reduction is
/// slightly biased over the top ~3 bits, but for nullifier purposes
/// (collision resistance against an adversary who must also forge a valid
/// DKIM RSA signature) the bias is far below cryptographic concern.
fn bytes_to_field(bytes: &[u8]) -> Fr {
    let digest = Sha256::digest(bytes);
    Fr::from_be_bytes_mod_order(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOM: &[u8] = b"0nce-v0-nullifier";

    #[test]
    fn nullifier_is_deterministic() {
        let a = compute_nullifier(DOM, b"example.com", b"signature-bytes");
        let b = compute_nullifier(DOM, b"example.com", b"signature-bytes");
        assert_eq!(a, b);
    }

    #[test]
    fn different_signature_yields_different_nullifier() {
        let a = compute_nullifier(DOM, b"example.com", b"sig-a");
        let b = compute_nullifier(DOM, b"example.com", b"sig-b");
        assert_ne!(a, b);
    }

    #[test]
    fn different_domain_yields_different_nullifier() {
        let a = compute_nullifier(DOM, b"example.com", b"sig");
        let b = compute_nullifier(DOM, b"corp.example", b"sig");
        assert_ne!(a, b);
    }

    #[test]
    fn different_domain_separator_yields_different_nullifier() {
        // If we ever rev to v1 and change domain_separator, every prior
        // proof's nullifier must be different. This is what makes the
        // separator constant load-bearing: changing it invalidates the
        // entire prior nullifier corpus.
        let a = compute_nullifier(b"0nce-v0-nullifier", b"example.com", b"sig");
        let b = compute_nullifier(b"0nce-v1-nullifier", b"example.com", b"sig");
        assert_ne!(a, b);
    }

    #[test]
    fn output_is_32_bytes() {
        let n = compute_nullifier(DOM, b"d", b"s");
        assert_eq!(n.len(), 32);
    }
}
