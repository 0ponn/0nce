//! Shared type definitions used by both the host (prover side) and the
//! guest (zkVM side).
//!
//! These types are the wire format between host and guest. Drift between
//! the two sides would be a silent-corruption bug, so they live in one
//! crate that both sides depend on.
//!
//! See SPEC.md §3 for which fields are public inputs vs witness (private)
//! vs public outputs (committed by the guest to the journal).

use serde::{Deserialize, Serialize};

/// Public inputs supplied by the verifier and echoed into the proof's
/// public input vector. SPEC.md §3.
///
/// The pubkey is split into modulus + exponent (big-endian bytes) so this
/// crate can stay free of the `rsa` crate dep. The guest reassembles into
/// an `RsaPublicKey` only at SPEC.md §4.6 when it actually verifies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    /// The domain the prover claims the email is signed by (e.g. `b"corp.example"`).
    pub claimed_domain: Vec<u8>,
    /// RSA public-key modulus, big-endian bytes.
    pub claimed_pubkey_n: Vec<u8>,
    /// RSA public-key exponent, big-endian bytes.
    pub claimed_pubkey_e: Vec<u8>,
}

/// Private witness, prover-only. SPEC.md §3.
///
/// The guest re-extracts `signature` and `body_hash` from `email_raw` and
/// asserts the witnessed values match, so the host cannot lie about them
/// (SPEC.md §5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Witness {
    /// Full RFC 5322 email message as received, including headers.
    pub email_raw: Vec<u8>,
    /// Byte offset in `email_raw` where the `DKIM-Signature:` header begins.
    pub dkim_header_index: u32,
    /// DKIM selector (private — can narrow the anonymity set).
    pub selector: Vec<u8>,
    /// RSA signature, base64 text as it appears in the `b=` tag (whitespace
    /// permitted; guest strips before decoding per RFC 6376 §3.5).
    pub signature: Vec<u8>,
    /// Body hash, base64 text as it appears in the `bh=` tag.
    pub body_hash: Vec<u8>,
}

/// Public outputs committed by the guest to the journal. SPEC.md §3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicOutputs {
    /// The claimed domain, echoed from public inputs to bind the proof to the input.
    pub claimed_domain: Vec<u8>,
    /// Poseidon-based replay nullifier. SPEC.md §4.7.
    pub nullifier: [u8; 32],
}
