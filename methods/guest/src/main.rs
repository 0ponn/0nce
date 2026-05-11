//! Guest program — SPEC.md §4.
//!
//! Each numbered TODO below maps to a step in `SPEC.md` §4 and is filled in
//! *in order*. Per guardrails:
//!   - Implement only what SPEC.md describes. Ask before adding anything else.
//!   - Stay under 500 lines, hand-readable (SPEC.md §9).
//!   - The cryptographic statement in SPEC.md §2 is the contract.
//!
//! Pure-function modules carry their own `#[cfg(test)]` unit tests:
//!   - `canonical` — SPEC.md §4.3 relaxed/relaxed canonicalization
//!   - `dkim`      — SPEC.md §4.1 + §4.2 header location, parse, assertions
//!
//! Build with the RISC0 toolchain to produce a guest ELF; build natively
//! (`cargo test`) to run those unit tests on the host architecture.

#![cfg_attr(not(test), no_main)]

mod canonical;
mod dkim;

#[cfg(not(test))]
risc0_zkvm::guest::entry!(main);

/// Domain separator for the nullifier construction (SPEC.md §3, §4.7).
/// Locked at v0; changing it invalidates every prior proof.
/// Encoded as a single BN254 field element with right-padding when fed into
/// Poseidon. See SPEC.md §4.7.
pub const DOMAIN_SEPARATOR_V0: &[u8] = b"0nce-v0-nullifier";

#[cfg(not(test))]
fn main() {
    use nce_core::{PublicInputs, Witness};
    use risc0_zkvm::guest::env;

    // Read inputs. The host writes witness then public inputs in this order;
    // the order is the contract between host and guest.
    let witness: Witness = env::read();
    let public_inputs: PublicInputs = env::read();

    // §4.1 + §4.2: locate, parse, validate the DKIM-Signature header. Any
    // assertion failure (wrong magic, wrong v/a/c, d != claimed_domain,
    // s != selector, b or bh != witness, l= present) panics here.
    let _parsed = dkim::locate_and_parse(
        &witness.email_raw,
        witness.dkim_header_index,
        &public_inputs.claimed_domain,
        &witness.selector,
        &witness.signature,
        &witness.body_hash,
    );

    // TODO §4.3: invoke canonical::canonicalize_body_relaxed on the body
    //            portion of email_raw (everything after the end-of-headers
    //            blank line). Also canonical::canonicalize_header_relaxed
    //            for the signed-header set in §4.5.
    //
    // TODO §4.4: SHA-256 of canonicalized body, assert == parsed.body_hash.
    //
    // TODO §4.5: construct canonicalized header set per parsed.signed_headers_raw,
    //            append DKIM-Signature header with b= emptied (RFC 6376 §3.7).
    //
    // TODO §4.6: RSA-verify parsed.signature over SHA-256(header set) using
    //            (public_inputs.claimed_pubkey_n, public_inputs.claimed_pubkey_e).
    //            This is the expensive step.
    //
    // TODO §4.7: nullifier = Poseidon(DOMAIN_SEPARATOR_V0, claimed_domain,
    //            parsed.signature). Commit via env::commit.
    //
    // TODO §4.8: commit claimed_domain via env::commit.
    //
    // Any assertion failure above => guest panics => no proof. Intended.

    panic!("guest §4.3+ not implemented");
}
