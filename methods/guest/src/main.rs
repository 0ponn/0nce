//! Guest program — SPEC.md §4.
//!
//! Each numbered TODO below maps to a step in `SPEC.md` §4 and is filled in
//! *in order*. Per guardrails:
//!   - Implement only what SPEC.md describes. Ask before adding anything else.
//!   - Stay under 500 lines, hand-readable (SPEC.md §9).
//!   - The cryptographic statement in SPEC.md §2 is the contract.
//!
//! Pure-function modules (e.g. `canonical`) carry their own `#[cfg(test)]`
//! unit tests. Build with the RISC0 toolchain to produce a guest ELF; build
//! natively (`cargo test`) to run those unit tests on the host architecture.

#![cfg_attr(not(test), no_main)]

mod canonical;

#[cfg(not(test))]
risc0_zkvm::guest::entry!(main);

/// Domain separator for the nullifier construction (SPEC.md §3, §4.7).
/// Locked at v0; changing it invalidates every prior proof.
/// Encoded as a single BN254 field element with right-padding when fed into
/// Poseidon. See SPEC.md §4.7.
pub const DOMAIN_SEPARATOR_V0: &[u8] = b"0nce-v0-nullifier";

#[cfg(not(test))]
fn main() {
    // TODO §4.1: parse `email_raw` to locate the DKIM-Signature header at
    //            `dkim_header_index`. Assert the header starts with the exact
    //            bytes `DKIM-Signature:` (case-insensitive per RFC 6376 §3.2).
    //            Parse its tag-value list.
    //
    // TODO §4.2: extract v, a, c, d, s, h, bh, b. Assert v=1, a=rsa-sha256,
    //            d == claimed_domain (public input), s == selector (witness).
    //
    // TODO §4.3: apply relaxed/relaxed canonicalization (the only mode
    //            supported in v0). Assert and fail on any other.
    //            <-- FIRST WALL. The advisor pre-named this as the worst part.
    //
    // TODO §4.4: SHA-256 the canonicalized body. Assert equals `bh`.
    //
    // TODO §4.5: construct the canonicalized header set per `h=`, append the
    //            DKIM-Signature header with `b=` emptied (RFC 6376 §3.7).
    //
    // TODO §4.6: RSA-verify `b` over SHA-256(header set) against
    //            `claimed_pubkey` (public input). This is the expensive step.
    //
    // TODO §4.7: nullifier = Poseidon(DOMAIN_SEPARATOR_V0, claimed_domain,
    //            signature). Commit as public output.
    //
    // TODO §4.8: commit `claimed_domain` as public output.
    //
    // Any assertion failure above => guest panics => no proof. That is the
    // intended behavior; do not add fallbacks.

    panic!("guest not implemented — see SPEC.md §4");
}
