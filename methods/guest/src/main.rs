//! Guest program — SPEC.md §4.
//!
//! Each numbered TODO below maps to a step in `SPEC.md` §4 and is filled in
//! *in order*. Per guardrails:
//!   - Implement only what SPEC.md describes. Ask before adding anything else.
//!   - Stay under 500 lines, hand-readable (SPEC.md §9).
//!   - The cryptographic statement in SPEC.md §2 is the contract.
//!
//! Pure-function modules carry their own `#[cfg(test)]` unit tests:
//!   * `canonical`:  SPEC.md §4.3 relaxed/relaxed canonicalization
//!   * `dkim`:       SPEC.md §4.1 + §4.2 header location, parse, assertions
//!   * `body`:       SPEC.md §4.4 body SHA-256 verification
//!   * `signed_set`: SPEC.md §4.5 canonicalized signed-header set
//!   * `verify`:     SPEC.md §4.6 RSA-PKCS1v1.5-SHA256 verify
//!   * `nullifier`:  SPEC.md §4.7 Poseidon-based replay nullifier
//!
//! Build with the RISC0 toolchain to produce a guest ELF; build natively
//! (`cargo test`) to run those unit tests on the host architecture.

#![cfg_attr(not(test), no_main)]

mod address;
mod body;
mod bytes_util;
mod canonical;
mod dkim;
mod nullifier;
mod signed_set;
mod verify;

#[cfg(not(test))]
risc0_zkvm::guest::entry!(main);

/// Domain separator for the nullifier construction (SPEC.md §3, §4.7).
/// Locked at v0; changing it invalidates every prior proof.
/// Encoded as a single BN254 field element with right-padding when fed into
/// Poseidon. See SPEC.md §4.7.
pub const DOMAIN_SEPARATOR_V0: &[u8] = b"0nce-v0-nullifier";

#[cfg(not(test))]
fn main() {
    use nce_core::{PublicInputs, PublicOutputs, Witness};
    use risc0_zkvm::guest::env;

    // Read inputs. The host writes witness then public inputs in this order;
    // the order is the contract between host and guest.
    let witness: Witness = env::read();
    let public_inputs: PublicInputs = env::read();

    // §4.1 + §4.2: locate, parse, validate the DKIM-Signature header. Any
    // assertion failure (wrong magic, wrong v/a/c, d != claimed_domain,
    // s != selector, b or bh != witness, l= present) panics here.
    let parsed = dkim::locate_and_parse(
        &witness.email_raw,
        witness.dkim_header_index,
        &public_inputs.claimed_domain,
        &witness.selector,
        &witness.signature,
        &witness.body_hash,
    );

    // §4.4: SHA-256 of canonicalized body, assert == parsed.body_hash.
    // (Body canonicalization, §4.3 body half, runs inside verify_body_hash.)
    body::verify_body_hash(&witness.email_raw, &parsed.body_hash);

    // §4.5: construct canonicalized header set with b= emptied. Uses
    // canonical::canonicalize_header_relaxed internally (§4.3 header half).
    let signed_data = signed_set::build_signed_data(
        &witness.email_raw,
        &parsed.signed_headers_raw,
        parsed.header_start,
        parsed.header_end,
    );

    // §4.6: RSA-PKCS1v1.5-SHA256 verify of the signature over signed_data.
    // The expensive step.
    verify::verify_rsa_signature(
        &signed_data,
        &parsed.signature,
        &public_inputs.claimed_pubkey_n,
        &public_inputs.claimed_pubkey_e,
    );

    // §4.7: nullifier = Poseidon(DOMAIN_SEPARATOR_V0, claimed_domain, signature).
    let nullifier = nullifier::compute_nullifier(
        DOMAIN_SEPARATOR_V0,
        &public_inputs.claimed_domain,
        &parsed.signature,
    );

    // §4.9 + §4.10 (v1): identity-header disclosure is OPT-IN. With
    // `disclosed_header_kind == None` the guest reveals no address (v0
    // privacy-preserving mode): nobody is named unless the prover chose to.
    let disclosed_address = match public_inputs.disclosed_header_kind {
        None => Vec::new(),
        Some(kind) => {
            // §4.9: locate the disclosed header WITHIN the signed set. Assert
            // it is covered by `h=` (else the signature does not protect it),
            // then read the bottom-most instance — the one the signature
            // actually covers. Reading the signed instance defeats
            // header-prepend attacks.
            let disclosed_name = kind.header_name();
            assert!(
                signed_set::h_contains(&parsed.signed_headers_raw, disclosed_name),
                "disclosed header is not covered by the DKIM h= tag"
            );
            let value = signed_set::signed_header_value(&witness.email_raw, disclosed_name)
                .expect("disclosed header is in h= but absent from the message");

            // §4.10: parse the address from the signed header and emit it.
            // Domain/signer alignment is a verifier-side policy check (see host
            // verify.rs), not a guest assertion — real mail is often signed by
            // a provider whose d= differs from the From domain.
            address::extract_address(&value)
        }
    };

    // §4.8: commit public outputs (claimed_domain echoed + nullifier + address).
    env::commit(&PublicOutputs {
        claimed_domain: public_inputs.claimed_domain,
        nullifier,
        disclosed_address,
    });
}
