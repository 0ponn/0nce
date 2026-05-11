//! SPEC.md §7 adversarial tests — "the part most ZK projects skip."
//!
//! These probe a *malicious prover* who controls the prover code. They are
//! the load-bearing part of the soundness story for v0. Per the advisor's
//! note: write the names as empty stubs first, so the implementation pass
//! cannot quietly fail to write them.
//!
//! Includes the §7 "Soundness sanity check" line items at the bottom.

// -- Adversarial: prover with bad intent ------------------------------------

#[test]
fn prover_lies_about_claimed_domain_in_public_inputs_guest_catches_mismatch() {
    // SPEC.md §7 adversarial #1:
    //   "Prover supplies a valid email but lies about claimed_domain in
    //    public inputs → guest catches mismatch, panics."
    unimplemented!("SPEC.md §7 adversarial #1");
}

#[test]
fn prover_forges_dkim_with_own_key_claims_different_domain_must_fail() {
    // SPEC.md §7 adversarial #2:
    //   "Prover supplies a forged DKIM-Signature header that 'verifies'
    //    against a key the prover controls but claims a different domain
    //    → must fail. (Tests the public input binding in step 2 of the guest.)"
    //
    // This is THE soundness-critical test for v0's §6 step-2 weakness. The
    // guest's d == claimed_domain assertion (SPEC.md §4.2) is what this
    // probes. If this passes a malicious key/domain pair, the proof is
    // vacuously trivial.
    unimplemented!("SPEC.md §7 adversarial #2");
}

#[test]
fn email_with_two_dkim_signature_headers_only_indexed_one_considered() {
    // SPEC.md §7 adversarial #3:
    //   "Prover supplies an email with TWO DKIM-Signature headers, one
    //    valid and one for the claimed domain → must not be exploitable.
    //    v0 behavior: only the header at dkim_header_index is considered;
    //    if it's not the claimed domain, fail."
    unimplemented!("SPEC.md §7 adversarial #3");
}

#[test]
fn malformed_inputs_never_produce_a_proof() {
    // SPEC.md §7 adversarial #4:
    //   "Empty email, malformed email, email with no DKIM-Signature, email
    //    with malformed DKIM tags → all must fail gracefully, never produce
    //    a proof."
    unimplemented!("SPEC.md §7 adversarial #4");
}

#[test]
fn re_signed_email_yields_different_nullifier_both_accepted() {
    // SPEC.md §7 adversarial #5:
    //   "Same email body, different DKIM-Signature (re-signed) → different
    //    nullifier, both accepted. Document this; may or may not be desired
    //    in v1."
    unimplemented!("SPEC.md §7 adversarial #5");
}

// -- Soundness sanity check -------------------------------------------------

#[test]
fn bit_flip_in_signature_panics_in_guest() {
    // SPEC.md §7 soundness sanity check:
    //   "flip a single bit in the signature, regenerate proof → should
    //    panic in guest, no proof produced."
    unimplemented!("SPEC.md §7 soundness sanity check (signature bit flip)");
}

#[test]
fn bit_flip_in_proof_artifact_verifier_rejects() {
    // SPEC.md §7 soundness sanity check:
    //   "flip a bit in the proof artifact itself after generation →
    //    verifier should reject."
    unimplemented!("SPEC.md §7 soundness sanity check (proof artifact bit flip)");
}
