//! SPEC.md §7 must-pass tests.
//!
//! Each test below is an empty stub mapped 1:1 to a line in SPEC.md §7
//! "Must-pass tests". Per the advisor's note: the test *names* live in the
//! file before any implementation work begins, so they cannot quietly slip.
//!
//! Currently `#[ignore]`'d because they require a real DKIM-signed `.eml`
//! fixture in `host/tests/fixtures/`. When that lands, drop the ignore
//! attribute and fill in the body.

#[test]
#[ignore = "needs real DKIM-signed .eml fixture in host/tests/fixtures/"]
fn real_dkim_signed_email_from_controlled_domain_proof_verifies() {
    // SPEC.md §7 must-pass #1:
    //   "Real DKIM-signed email from a controlled domain → proof verifies."
    unimplemented!("SPEC.md §7 must-pass #1");
}

#[test]
#[ignore = "needs real DKIM-signed .eml fixture in host/tests/fixtures/"]
fn same_email_submitted_twice_second_rejected_as_replay() {
    // SPEC.md §7 must-pass #2:
    //   "Same email submitted twice → second submission rejected (nullifier replay)."
    unimplemented!("SPEC.md §7 must-pass #2");
}

#[test]
#[ignore = "needs real DKIM-signed .eml fixture in host/tests/fixtures/"]
fn email_from_different_domain_than_claimed_guest_panics() {
    // SPEC.md §7 must-pass #3:
    //   "Email from a different domain than claimed_domain → guest panics, no proof."
    unimplemented!("SPEC.md §7 must-pass #3");
}

#[test]
#[ignore = "needs real DKIM-signed .eml fixture in host/tests/fixtures/"]
fn email_with_tampered_body_bh_mismatch_guest_panics() {
    // SPEC.md §7 must-pass #4:
    //   "Email with tampered body → bh mismatch, guest panics."
    unimplemented!("SPEC.md §7 must-pass #4");
}

#[test]
#[ignore = "needs real DKIM-signed .eml fixture in host/tests/fixtures/"]
fn email_with_tampered_dkim_signature_rsa_verify_fails_guest_panics() {
    // SPEC.md §7 must-pass #5:
    //   "Email with tampered DKIM-Signature → RSA verification fails, guest panics."
    unimplemented!("SPEC.md §7 must-pass #5");
}
