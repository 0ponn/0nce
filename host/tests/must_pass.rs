//! SPEC.md §7 must-pass tests.
//!
//! Each test maps 1:1 to a line in SPEC.md §7 "Must-pass tests". The names
//! exist as visible TODOs before any implementation per the advisor's note.
//!
//! Tests run with `RISC0_DEV_MODE=1` so they don't pay the full STARK
//! prove time on every cargo test invocation. Dev mode produces fake
//! receipts that are accepted by `receipt.verify()` ONLY when dev mode
//! is also set on the verifier side; production-mode verification of a
//! dev-mode receipt fails. So this is safe to use in tests but cannot
//! be used to fake a real proof.

use std::path::{Path, PathBuf};
use std::process::Command;

fn cli_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_0nce"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn pubkey_tag() -> String {
    std::fs::read_to_string(fixture("real.pubkey.tag"))
        .expect("fixture real.pubkey.tag missing")
        .trim()
        .to_string()
}

struct ProveResult {
    success: bool,
    proof_path: PathBuf,
    stdout: String,
    stderr: String,
}

fn run_prove(email: &Path, out: &Path, pubkey_tag: &str) -> ProveResult {
    let out_proc = Command::new(cli_path())
        .args([
            "prove",
            "--email", email.to_str().unwrap(),
            "--out", out.to_str().unwrap(),
            "--pubkey-tag", pubkey_tag,
            "-y",
        ])
        .env("RISC0_DEV_MODE", "1")
        .output()
        .expect("prove subprocess");
    ProveResult {
        success: out_proc.status.success(),
        proof_path: out.to_path_buf(),
        stdout: String::from_utf8_lossy(&out_proc.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out_proc.stderr).into_owned(),
    }
}

struct VerifyResult {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run_verify(proof: &Path, store: &Path) -> VerifyResult {
    let out_proc = Command::new(cli_path())
        .args([
            "verify",
            "--proof", proof.to_str().unwrap(),
            "--nullifier-store", store.to_str().unwrap(),
        ])
        .env("RISC0_DEV_MODE", "1")
        .output()
        .expect("verify subprocess");
    VerifyResult {
        success: out_proc.status.success(),
        stdout: String::from_utf8_lossy(&out_proc.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out_proc.stderr).into_owned(),
    }
}

#[test]
fn real_dkim_signed_email_from_controlled_domain_proof_verifies() {
    // SPEC.md §7 must-pass #1:
    //   "Real DKIM-signed email from a controlled domain → proof verifies."
    let tmp = tempfile::tempdir().expect("tempdir");
    let proof_path = tmp.path().join("real.proof.bin");
    let store_path = tmp.path().join("nullifiers.txt");
    let email = fixture("real.eml");
    let tag = pubkey_tag();

    let p = run_prove(&email, &proof_path, &tag);
    assert!(
        p.success,
        "prove failed.\nstdout:\n{}\nstderr:\n{}",
        p.stdout, p.stderr
    );
    assert!(p.proof_path.exists(), "proof.bin not written");

    let v = run_verify(&proof_path, &store_path);
    assert!(
        v.success,
        "verify failed.\nstdout:\n{}\nstderr:\n{}",
        v.stdout, v.stderr
    );
    assert!(v.stdout.contains("ACCEPTED"), "verify did not print ACCEPTED:\n{}", v.stdout);
    assert!(
        v.stdout.contains("visionaryauto.ai"),
        "verify did not echo the claimed domain:\n{}",
        v.stdout
    );
    assert!(store_path.exists(), "nullifier store was not written");
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
