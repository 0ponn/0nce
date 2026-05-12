//! SPEC.md §7 must-pass tests.
//!
//! Run with `RISC0_DEV_MODE=1` so they don't pay the full STARK prove
//! time on every invocation. Dev mode produces fake receipts that are
//! accepted by `receipt.verify()` only when dev mode is also set on the
//! verifier side; production-mode verification of a dev-mode receipt
//! fails, so this is safe for tests but cannot be used to fake a real
//! proof.

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

fn run_prove(email: &Path, out: &Path, pubkey_tag: &str, extra_args: &[&str]) -> ProveResult {
    let mut cmd = Command::new(cli_path());
    cmd.args([
        "prove",
        "--email", email.to_str().unwrap(),
        "--out", out.to_str().unwrap(),
        "--pubkey-tag", pubkey_tag,
        "-y",
    ]);
    cmd.args(extra_args);
    cmd.env("RISC0_DEV_MODE", "1");
    let out_proc = cmd.output().expect("prove subprocess");
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

    let p = run_prove(&email, &proof_path, &tag, &[]);
    assert!(p.success, "prove failed.\nstdout:\n{}\nstderr:\n{}", p.stdout, p.stderr);
    assert!(p.proof_path.exists(), "proof.bin not written");

    let v = run_verify(&proof_path, &store_path);
    assert!(v.success, "verify failed.\nstdout:\n{}\nstderr:\n{}", v.stdout, v.stderr);
    assert!(v.stdout.contains("ACCEPTED"), "verify did not print ACCEPTED:\n{}", v.stdout);
    assert!(v.stdout.contains("visionaryauto.ai"), "verify did not echo the claimed domain:\n{}", v.stdout);
    assert!(store_path.exists(), "nullifier store was not written");
}

#[test]
fn same_email_submitted_twice_second_rejected_as_replay() {
    // SPEC.md §7 must-pass #2:
    //   "Same email submitted twice → second submission rejected (nullifier replay)."
    let tmp = tempfile::tempdir().expect("tempdir");
    let proof_path = tmp.path().join("real.proof.bin");
    let store_path = tmp.path().join("nullifiers.txt");
    let email = fixture("real.eml");
    let tag = pubkey_tag();

    let p = run_prove(&email, &proof_path, &tag, &[]);
    assert!(p.success, "prove failed");

    // First verify: accept.
    let v1 = run_verify(&proof_path, &store_path);
    assert!(v1.success, "first verify failed: {}", v1.stderr);
    assert!(v1.stdout.contains("ACCEPTED"));

    // Second verify of the same proof against the same store: must reject.
    let v2 = run_verify(&proof_path, &store_path);
    assert!(!v2.success, "replay was accepted, must be rejected.\nstdout:\n{}\nstderr:\n{}", v2.stdout, v2.stderr);
    assert!(
        v2.stderr.contains("replay") || v2.stderr.contains("REJECTED"),
        "expected replay/REJECTED in stderr; got:\n{}",
        v2.stderr
    );
}

#[test]
fn email_from_different_domain_than_claimed_guest_panics() {
    // SPEC.md §7 must-pass #3:
    //   "Email from a different domain than claimed_domain → guest panics, no proof."
    // We exercise this via the --claimed-domain override: feed the real email
    // (d=visionaryauto.ai) but tell the guest claimed_domain="evil.example".
    // The §4.2 `d == claimed_domain` assertion fires.
    let tmp = tempfile::tempdir().expect("tempdir");
    let proof_path = tmp.path().join("p.bin");
    let email = fixture("real.eml");
    let tag = pubkey_tag();

    let p = run_prove(&email, &proof_path, &tag, &["--claimed-domain", "evil.example"]);
    assert!(!p.success, "prove succeeded with d != claimed_domain; soundness-critical assertion was bypassed");
    assert!(
        p.stderr.contains("d tag does not match claimed_domain")
            || p.stderr.contains("public-input binding"),
        "expected d-mismatch assertion in stderr; got:\n{}",
        p.stderr
    );
}

#[test]
fn email_with_tampered_body_bh_mismatch_guest_panics() {
    // SPEC.md §7 must-pass #4:
    //   "Email with tampered body → bh mismatch, guest panics."
    let tmp = tempfile::tempdir().expect("tempdir");
    let tampered = tmp.path().join("tampered.eml");
    let proof_path = tmp.path().join("p.bin");
    let tag = pubkey_tag();

    let mut bytes = std::fs::read(fixture("real.eml")).expect("read real.eml");
    // Locate the body (after the first \r\n\r\n) and flip a single byte in it.
    let sep = bytes.windows(4).position(|w| w == b"\r\n\r\n").expect("header/body sep");
    let body_start = sep + 4;
    assert!(body_start < bytes.len(), "body is empty");
    bytes[body_start] ^= 0x01;
    std::fs::write(&tampered, &bytes).expect("write tampered.eml");

    let p = run_prove(&tampered, &proof_path, &tag, &[]);
    assert!(!p.success, "prove succeeded on tampered body");
    assert!(
        p.stderr.contains("computed body hash does not match bh"),
        "expected body-hash mismatch panic; got:\n{}",
        p.stderr
    );
}

#[test]
fn email_with_tampered_dkim_signature_rsa_verify_fails_guest_panics() {
    // SPEC.md §7 must-pass #5:
    //   "Email with tampered DKIM-Signature → RSA verification fails, guest panics."
    // We tamper a single byte inside the b= base64 region. The §4.2 b=
    // host-trust guard (b in header == witness b) doesn't fire because the
    // host re-extracts; the failure surfaces at §4.6 RSA verify.
    let tmp = tempfile::tempdir().expect("tempdir");
    let tampered = tmp.path().join("tampered.eml");
    let proof_path = tmp.path().join("p.bin");
    let tag = pubkey_tag();

    let mut bytes = std::fs::read(fixture("real.eml")).expect("read real.eml");
    // The b= tag in this fixture sits on a continuation line and its value
    // begins with "GwdLg". Anchor on that unique prefix.
    let marker: &[u8] = b"b=GwdLg";
    let pos = bytes.windows(marker.len())
        .position(|w| w == marker)
        .expect("b= base64 prefix in DKIM-Signature");
    // Flip a byte well inside the base64 value (skip past "b=" + a few chars).
    let flip = pos + 4;
    bytes[flip] = if bytes[flip] == b'A' { b'B' } else { b'A' };
    std::fs::write(&tampered, &bytes).expect("write tampered.eml");

    let p = run_prove(&tampered, &proof_path, &tag, &[]);
    assert!(!p.success, "prove succeeded with a flipped byte in the signature");
    assert!(
        p.stderr.contains("RSA signature verification failed"),
        "expected RSA verify failure; got:\n{}",
        p.stderr
    );
}
