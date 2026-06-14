//! v1 design §8 — selective identity-header disclosure tests.
//!
//! Must-pass (the disclosure reveals the signed address and verifies) plus
//! the load-bearing adversarial cases: header-prepend safety, a disclosed
//! header not covered by `h=`, and a malformed address. All run in
//! `RISC0_DEV_MODE=1` (fast, fake receipts) — they exercise the guest
//! pipeline's logic and panics, which is what these assertions check.

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

fn read_tag(name: &str) -> String {
    std::fs::read_to_string(fixture(name))
        .unwrap_or_else(|_| panic!("fixture {name} missing"))
        .trim()
        .to_string()
}

fn run_prove(email: &Path, out: &Path, tag: &str, disclose: &str) -> (bool, String, String) {
    let o = Command::new(cli_path())
        .args([
            "prove",
            "--email", email.to_str().unwrap(),
            "--out", out.to_str().unwrap(),
            "--pubkey-tag", tag,
            "--disclose", disclose,
            "-y",
        ])
        .env("RISC0_DEV_MODE", "1")
        .output()
        .expect("prove subprocess");
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn run_verify(proof: &Path, store: &Path) -> (bool, String, String) {
    let o = Command::new(cli_path())
        .args([
            "verify",
            "--proof", proof.to_str().unwrap(),
            "--nullifier-store", store.to_str().unwrap(),
        ])
        .env("RISC0_DEV_MODE", "1")
        .output()
        .expect("verify subprocess");
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// The `local@domain` from the verifier's "Disclosed address: X  [..]" line.
fn disclosed_address(verify_stdout: &str) -> String {
    verify_stdout
        .lines()
        .find_map(|l| l.strip_prefix("Disclosed address: "))
        .expect("verify output missing Disclosed address line")
        .split("  [")
        .next()
        .unwrap()
        .trim()
        .to_string()
}

// -- Must-pass --------------------------------------------------------------

#[test]
fn disclose_from_reveals_signed_address_and_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let proof = tmp.path().join("p.bin");
    let store = tmp.path().join("nf.txt");
    let tag = read_tag("resigned.pubkey.tag");

    let (ok, _o, err) = run_prove(&fixture("resigned_a.eml"), &proof, &tag, "from");
    assert!(ok, "prove failed:\n{err}");
    let (ok, out, err) = run_verify(&proof, &store);
    assert!(ok, "verify rejected:\n{out}{err}");
    assert_eq!(disclosed_address(&out), "whistle@insider.test");
    assert!(out.contains("ALIGNED with signing domain"), "expected aligned:\n{out}");
    assert!(out.contains("ACCEPTED"));
}

#[test]
fn disclose_to_reveals_recipient_address() {
    let tmp = tempfile::tempdir().unwrap();
    let proof = tmp.path().join("p.bin");
    let store = tmp.path().join("nf.txt");
    let tag = read_tag("resigned.pubkey.tag");

    let (ok, _o, err) = run_prove(&fixture("resigned_a.eml"), &proof, &tag, "to");
    assert!(ok, "prove failed:\n{err}");
    let (ok, out, err) = run_verify(&proof, &store);
    assert!(ok, "verify rejected:\n{out}{err}");
    // resigned_a's To is at a different domain than d= (insider.test): a
    // legitimately-disclosed recipient address the verifier flags as not aligned.
    assert_eq!(disclosed_address(&out), "v@example.org");
    assert!(out.contains("NOT aligned with signing domain"), "expected not-aligned:\n{out}");
}

// -- Adversarial (load-bearing) --------------------------------------------

#[test]
fn header_prepend_discloses_the_signed_instance_not_the_forgery() {
    // Prepend an unsigned `From:` above the signed one. The guest must
    // disclose the bottom-most (signed) instance, never the attacker's.
    let tmp = tempfile::tempdir().unwrap();
    let tampered = tmp.path().join("prepended.eml");
    let proof = tmp.path().join("p.bin");
    let store = tmp.path().join("nf.txt");
    let tag = read_tag("resigned.pubkey.tag");

    let mut bytes = b"From: attacker@evil.test\r\n".to_vec();
    bytes.extend_from_slice(&std::fs::read(fixture("resigned_a.eml")).unwrap());
    std::fs::write(&tampered, &bytes).unwrap();

    let (ok, _o, err) = run_prove(&tampered, &proof, &tag, "from");
    assert!(ok, "prove failed (RSA should still verify the signed From):\n{err}");
    let (ok, out, err) = run_verify(&proof, &store);
    assert!(ok, "verify rejected:\n{out}{err}");
    assert_eq!(disclosed_address(&out), "whistle@insider.test");
    assert!(!out.contains("attacker@evil.test"), "disclosed the forged header:\n{out}");
}

#[test]
fn disclosing_a_non_h_header_panics() {
    // org_nonh_to.eml signs h=from:subject:date — To is present but NOT
    // covered. Disclosing To must abort (no proof).
    let tmp = tempfile::tempdir().unwrap();
    let proof = tmp.path().join("p.bin");
    let tag = read_tag("org.pubkey.tag");

    let (ok, _o, err) = run_prove(&fixture("org_nonh_to.eml"), &proof, &tag, "to");
    assert!(!ok, "prove succeeded disclosing a non-h= header");
    assert!(
        err.contains("not covered by the DKIM h= tag"),
        "expected h= coverage panic; got:\n{err}"
    );
}

#[test]
fn malformed_disclosed_address_panics() {
    // org_malformed_from.eml has a signed `From: noatsign-here` (no address).
    let tmp = tempfile::tempdir().unwrap();
    let proof = tmp.path().join("p.bin");
    let tag = read_tag("org.pubkey.tag");

    let (ok, _o, err) = run_prove(&fixture("org_malformed_from.eml"), &proof, &tag, "from");
    assert!(!ok, "prove succeeded on a malformed From address");
    assert!(err.contains("'@'"), "expected address-parse panic; got:\n{err}");
}
