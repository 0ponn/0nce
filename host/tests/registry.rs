//! v2-A registry-membership integration tests (design §10). The pinned
//! registry root is the trust anchor; these confirm the prover-forgery hole
//! is closed. Run in RISC0_DEV_MODE=1 — the membership + RSA assertions
//! execute regardless, which is what these check.

use std::path::{Path, PathBuf};
use std::process::Command;

fn cli() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_0nce"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(name)
}

fn read_tag(name: &str) -> String {
    std::fs::read_to_string(fixture(name)).unwrap().trim().to_string()
}

/// Build a one-entry registry for (insider.test, v0test) from a tag fixture;
/// return (registry_path, root_hex).
fn build_registry(dir: &Path, name: &str, tag_fixture: &str) -> (PathBuf, String) {
    let out = dir.join(name);
    let o = Command::new(cli())
        .args(["registry", "build", "--pubkey-tag", &read_tag(tag_fixture),
               "--domain", "insider.test", "--selector", "v0test",
               "--out", out.to_str().unwrap()])
        .env("RISC0_DEV_MODE", "1")
        .output()
        .expect("registry build");
    assert!(o.status.success(), "registry build failed: {}", String::from_utf8_lossy(&o.stderr));
    let stdout = String::from_utf8_lossy(&o.stdout);
    let root = stdout
        .lines()
        .find_map(|l| l.strip_prefix("registry root: "))
        .expect("no root line")
        .trim()
        .to_string();
    (out, root)
}

fn prove(email: &Path, registry: &Path, out: &Path) -> (bool, String) {
    let o = Command::new(cli())
        .args(["prove", "--email", email.to_str().unwrap(),
               "--registry", registry.to_str().unwrap(),
               "--out", out.to_str().unwrap(), "-y"])
        .env("RISC0_DEV_MODE", "1")
        .output()
        .expect("prove");
    (o.status.success(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn verify(proof: &Path, root: Option<&str>, store: &Path) -> (bool, String) {
    let mut args = vec!["verify".to_string(),
        "--proof".into(), proof.to_str().unwrap().into(),
        "--nullifier-store".into(), store.to_str().unwrap().into()];
    if let Some(r) = root {
        args.push("--registry-root".into());
        args.push(r.into());
    }
    let o = Command::new(cli()).args(&args).env("RISC0_DEV_MODE", "1").output().expect("verify");
    let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&o.stderr));
    (o.status.success(), s)
}

#[test]
fn honest_proof_verifies_against_pinned_root() {
    let tmp = tempfile::tempdir().unwrap();
    let (reg, root) = build_registry(tmp.path(), "reg.json", "resigned.pubkey.tag");
    let proof = tmp.path().join("p.bin");
    let (ok, err) = prove(&fixture("resigned_a.eml"), &reg, &proof);
    assert!(ok, "prove failed:\n{err}");
    let (ok, out) = verify(&proof, Some(&root), &tmp.path().join("nf.txt"));
    assert!(ok, "verify rejected:\n{out}");
    assert!(out.contains("pinned — OK"));
    assert!(out.contains("ACCEPTED"));
}

#[test]
fn wrong_pinned_root_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let (reg, _root) = build_registry(tmp.path(), "reg.json", "resigned.pubkey.tag");
    let proof = tmp.path().join("p.bin");
    assert!(prove(&fixture("resigned_a.eml"), &reg, &proof).0);
    let bogus = "deadbeef".repeat(8);
    let (ok, out) = verify(&proof, Some(&bogus), &tmp.path().join("nf.txt"));
    assert!(!ok, "verify accepted a wrong pinned root");
    assert!(out.contains("registry root mismatch"), "got:\n{out}");
}

#[test]
fn email_signed_by_unregistered_key_yields_no_proof() {
    // Registry pins the resigned key for (insider.test, v0test). An email
    // signed by a DIFFERENT key for the same domain/selector cannot prove:
    // the registered key is used for RSA verify, which fails.
    let tmp = tempfile::tempdir().unwrap();
    let (reg, _root) = build_registry(tmp.path(), "reg.json", "resigned.pubkey.tag");
    let proof = tmp.path().join("p.bin");
    let (ok, err) = prove(&fixture("org_nonh_to.eml"), &reg, &proof);
    assert!(!ok, "prove succeeded for an unregistered signing key");
    assert!(err.contains("RSA signature verification failed"), "got:\n{err}");
}

#[test]
fn forger_own_registry_rejected_against_real_root() {
    // A forger signs with their own key and builds their OWN registry. The
    // proof is internally valid but carries the forger's root; pinning the
    // real root rejects it.
    let tmp = tempfile::tempdir().unwrap();
    let (_real, real_root) = build_registry(tmp.path(), "real.json", "resigned.pubkey.tag");
    let (forger_reg, _fr) = build_registry(tmp.path(), "forger.json", "org.pubkey.tag");
    let proof = tmp.path().join("p.bin");
    let (ok, err) = prove(&fixture("org_nonh_to.eml"), &forger_reg, &proof);
    assert!(ok, "forger prove failed unexpectedly:\n{err}");
    let (ok, out) = verify(&proof, Some(&real_root), &tmp.path().join("nf.txt"));
    assert!(!ok, "forger proof accepted against the real pinned root");
    assert!(out.contains("registry root mismatch"), "got:\n{out}");
}

#[test]
fn unpinned_verify_warns_but_is_not_bound() {
    let tmp = tempfile::tempdir().unwrap();
    let (reg, _root) = build_registry(tmp.path(), "reg.json", "resigned.pubkey.tag");
    let proof = tmp.path().join("p.bin");
    assert!(prove(&fixture("resigned_a.eml"), &reg, &proof).0);
    let (ok, out) = verify(&proof, None, &tmp.path().join("nf.txt"));
    assert!(ok);
    assert!(out.contains("NOT pinned"), "expected unpinned warning:\n{out}");
}
