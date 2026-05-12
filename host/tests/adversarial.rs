//! SPEC.md §7 adversarial tests — "the part most ZK projects skip."
//!
//! These probe a *malicious prover* who controls the prover code. They are
//! the load-bearing part of the soundness story for v0.
//!
//! Includes the §7 "Soundness sanity check" items at the bottom.

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

fn run_prove(email: &Path, out: &Path, pubkey_tag: &str, extra: &[&str]) -> (bool, String, String) {
    let mut cmd = Command::new(cli_path());
    cmd.args([
        "prove",
        "--email", email.to_str().unwrap(),
        "--out", out.to_str().unwrap(),
        "--pubkey-tag", pubkey_tag,
        "-y",
    ]);
    cmd.args(extra);
    cmd.env("RISC0_DEV_MODE", "1");
    let o = cmd.output().expect("prove subprocess");
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

// -- Adversarial: prover with bad intent ------------------------------------

#[test]
fn prover_lies_about_claimed_domain_in_public_inputs_guest_catches_mismatch() {
    // SPEC.md §7 adversarial #1: prover supplies a valid email but lies
    // about claimed_domain in public inputs. The guest's §4.2 `d ==
    // claimed_domain` assertion catches it.
    let tmp = tempfile::tempdir().unwrap();
    let proof = tmp.path().join("p.bin");
    let (ok, _out, err) = run_prove(
        &fixture("real.eml"),
        &proof,
        &pubkey_tag(),
        &["--claimed-domain", "attacker.example"],
    );
    assert!(!ok, "prove succeeded despite d != claimed_domain (soundness-critical)");
    assert!(
        err.contains("d tag does not match claimed_domain") || err.contains("public-input binding"),
        "expected the public-input binding panic; got stderr:\n{}",
        err
    );
}

#[test]
fn prover_forges_dkim_with_own_key_claims_different_domain_must_fail() {
    // SPEC.md §7 adversarial #2: the same attack class as #1 but framed
    // around the attacker having generated their own RSA key.
    //
    // Concretely: a prover wishing to claim "email from victim.example"
    // would have to (a) get a valid DKIM-signed email with d=victim.example
    // (which they don't have because they don't control victim.example's
    // key), or (b) lie about claimed_domain while supplying an email signed
    // for some OTHER domain. Path (b) is exactly the test below — feed an
    // email with d=visionaryauto.ai but claim victim.example. The §4.2
    // `d == claimed_domain` assertion catches it.
    //
    // (Note: v0 does NOT defend against an attacker who supplies a
    // self-signed email with d=victim.example and lies about
    // claimed_pubkey. That weakness is documented in SPEC.md §6 step 2
    // and the README; the verifier-side DNS check closes it.)
    let tmp = tempfile::tempdir().unwrap();
    let proof = tmp.path().join("p.bin");
    let (ok, _out, err) = run_prove(
        &fixture("real.eml"),
        &proof,
        &pubkey_tag(),
        &["--claimed-domain", "victim.example"],
    );
    assert!(!ok, "prove succeeded; the public-input binding was bypassed");
    assert!(
        err.contains("d tag does not match claimed_domain") || err.contains("public-input binding"),
        "expected d-mismatch panic; got:\n{}",
        err
    );
}

#[test]
fn email_with_two_dkim_signature_headers_only_indexed_one_considered() {
    // SPEC.md §7 adversarial #3:
    //   "Prover supplies an email with TWO DKIM-Signature headers, one
    //    valid and one for the claimed domain. Must not be exploitable.
    //    v0 behavior: only the header at dkim_header_index is considered;
    //    if it is not the claimed domain, fail."
    //
    // Construction: prepend a FAKE DKIM-Signature header to the real .eml.
    // The fake declares d=visionaryauto.ai (so the §4.2 d-match passes)
    // and a bh of all-zeros (so the §4.4 body hash check will fail).
    // Point --dkim-header-offset at the fake (offset 0). The guest must
    // process the fake header, not magically pick the real one below it.
    let tmp = tempfile::tempdir().unwrap();
    let planted = tmp.path().join("two_dkim.eml");
    let proof = tmp.path().join("p.bin");
    let tag = pubkey_tag();

    // bh value: base64 of 32 zero bytes. The SHA-256 of the real body
    // will not match, so the guest panics at §4.4.
    let fake_bh = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    // b= value: 4 'A's is valid base64 (3 zero bytes). We don't reach
    // RSA verify because §4.4 fails first.
    let fake_b = "AAAA";
    let fake_header = format!(
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; \
         d=visionaryauto.ai; s=google; h=From; bh={fake_bh}; b={fake_b}\r\n"
    );

    let mut bytes = fake_header.into_bytes();
    bytes.extend_from_slice(&std::fs::read(fixture("real.eml")).unwrap());
    std::fs::write(&planted, &bytes).unwrap();

    let (ok, _out, err) = run_prove(
        &planted,
        &proof,
        &tag,
        &["--dkim-header-offset", "0"],
    );
    assert!(!ok, "prove succeeded; the guest may not be honoring dkim_header_index");
    assert!(
        err.contains("computed body hash does not match bh"),
        "expected body-hash mismatch from the planted fake header; got:\n{}",
        err
    );
}

#[test]
fn malformed_inputs_never_produce_a_proof() {
    // SPEC.md §7 adversarial #4: empty email, malformed email, email with
    // no DKIM-Signature, email with malformed DKIM tags → all fail
    // gracefully, never produce a proof.
    let tmp = tempfile::tempdir().unwrap();
    let proof = tmp.path().join("p.bin");
    let tag = pubkey_tag();

    // Case A: empty file.
    let empty = tmp.path().join("empty.eml");
    std::fs::write(&empty, b"").unwrap();
    let (ok, _out, _err) = run_prove(&empty, &proof, &tag, &[]);
    assert!(!ok, "prove succeeded on empty .eml");

    // Case B: no DKIM-Signature header.
    let nosig = tmp.path().join("nosig.eml");
    std::fs::write(&nosig, b"From: a@b\r\nSubject: no dkim\r\n\r\nBody\r\n").unwrap();
    let (ok, _out, _err) = run_prove(&nosig, &proof, &tag, &[]);
    assert!(!ok, "prove succeeded on email with no DKIM-Signature");

    // Case C: DKIM-Signature header with a malformed tag list (no '=' on a tag).
    let bad_tags = tmp.path().join("badtags.eml");
    std::fs::write(
        &bad_tags,
        b"From: a@b\r\nDKIM-Signature: bogus content with no equals signs at all\r\n\r\nBody\r\n",
    )
    .unwrap();
    let (ok, _out, _err) = run_prove(&bad_tags, &proof, &tag, &[]);
    assert!(!ok, "prove succeeded on malformed DKIM tags");

    // Case D: garbage bytes (not even ASCII).
    let garbage = tmp.path().join("garbage.eml");
    std::fs::write(&garbage, b"\xff\xff\xff\xff\xff\xff\xff\xff").unwrap();
    let (ok, _out, _err) = run_prove(&garbage, &proof, &tag, &[]);
    assert!(!ok, "prove succeeded on raw garbage bytes");
}

#[test]
#[ignore = "needs a second .eml fixture: the same content signed under a different DKIM key/timestamp by the same domain, to confirm distinct nullifiers"]
fn re_signed_email_yields_different_nullifier_both_accepted() {
    // SPEC.md §7 adversarial #5:
    //   "Same email body, different DKIM-Signature (re-signed) → different
    //    nullifier, both accepted."
    //
    // Requires a second fixture (e.g., re-send the same Test email and
    // capture a second .eml whose DKIM-Signature's b= differs). v0
    // computes nullifier = Poseidon(domain_sep, claimed_domain, signature),
    // so different b= => different nullifier => both accepted as distinct
    // events. Test stays ignored until a second fixture is available.
    unimplemented!("SPEC.md §7 adversarial #5");
}

// -- Soundness sanity check -------------------------------------------------

#[test]
fn bit_flip_in_signature_panics_in_guest() {
    // SPEC.md §7 soundness sanity check: flip a single bit in the
    // signature, regenerate proof → should panic in guest, no proof.
    // Equivalent in effect to must-pass #5 but framed as a sanity check
    // on the §4.6 RSA verify.
    let tmp = tempfile::tempdir().unwrap();
    let tampered = tmp.path().join("tampered.eml");
    let proof = tmp.path().join("p.bin");
    let tag = pubkey_tag();

    let mut bytes = std::fs::read(fixture("real.eml")).unwrap();
    let marker: &[u8] = b"b=GwdLg";
    let pos = bytes.windows(marker.len()).position(|w| w == marker).unwrap();
    bytes[pos + 4] ^= 0x01; // single bit flip inside the base64 value
    std::fs::write(&tampered, &bytes).unwrap();

    let (ok, _out, err) = run_prove(&tampered, &proof, &tag, &[]);
    assert!(!ok, "prove succeeded on a single-bit-flipped signature");
    assert!(
        err.contains("RSA signature verification failed"),
        "expected RSA verify failure; got:\n{}",
        err
    );
}

#[test]
fn bit_flip_in_proof_artifact_verifier_rejects() {
    // SPEC.md §7 soundness sanity check: flip a bit in the proof artifact
    // itself after generation → verifier should reject.
    let tmp = tempfile::tempdir().unwrap();
    let proof = tmp.path().join("p.bin");
    let store = tmp.path().join("nullifiers.txt");
    let (ok, _out, _err) = run_prove(&fixture("real.eml"), &proof, &pubkey_tag(), &[]);
    assert!(ok, "prerequisite prove failed");

    // Flip a byte in the middle of the proof artifact.
    let mut bytes = std::fs::read(&proof).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    std::fs::write(&proof, &bytes).unwrap();

    let (ok, _out, _err) = run_verify(&proof, &store);
    assert!(!ok, "verifier accepted a bit-flipped proof artifact");
}
