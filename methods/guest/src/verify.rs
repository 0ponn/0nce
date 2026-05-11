//! SPEC.md §4 step 6 — RSA-PKCS1#v1.5-SHA256 verify of the DKIM signature
//! over the signed data produced in §4.5.
//!
//! This is the expensive step in the guest. RISC0's bigint accelerator
//! syscalls are reached transitively via `num-bigint` (used by `rsa`);
//! adopting the upstream RISC0 patches for `rsa`/`num-bigint` is a v1
//! prove-time optimization, not done in v0.

use rsa::{pkcs1v15::Pkcs1v15Sign, BigUint, RsaPublicKey};
use sha2::{Digest, Sha256};

/// SPEC.md §4 step 6.
///
/// SHA-256s `signed_data`, then PKCS#1 v1.5 RSA-verifies `signature`
/// against it using the public key (modulus `n`, exponent `e`, both
/// supplied as big-endian byte slices via the `PublicInputs`).
///
/// Panics (= guest aborts = no proof) on any failure: invalid pubkey
/// encoding, signature/hash size mismatch, or cryptographic verification
/// failure. The §7 must-pass #5 and adversarial bit-flip tests exercise
/// these failure paths against a real RSA keypair built in the host.
pub fn verify_rsa_signature(
    signed_data: &[u8],
    signature: &[u8],
    pubkey_n: &[u8],
    pubkey_e: &[u8],
) {
    let n = BigUint::from_bytes_be(pubkey_n);
    let e = BigUint::from_bytes_be(pubkey_e);
    let pubkey = RsaPublicKey::new(n, e).expect("invalid RSA public key");
    let hashed = Sha256::digest(signed_data);
    pubkey
        .verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, signature)
        .expect("RSA signature verification failed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use std::sync::OnceLock;

    /// Generate (private, public) once per test process. RSA-2048 keygen
    /// is ~1-2s; cache it so all tests share one keypair.
    fn keypair() -> &'static (RsaPrivateKey, RsaPublicKey) {
        static KP: OnceLock<(RsaPrivateKey, RsaPublicKey)> = OnceLock::new();
        KP.get_or_init(|| {
            let mut rng = OsRng;
            let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
            let pub_key = RsaPublicKey::from(&priv_key);
            (priv_key, pub_key)
        })
    }

    fn pubkey_bytes(pk: &RsaPublicKey) -> (Vec<u8>, Vec<u8>) {
        (pk.n().to_bytes_be(), pk.e().to_bytes_be())
    }

    fn sign(priv_key: &RsaPrivateKey, signed_data: &[u8]) -> Vec<u8> {
        let hashed = Sha256::digest(signed_data);
        priv_key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &hashed)
            .expect("sign")
    }

    #[test]
    fn happy_path_valid_signature_verifies() {
        let (priv_key, pub_key) = keypair();
        let signed_data = b"any bytes that the signer signed";
        let signature = sign(priv_key, signed_data);
        let (n, e) = pubkey_bytes(pub_key);
        verify_rsa_signature(signed_data, &signature, &n, &e);
    }

    #[test]
    #[should_panic(expected = "RSA signature verification failed")]
    fn bit_flip_in_signature_panics() {
        // SPEC.md §7 soundness sanity check.
        let (priv_key, pub_key) = keypair();
        let signed_data = b"any bytes that the signer signed";
        let mut signature = sign(priv_key, signed_data);
        signature[0] ^= 0x01;
        let (n, e) = pubkey_bytes(pub_key);
        verify_rsa_signature(signed_data, &signature, &n, &e);
    }

    #[test]
    #[should_panic(expected = "RSA signature verification failed")]
    fn tampered_signed_data_panics() {
        // SPEC.md §7 must-pass #5: tampered signed data => verify fails.
        let (priv_key, pub_key) = keypair();
        let signed_data = b"any bytes that the signer signed";
        let signature = sign(priv_key, signed_data);
        let (n, e) = pubkey_bytes(pub_key);
        let tampered = b"DIFFERENT bytes than the signer signed";
        verify_rsa_signature(tampered, &signature, &n, &e);
    }

    #[test]
    #[should_panic(expected = "RSA signature verification failed")]
    fn wrong_pubkey_panics() {
        let (priv_key, _) = keypair();
        let signed_data = b"any bytes";
        let signature = sign(priv_key, signed_data);
        // Build an unrelated keypair and verify against THAT pubkey.
        let mut rng = OsRng;
        let other_priv = RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
        let other_pub = RsaPublicKey::from(&other_priv);
        let (n, e) = pubkey_bytes(&other_pub);
        verify_rsa_signature(signed_data, &signature, &n, &e);
    }
}
