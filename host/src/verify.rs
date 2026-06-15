//! SPEC.md §6 verifier (host side).
//!
//! Reads a receipt from disk, runs the zkVM verifier against the embedded
//! image id, extracts PublicOutputs from the journal, checks the
//! nullifier against the local store, appends on accept.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

use methods::GUEST_ID;
use nce_core::PublicOutputs;
use risc0_zkvm::Receipt;

use crate::nullifier_store;

pub struct VerifyArgs<'a> {
    pub proof_path: &'a Path,
    pub nullifier_store_path: &'a Path,
    /// v2-A: the registry root the verifier trusts (hex). When `Some`, the
    /// proof's echoed root must equal it. This is the trust anchor that closes
    /// the v0 pubkey gap: a forger's proof carries a root that won't match.
    pub pinned_registry_root: Option<&'a str>,
}

pub fn run(args: VerifyArgs) -> Result<()> {
    let bytes = fs::read(args.proof_path)
        .with_context(|| format!("reading proof {}", args.proof_path.display()))?;
    let receipt: Receipt = bincode::deserialize(&bytes)
        .context("deserializing receipt")?;

    receipt.verify(GUEST_ID).context("zkVM verifier rejected the receipt")?;

    let outputs: PublicOutputs = receipt.journal.decode()
        .context("decoding PublicOutputs from receipt journal")?;

    let domain_str = String::from_utf8_lossy(&outputs.claimed_domain);
    let nullifier_hex = hex::encode(outputs.nullifier);
    println!("Receipt verifies. claimed_domain: {}", domain_str);

    // v2-A: the registry root is the trust anchor. The honest proof echoes the
    // root it proved membership against; the verifier checks it equals the root
    // it pins. A forger can produce a valid-looking proof only against their
    // OWN registry, whose root won't match — so the pin is what rejects them.
    let root_hex = hex::encode(outputs.registry_root);
    match args.pinned_registry_root {
        Some(pinned) if root_hex.eq_ignore_ascii_case(pinned.trim()) => {
            println!("Registry root: {} (pinned — OK)", root_hex);
        }
        Some(pinned) => {
            bail!(
                "REJECTED: registry root mismatch. proof root {} != pinned {}",
                root_hex,
                pinned.trim()
            );
        }
        None => {
            println!(
                "Registry root: {} (NOT pinned — proof is not bound to a trusted registry; \
                 pass --registry-root to enforce)",
                root_hex
            );
        }
    }

    // v1: disclosure is opt-in. An empty address means the prover proved
    // domain possession without naming anyone (the privacy-preserving mode).
    // When an address IS disclosed, report whether its domain aligns with the
    // signing domain: the org-membership claim ("the domain vouches for this
    // address") holds only when aligned; a misaligned address means the signer
    // (e.g. a mail provider) merely relayed mail naming that address. Alignment
    // is policy the relying party enforces — the guest proves only that the
    // address came from the DKIM-signed header set.
    if outputs.disclosed_address.is_empty() {
        println!("Disclosed address: (none — anonymous within domain)");
    } else {
        let disclosed_str = String::from_utf8_lossy(&outputs.disclosed_address);
        let aligned = address_domain(&outputs.disclosed_address)
            .map(|d| d.eq_ignore_ascii_case(&outputs.claimed_domain))
            .unwrap_or(false);
        println!(
            "Disclosed address: {}  [domain {} signing domain]",
            disclosed_str,
            if aligned { "ALIGNED with" } else { "NOT aligned with" }
        );
    }
    println!("Nullifier: {}", nullifier_hex);

    if nullifier_store::contains(args.nullifier_store_path, &nullifier_hex)? {
        bail!(
            "REJECTED: replay. Nullifier {} already in {}.",
            nullifier_hex,
            args.nullifier_store_path.display()
        );
    }
    nullifier_store::append(args.nullifier_store_path, &nullifier_hex)?;
    println!("ACCEPTED. Nullifier appended to {}.", args.nullifier_store_path.display());
    Ok(())
}

/// The domain part (after the single `@`) of a `local@domain` address.
fn address_domain(addr: &[u8]) -> Option<&[u8]> {
    addr.iter().position(|&b| b == b'@').map(|at| &addr[at + 1..])
}
