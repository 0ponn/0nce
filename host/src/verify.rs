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
