//! SPEC.md §5 host (prover side).
//!
//! Reads an email file, locates and pre-parses the DKIM-Signature header
//! to populate the witness, resolves the public key out-of-band (DNS or
//! a `--pubkey-tag` override), prompts the operator to confirm, invokes
//! the RISC0 prover, writes the serialized receipt to disk.

use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;

use methods::GUEST_ELF;
use nce_core::{PublicInputs, Witness};
use risc0_zkvm::{default_prover, ExecutorEnv};

use crate::dns;
use crate::email;

pub struct ProveArgs<'a> {
    pub email_path: &'a Path,
    pub out_path: &'a Path,
    pub pubkey_tag_override: Option<&'a str>,
    pub assume_yes: bool,
    /// Adversarial-test hook: replace the claimed_domain public input
    /// with these bytes. Normally the CLI uses parsed.domain from the
    /// DKIM-Signature's d= tag. SPEC.md §7 adversarial #1 / #2 / must-
    /// pass #3 set this to inject a mismatch and exercise the guest's
    /// soundness-critical `d == claimed_domain` assertion.
    pub claimed_domain_override: Option<&'a str>,
    /// Adversarial-test hook: point dkim_header_index at this byte offset
    /// instead of the first DKIM-Signature email::extract would find.
    /// SPEC.md §7 adversarial #3 uses this to point at a planted second
    /// header and verify v0 considers only the witnessed one.
    pub dkim_header_offset_override: Option<u32>,
}

pub fn run(args: ProveArgs) -> Result<()> {
    let email_raw = fs::read(args.email_path)
        .with_context(|| format!("reading email {}", args.email_path.display()))?;

    let parsed = match args.dkim_header_offset_override {
        Some(off) => {
            eprintln!("  dkim_header_offset: OVERRIDDEN ({})", off);
            email::extract_at(&email_raw, off as usize)
                .context("extracting DKIM-Signature fields at overridden offset")?
        }
        None => email::extract(&email_raw)
            .context("extracting DKIM-Signature fields from email")?,
    };

    let domain_str = std::str::from_utf8(&parsed.domain)?;
    let selector_str = std::str::from_utf8(&parsed.selector)?;
    println!("Email parsed:");
    println!("  domain    : {}", domain_str);
    println!("  selector  : {}", selector_str);

    let pubkey = if let Some(tag) = args.pubkey_tag_override {
        println!("  pubkey    : (from --pubkey-tag override)");
        dns::parse_dkim_tag(tag)?
    } else {
        println!("  resolving {}._domainkey.{} via dig ...", selector_str, domain_str);
        let pk = dns::lookup(&parsed.domain, &parsed.selector)?;
        println!("  pubkey    : RSA-{}-bit (n={} bytes BE)", pk.n.len() * 8, pk.n.len());
        if !args.assume_yes {
            print!("Confirm this pubkey is currently published for {} (y/N)? ", domain_str);
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                bail!("operator declined; not proving");
            }
        }
        pk
    };

    let witness = Witness {
        email_raw,
        dkim_header_index: parsed.header_index,
        selector: parsed.selector.clone(),
        signature: parsed.signature_b64,
        body_hash: parsed.body_hash_b64,
    };
    let claimed_domain = match args.claimed_domain_override {
        Some(s) => {
            eprintln!("  claimed_domain: OVERRIDDEN (--claimed-domain {}), expect d != claimed_domain panic in guest", s);
            s.as_bytes().to_vec()
        }
        None => parsed.domain,
    };
    let public_inputs = PublicInputs {
        claimed_domain,
        claimed_pubkey_n: pubkey.n,
        claimed_pubkey_e: pubkey.e,
    };

    println!("Invoking RISC0 prover. This may take minutes ...");
    let env = ExecutorEnv::builder()
        .write(&witness)?
        .write(&public_inputs)?
        .build()?;
    let prover = default_prover();
    let prove_info = prover.prove(env, GUEST_ELF)?;
    let receipt = prove_info.receipt;
    println!("Proof produced.");

    let receipt_bytes = bincode::serialize(&receipt)
        .context("serializing receipt with bincode")?;
    fs::write(args.out_path, &receipt_bytes)
        .with_context(|| format!("writing receipt to {}", args.out_path.display()))?;
    println!("Receipt: {} ({} bytes)", args.out_path.display(), receipt_bytes.len());

    Ok(())
}
