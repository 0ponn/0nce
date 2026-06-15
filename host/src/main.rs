//! 0nce host CLI. SPEC.md §5 (prove) and §6 (verify).

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use nce_core::HeaderKind;
use std::path::PathBuf;

/// CLI spelling of `Option<nce_core::HeaderKind>` (v1 `--disclose`).
/// `None` is the privacy-preserving default: prove domain possession, reveal
/// no address.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum DiscloseArg {
    None,
    From,
    To,
}

impl From<DiscloseArg> for Option<HeaderKind> {
    fn from(d: DiscloseArg) -> Self {
        match d {
            DiscloseArg::None => Option::None,
            DiscloseArg::From => Some(HeaderKind::From),
            DiscloseArg::To => Some(HeaderKind::To),
        }
    }
}

mod dns;
mod email;
mod nullifier_store;
mod prove;
mod registry;
mod verify;

#[derive(Parser)]
#[command(name = "0nce", about = "ZK-Email insider proof, v0 (SPEC.md)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Produce a zero-knowledge proof that the email was DKIM-signed by its
    /// claimed domain. Resolves the public key via DNS by default; use
    /// --pubkey-tag for offline mode (test fixtures).
    Prove {
        /// Path to a raw RFC 5322 email file (.eml).
        #[arg(long)]
        email: PathBuf,

        /// Path to write the proof artifact. Defaults to <email>.proof.bin.
        #[arg(long)]
        out: Option<PathBuf>,

        /// DKIM1 TXT record text, e.g. "v=DKIM1; k=rsa; p=MIIBIj...".
        /// When supplied, skips the DNS lookup. Use this for test fixtures
        /// or air-gapped operation.
        #[arg(long)]
        pubkey_tag: Option<String>,

        /// Skip the interactive pubkey-confirmation prompt.
        #[arg(long, short = 'y')]
        yes: bool,

        /// Override the claimed_domain public input. Normally the CLI uses
        /// the d= tag from the email's DKIM-Signature header; this flag
        /// lets the SPEC.md §7 adversarial tests inject a mismatch to
        /// exercise the soundness-critical `d == claimed_domain` assertion.
        #[arg(long)]
        claimed_domain: Option<String>,

        /// Override dkim_header_index. Normally the CLI uses the byte
        /// offset of the first DKIM-Signature in the email; this flag
        /// lets the SPEC.md §7 adversarial #3 test point at a planted
        /// second DKIM-Signature header and confirm v0 considers only
        /// the witnessed one.
        #[arg(long)]
        dkim_header_offset: Option<u32>,

        /// v1: which signed identity header to disclose. `none` (default) is
        /// the privacy-preserving v0 mode — prove domain possession, reveal no
        /// address. `from`/`to` reveal that signed header's email address as a
        /// public output. Disclosure is opt-in. v1 design §6.
        #[arg(long, value_enum, default_value_t = DiscloseArg::None)]
        disclose: DiscloseArg,

        /// v2-A: path to a registry.json (built by `0nce registry build`). The
        /// signing key + Merkle path are looked up here and the proof binds to
        /// the registry root. Without it, a 1-entry registry is built inline
        /// from --pubkey-tag or DNS.
        #[arg(long)]
        registry: Option<PathBuf>,
    },
    /// Verify a proof artifact and check its nullifier against the local store.
    Verify {
        /// Path to the proof artifact (output of `prove`).
        #[arg(long)]
        proof: PathBuf,

        /// Path to the nullifier store. Defaults to $HOME/.0nce/nullifiers.txt.
        #[arg(long)]
        nullifier_store: Option<PathBuf>,

        /// v2-A: the registry root the verifier pins (hex). When given, the
        /// proof's echoed root must equal it or the proof is rejected — this
        /// is the trust anchor. When omitted, the root is reported but not
        /// enforced (the proof is not bound to a trusted registry).
        #[arg(long)]
        registry_root: Option<String>,
    },
    /// v2-A: build a DKIM key registry (the trusted key set + Merkle root).
    Registry {
        #[command(subcommand)]
        action: RegistryCmd,
    },
}

#[derive(Subcommand)]
enum RegistryCmd {
    /// Build a registry.json and print its root.
    Build {
        /// File of `<domain> <selector>` lines, resolved via DNS.
        #[arg(long)]
        domains: Option<PathBuf>,
        /// Offline single-entry build: the DKIM1 TXT record text.
        #[arg(long)]
        pubkey_tag: Option<String>,
        /// Domain for the --pubkey-tag entry.
        #[arg(long)]
        domain: Option<String>,
        /// Selector for the --pubkey-tag entry.
        #[arg(long)]
        selector: Option<String>,
        /// Where to write registry.json.
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Prove { email, out, pubkey_tag, yes, claimed_domain, dkim_header_offset, disclose, registry } => {
            let out_path = out.unwrap_or_else(|| {
                let mut p = email.clone();
                let stem = p.file_stem().map(|s| s.to_owned()).unwrap_or_default();
                p.set_file_name({
                    let mut s = stem;
                    s.push(".proof.bin");
                    s
                });
                p
            });
            prove::run(prove::ProveArgs {
                email_path: &email,
                out_path: &out_path,
                pubkey_tag_override: pubkey_tag.as_deref(),
                assume_yes: yes,
                claimed_domain_override: claimed_domain.as_deref(),
                dkim_header_offset_override: dkim_header_offset,
                disclose: disclose.into(),
                registry_path: registry.as_deref(),
            })
        }
        Cmd::Verify { proof, nullifier_store, registry_root } => {
            let store = nullifier_store.unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                PathBuf::from(home).join(".0nce").join("nullifiers.txt")
            });
            verify::run(verify::VerifyArgs {
                proof_path: &proof,
                nullifier_store_path: &store,
                pinned_registry_root: registry_root.as_deref(),
            })
        }
        Cmd::Registry { action } => match action {
            RegistryCmd::Build { domains, pubkey_tag, domain, selector, out } => {
                let reg = if let Some(list) = domains {
                    let text = std::fs::read_to_string(&list)?;
                    let mut keys = Vec::new();
                    for line in text.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        let mut it = line.split_whitespace();
                        let d = it.next().ok_or_else(|| anyhow::anyhow!("bad line: {line}"))?;
                        let s = it.next().ok_or_else(|| anyhow::anyhow!("missing selector: {line}"))?;
                        println!("  resolving {s}._domainkey.{d} ...");
                        let pk = dns::lookup(d.as_bytes(), s.as_bytes())?;
                        keys.push((d.to_string(), s.to_string(), pk.n, pk.e));
                    }
                    registry::RegistryFile::build(keys)
                } else if let (Some(tag), Some(d), Some(s)) = (pubkey_tag, domain, selector) {
                    registry::RegistryFile::build_from_tag(&d, &s, &tag)?
                } else {
                    anyhow::bail!("provide --domains <file>, or --pubkey-tag with --domain and --selector");
                };
                reg.save(&out)?;
                println!("registry root: {}", reg.root);
                println!("entries: {}  ->  {}", reg.entries.len(), out.display());
                Ok(())
            }
        },
    }
}
