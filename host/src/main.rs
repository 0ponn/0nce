//! 0nce host CLI. SPEC.md §5 (prove) and §6 (verify).

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use nce_core::HeaderKind;
use std::path::PathBuf;

/// CLI spelling of `nce_core::HeaderKind` (v1 `--disclose`).
#[derive(Clone, Copy, Debug, ValueEnum)]
enum DiscloseArg {
    From,
    To,
}

impl From<DiscloseArg> for HeaderKind {
    fn from(d: DiscloseArg) -> Self {
        match d {
            DiscloseArg::From => HeaderKind::From,
            DiscloseArg::To => HeaderKind::To,
        }
    }
}

mod dns;
mod email;
mod nullifier_store;
mod prove;
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

        /// v1: which signed identity header to disclose (From or To). The
        /// guest reveals that header's email address as a public output,
        /// asserting its domain equals claimed_domain. v1 design §6.
        #[arg(long, value_enum, default_value_t = DiscloseArg::From)]
        disclose: DiscloseArg,
    },
    /// Verify a proof artifact and check its nullifier against the local store.
    Verify {
        /// Path to the proof artifact (output of `prove`).
        #[arg(long)]
        proof: PathBuf,

        /// Path to the nullifier store. Defaults to $HOME/.0nce/nullifiers.txt.
        #[arg(long)]
        nullifier_store: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Prove { email, out, pubkey_tag, yes, claimed_domain, dkim_header_offset, disclose } => {
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
            })
        }
        Cmd::Verify { proof, nullifier_store } => {
            let store = nullifier_store.unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                PathBuf::from(home).join(".0nce").join("nullifiers.txt")
            });
            verify::run(verify::VerifyArgs {
                proof_path: &proof,
                nullifier_store_path: &store,
            })
        }
    }
}
