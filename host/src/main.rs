//! Host — SPEC.md §5 (prover side) and §6 (verifier side).
//!
//! Two subcommands planned for v0:
//!
//!   prove   — read an email file + claimed_domain + claimed_pubkey,
//!             build the witness (SPEC.md §5), invoke the zkVM prover,
//!             write the proof artifact and public inputs to disk.
//!
//!   verify  — read a proof artifact + claimed public inputs, run the
//!             zkVM verifier (SPEC.md §6), extract the nullifier, check it
//!             against the local nullifier store, output (accepted,
//!             claimed_domain, nullifier).
//!
//! Not implemented yet. The host is **not trusted**: anything the host could
//! lie about must be re-asserted inside the guest (SPEC.md §5).

fn main() {
    eprintln!("0nce host: not implemented — see SPEC.md §5, §6");
    std::process::exit(1);
}
