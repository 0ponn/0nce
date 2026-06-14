# 0nce — ZK-Email Insider Proof, v0

**Status: v0 learning scope.** CLI in, CLI out. Single prover, single verifier, single domain. See `SPEC.md` for the full specification — this README is a précis with the critical caveats pulled forward.

## What this proves

The proof, when verified, convinces the verifier of exactly this:

> The prover possesses an email message *M* and a DKIM-Signature header *H* such that *H* is well-formed per RFC 6376, the signing domain in *H* equals the public input `claimed_domain`, the RSA signature in *H* verifies against `claimed_pubkey` over the canonicalized signed portion of *M* per *H*'s `c=` and `h=` tags, and the nullifier *N* = Poseidon(`domain_separator_v0`, `claimed_domain`, *H*.signature) has not been seen by the verifier before.

See `SPEC.md` §2 for the exact statement.

## What this does NOT prove

Read this carefully. These are deliberately **not** claims the proof makes:

- The proof does **not** claim the prover authored the email.
- The proof does **not** claim the prover is the recipient.
- The proof does **not** claim the email is recent.
- The proof does **not** claim the prover currently works at `claimed_domain`.
- The proof claims only that the prover, at some point, came into possession of a message DKIM-signed by `claimed_domain`. **Anyone who ever received such a message — including a forwarded copy — can produce this proof.**

Many ZK-Email projects describe their proofs in terms of the first four bullets. This project deliberately does not. The proof is honest about what it actually shows.

## Known soundness gap in v0

The DKIM selector is private in v0 (see `SPEC.md` §3, §6 step 2). Therefore the verifier accepts the `claimed_pubkey` as a public input **from the prover** and must out-of-band confirm via a separate DNS query that this pubkey is currently or recently published for the claimed domain.

**Stated plainly:** a malicious prover could supply a pubkey they control, sign a fake "DKIM" message with their own key, claim a domain they do not control, and produce a proof that passes the in-zkVM check. The proof is sound *internally* but the verifier-side DNS check is what closes the loop — and v0 makes that step manual.

This is a known weakness, documented here and in `SPEC.md` §6. v1 will fix it via one of:

- making the selector public,
- proving against a Merkle tree of known-good pubkeys for the domain, or
- DNSSEC-in-ZK.

Each has tradeoffs. v0 punts.

## Scope limitations in v0

- Signature algorithm: `rsa-sha256` only.
- Canonicalization: `relaxed/relaxed` only.
- DNS lookup: out-of-band, manual.
- No network transport, no UI, no platform.
- Anyone who possesses the email (including a forwarded copy) can prove. No recipient binding, no freshness.

See `SPEC.md` §8 for what's deferred to v1.

## v1 — identity-header disclosure

v1 adds **opt-in selective disclosure of one signed identity header** on top
of the v0 proof. Design: `docs/superpowers/specs/2026-06-13-0nce-v1-design.md`.

**Disclosure is off by default — nobody is named unless the prover explicitly
asks for it.** With `--disclose none` (the default) v1 behaves exactly like v0:
it proves possession of an email DKIM-signed by `claimed_domain` and reveals no
address. With `--disclose from|to`, the proof additionally reveals that signed
header's email address **from inside the DKIM-signed header set**, so the
verifier learns an address the signing domain's key actually covered:

> … and the header named by `disclosed_header_kind` is covered by *H*'s `h=`
> tag, and its parsed address `disclosed_address` (revealed as a public output)
> was taken from that signed header.

This is the **org-membership wedge**: "`claimed_domain`'s key signed an email
naming `alice@claimed_domain`."

**What v1 adds to the NOT-proved list** (only when disclosure is opted into):

- v1 does **not** prove the prover *is*, or controls, `disclosed_address`. It
  is still possession-based — a forwarded copy proves it. Identity binding
  needs recipient binding (deferred).
- The guest does **not** assert the disclosed address's domain equals the
  signing domain. Real mail is often signed by a provider whose `d=` differs
  from the From domain. The verifier reports **ALIGNED / NOT aligned**; the
  org-membership claim holds only when aligned. Soundness — that the address
  came from the signed set and not a forged/prepended header — is enforced in
  the guest regardless.

**v1 is a capability demo, NOT production-sound for high-stakes use (e.g.
lending).** The v0 pubkey-trust gap above is unchanged: a malicious prover who
supplies their own key can forge any address *and* its disclosure. Closing
that gap is a prerequisite for production and is tracked separately.

## Build / run

Prerequisites: [`rzup`](https://dev.risczero.com/api/zkvm/install) for the RISC0 toolchain, Rust 1.91+ for the host (pinned in `rust-toolchain.toml`), and `dig` for DNS lookups of DKIM public keys (or use `--pubkey-tag` for offline mode).

Build everything:

```sh
cargo build --release
```

Prove a DKIM-signed email:

```sh
cargo run --release --bin 0nce -- prove \
  --email path/to/your.eml \
  --out /tmp/your.proof.bin          # default: no address disclosed
# add --disclose from   (or --disclose to)   to reveal that signed address
```

The host extracts the DKIM-Signature header, looks up the signer's public key via `dig +short TXT <selector>._domainkey.<domain>`, prompts you to confirm the key (since the v0 design treats the pubkey as out-of-trust-boundary, see §6 step 2 weakness above), and runs the zkVM prover. Pass `-y` to skip the confirmation prompt, or `--pubkey-tag "v=DKIM1; ..."` to supply the TXT record directly without DNS. `--disclose none|from|to` (default `none`) selects whether — and which — signed identity header's address is revealed; `none` keeps the prover anonymous within the domain.

Verify a proof:

```sh
cargo run --release --bin 0nce -- verify \
  --proof /tmp/your.proof.bin \
  --nullifier-store ~/.0nce/nullifiers.txt
```

Replay protection: each accepted proof appends its nullifier to the store; resubmission of the same proof against the same store is rejected.

### Running the test suite

```sh
cargo test                          # workspace + host unit + integration
RISC0_DEV_MODE=1 cargo test         # use the dev-mode prover for fast iteration
cd methods/guest && cargo test      # guest crate unit tests
```

A real DKIM-signed test fixture lives at `host/tests/fixtures/real.eml` with the matching DKIM TXT record at `host/tests/fixtures/real.pubkey.tag`. The `host/tests/{must_pass,adversarial,disclosure}.rs` integration tests exercise the full prove → verify CLI flow under `RISC0_DEV_MODE=1`. Synthetic, hermetic fixtures are generated by `host/tests/fixtures/gen_{resigned,org}.py` (require `dkimpy`).

### Benchmarking

See `BENCHMARKS.md` for the §9 prove-time / proof-size measurement recipe.

## Definition of done for v0

See `SPEC.md` §9. The short version:

- All `SPEC.md` §7 must-pass and adversarial tests pass.
- Guest program is under 500 lines of Rust, hand-readable.
- A second reviewer has read the guest line by line and signed off that the cryptographic statement in §2 is what's actually being proven.
- The "what this does NOT prove" list above is prominent in any user-facing material.
- Prove time and proof size are measured and recorded for a 10KB email.
