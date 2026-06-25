# Kosmos validation brief — 0nce

**Purpose.** Independent validation of the 0nce ZK-email proof system, scoped to the
three things the team *cannot* self-certify with confidence. Prove-independent — none
of this requires running the (30–49 min) zkVM prover. Prepared 2026-06-25.

**What 0nce is (context).** A zero-knowledge proof system (RISC0 zkVM, Rust guest)
that lets a prover convince a verifier they possess an email DKIM-signed (RFC 6376,
rsa-sha256, relaxed/relaxed) by a claimed domain — without revealing the email. v2-A
adds *registry membership*: the signing key is witnessed (private) and proven, in-ZK, to
be a member of a verifier-pinned Merkle registry root, closing a v0 gap where a malicious
prover could supply their own key. A Poseidon nullifier gives replay protection;
identity-header disclosure (v1) is opt-in.

---

## What to validate

### T1 — Soundness audit (highest priority)

Verify that the proof proves **exactly** the stated statement and nothing more, and that
a malicious prover (who may have written the prover code) cannot forge or over-claim.

The claimed statement (`SPEC.md §2`, verbatim):

> The prover possesses an email message M and a DKIM-Signature header H such that:
> (a) H is well-formed per RFC 6376; (b) the signing domain in H equals the public input
> `claimed_domain`; (c) the RSA signature in H verifies against the public key over the
> canonicalized signed portion per H's `c=`/`h=` tags; (d) the nullifier N =
> Poseidon(sep, claimed_domain, signature) is not already seen.

v2-A change: (c) verifies against a **witnessed** key, plus an added assertion that
`leaf = Poseidon(sep, claimed_domain, selector, n, e)` is a member of the pinned
`registry_root` (fixed Merkle depth 20).

**Check specifically:**
- Does the guest (`methods/guest/src/main.rs` + modules) actually enforce (a)–(d) and the
  membership assertion, with no gap a malicious host/prover could exploit? The host is
  untrusted; anything it could lie about must be re-asserted in-guest.
- The two adversarial cases the design claims to defeat: (i) a forger's own key targeting
  the real registry root → membership fails → no proof; (ii) a forger's self-built registry
  → verify rejects on pinned-root mismatch. Are these genuinely closed?
- The **Merkle node-hash change** (recent): node hash is now `SHA-256(left‖right)`, leaf
  stays BN254 Poseidon. The design argues fixed depth + `leaf_index < 2^20` defeat
  leaf/node second-preimage confusion *without* a domain-separation byte. **Is that
  argument sound?** This is the single most uncertain crypto claim and the reason for this
  pass.
- The honest "what this does NOT prove" list (possession ≠ authorship/identity/recency;
  a forwarded copy proves) — is it complete, or are there over-claims hiding elsewhere?

**Pass/fail:** confirm the statement is exactly what's proven, or enumerate concrete gaps.

### T2 — Novelty of the two engineering findings (redundancy check)

The team intends a technical writeup. The risk is **redundancy** — restating community
knowledge as if novel. Check whether these are genuine contributions or already known:

1. **"BN254 Poseidon Merkle is a trap in RISC0."** 20 BN254 Poseidon node-hashes in the
   Merkle fold ran as unaccelerated software bignum and rivaled an RSA-2048 verify in
   cost — measured 4× prove-time regression (31min→2h7m); swapping the node hash to
   accelerated SHA-256 gave 2.6×/2.8×. Is this finding (BN254-Poseidon cost in
   RISC0/SP1-class zkVMs) already documented?
2. **RISC0 3.0.5 accelerator recipe.** Stable, no `unstable` feature:
   `sha2 = risc0/RustCrypto-hashes @ sha2-v0.10.9-risczero.0`,
   `rsa = risc0/RustCrypto-RSA @ v0.9.9-risczero.0` (rsa pinned =0.9.9; pulls
   risc0-bigint2). Is the recipe already clearly documented somewhere public, or is it
   genuinely scarce (the official docs page renders empty)?

**Pass/fail:** for each, "novel / partially novel / already public (cite source)."

### T3 — DNSSEC-in-ZK prior art (feeds a pivot decision, Linear 0PO-389)

The roadmap's v2-B proves one DKIM TXT record authentic via DNSSEC-in-ZK. The team is
weighing whether this is a reusable *component* or a *product* worth repositioning around.

**Check:** survey existing zk-DNSSEC / "authenticate a DNS record via DNSSEC in ZK" work
(academic + projects). Already done? By whom? How complete — demonstrated vs
production-grade reusable? Also note the structural ceiling: roughly what share of major
DKIM-signing domains are DNSSEC-signed at all.

**Pass/fail:** prior-art summary + whether the space is open enough to justify a product
bet, or already crowded → component only.

---

## Artifacts to attach

- `SPEC.md` — the v0 contract, threat model, statement (T1).
- `README.md` — what it does / does NOT prove; v1/v2-A summaries (T1).
- `core/src/registry.rs` — leaf + SHA-256 Merkle membership; the node-hash argument (T1).
- `methods/guest/src/main.rs` — guest assertion order (T1).
- `BENCHMARKS.md` — measured prove-time/size across v0/v1/v2-A/SHA-Merkle (T2).
- This brief — the questions and the verified accelerator recipe (T2).

## Explicitly NOT for Kosmos

- **Do not validate the perf *numbers*.** Wall-clock prove time is validated only by
  reproducible hardware runs; it is the team's deliverable, not a reasoning task.
- **Do not re-derive** the RFC 6376 canonicalization or RSA math — assume the crates;
  audit the *composition and claims*, not the primitives.

## Desired output

Per task: a verdict (sound / gap; novel / known; open / crowded), the *reasoning*, and —
for T1 — any concrete attack or gap as a reproducible scenario. Cite sources for any
prior-art / known-result claim.
