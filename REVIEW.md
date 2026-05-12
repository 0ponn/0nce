# Hand-review of the guest

SPEC.md §9 asks a second reviewer to confirm with their own eyes that the guest proves the §2 statement. The test suite (`cargo test`: 76 passing, 1 deferred fixture) covers correctness in depth. The hand-review's job is just to look at the load-bearing pieces.

**Reviewed:** Michael Layug, 2026-05-12
**Commit:** c6c58ca

## The statement (SPEC.md §2 verbatim)

> The prover possesses an email message *M* and a DKIM-Signature header *H* such that:
> (a) *H* is well-formed per RFC 6376,
> (b) The signing domain in *H* equals the public input `claimed_domain`,
> (c) The RSA signature in *H* verifies against `claimed_pubkey` over the canonicalized signed portion of *M*,
> (d) The nullifier *N* = Poseidon(`domain_separator_v0`, `claimed_domain`, *H*.signature). The verifier checks *N* against its local store.

## The five things to look at

1. **The soundness-critical assertion.** Open `methods/guest/src/dkim.rs` and find the line in `locate_and_parse` that says `assert_eq!(trim_wsp_crlf(d), claimed_domain, ...)`. This is THE public-input binding. If it's missing, weakened to a substring match, or relaxed in any way, a prover can supply an email signed by attacker.com while claiming victim.com. Read the assertion and the surrounding 5 lines.

2. **The full assertion list in `locate_and_parse`.** Scan the function and confirm you see, in order: v=1, a=rsa-sha256, c=relaxed/relaxed, **d == claimed_domain**, s == witnessed_selector, b/bh match the witness, l= absent. Seven assertions. Anything missing or commented out is a finding.

3. **Pipeline order in `methods/guest/src/main.rs`.** Should be: read inputs → `dkim::locate_and_parse` → `body::verify_body_hash` → `signed_set::build_signed_data` → `verify::verify_rsa_signature` → `nullifier::compute_nullifier` → `env::commit`. Out-of-order means assertions could be skipped.

4. **Journal contents.** In `main.rs`, find the `env::commit(&PublicOutputs { ... })` call. Confirm the struct holds exactly `claimed_domain` and `nullifier`. Anything else committed becomes part of the public claim of the proof.

5. **Nullifier inputs.** In `methods/guest/src/nullifier.rs`, find `compute_nullifier` and confirm the three inputs to the Poseidon call are in the order `(DOMAIN_SEPARATOR_V0, claimed_domain, signature)`. Matches SPEC.md §3.

## Non-statements (sanity-check, no code reading needed)

Convince yourself that nothing in those five places makes any of these accidentally true. (None of them should.)

- The proof does NOT claim the prover authored the email.
- The proof does NOT claim the prover is the recipient.
- The proof does NOT claim the email is recent.
- The proof does NOT claim the prover currently works at `claimed_domain`.
- Anyone forwarded such an email can produce this proof.

## Findings

_If anything looked off, file:line and a one-line description. Otherwise: `(none)`._

```
(none)
```

## Sign-off

Reviewer: Michael Layug
Date: 2026-05-12
Commit hash: c6c58ca

I confirm the five load-bearing pieces above match SPEC.md §2, modulo the findings.
