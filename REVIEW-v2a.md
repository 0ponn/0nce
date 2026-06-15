# REVIEW-v2a — adversarial soundness review (registry membership)

A fresh-context adversarial reviewer (instructed to break it, not agree) read
the v2-A membership code line-by-line against design §2(c′)/§4 and ran the core
+ guest tests. This records the verdicts. A different *provider* (the PR bots /
Michael) is still the intended second pair of eyes.

## What v2-A must prove

For a verifier that pins `registry_root`, a passing proof entails: the RSA
signature verifies against a witnessed key P, and
`leaf = Poseidon(sep, claimed_domain, selector, P)` is a member of the pinned
tree — with `claimed_domain`, `selector`, and `P` mutually bound.

## Verdicts (all SAFE)

1. **Forge membership for a non-member leaf** — Safe. `verify_membership`
   rejects path length ≠ `REGISTRY_DEPTH`; the fold is a standard fixed-depth
   recompute; per-input Poseidon lanes (t=6) avoid concat/length-extension
   ambiguity. (`core/src/registry.rs`)
2. **Cross-domain key reuse (X's email, key under Y)** — Safe. `dkim.rs` asserts
   email `d=` == `claimed_domain` (RSA-covered); the leaf uses that same
   `claimed_domain`, so a Y-registered leaf can't match an X proof.
3. **Witness key A for RSA, key B for the leaf** — Safe. RSA verify and the leaf
   read the *same* `witness.pubkey_n/e`; there is no second key field.
4. **Forger supplies their own root** — Safe. The guest folds to
   `public_inputs.registry_root` and echoes it; `host/src/verify.rs` rejects when
   the journal's root ≠ the pinned `--registry-root`.
5. **Empty-leaf / padding slot** — Safe. `EMPTY_LEAF` is a distinct-arity (t=2),
   domain-separated constant; claiming an empty slot needs a cross-arity Poseidon
   collision, and the fold still seeds from the prover's real leaf.
6. **Selector swap (selector now private)** — Safe. `dkim.rs` asserts email `s=`
   == `witness.selector`, which is the same selector fed into the leaf.

**Sign-off:** *"The guest proves exactly §2(c′)."* None of the three forgery
classes (non-member key, key substitution, cross-domain reuse) is achievable.

## Fixed in response to the review

- **leaf_index witness hygiene:** `verify_membership` now rejects
  `leaf_index >= 2^REGISTRY_DEPTH` (high bits were ignored — cosmetic
  malleability, no soundness impact). Test `leaf_index_above_depth_rejected`.
- **Spec drift:** design §4.6a said "length-prefixed packing"; the impl uses
  per-input SHA-256 lanes (functionally stronger). Doc reconciled.

## Operator note (not a code defect)

`verify` without `--registry-root` prints a "NOT pinned" warning and accepts any
root — there is no key-trust guarantee in that mode. `--registry-root` is
mandatory for any soundness claim. Documented in the README v2-A section.
