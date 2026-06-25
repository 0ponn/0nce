# 0nce maturity push — task ledger

Direction chosen 2026-06-24: **engineering maturity** (patent path assessed weak —
crowded zkEmail prior art + §101; dropped). Drive the existing roadmap.

## Units (in order)

### 1. Merkle perf fix — SHA-256 node hash  ✅ DONE (2026-06-24)
Result: 2:06:51 → 48:43.86 (2.6× faster), 15.0 → 5.34 MB (2.8× smaller), same i5,
nullifier bit-identical (`20939a2d…`). This **narrows** the regression but does
not reach the v1 baseline (31:09) — a residual ~17min remains (leaf t6 Poseidon +
20 unaccelerated SHA), which unit 2 is expected to close. See BENCHMARKS.md
2026-06-24 row.

The v2-A benchmark (2026-06-15) recorded a 4× prove-time regression (31min → 2h7m)
and proof-size blowup (3.9 → 15.0 MB), caused by 20 BN254 Poseidon node hashes in
the Merkle fold running as unaccelerated software bignum. Fix per BENCHMARKS.md:
swap the **node hash** to SHA-256; keep `registry_leaf` + `empty_leaf` on BN254
(leaf semantics LOCKED at v2-A, preserves Circom nullifier compat). SHA-256(l||r)
is ~2 orders cheaper than a BN254 Poseidon permutation even unaccelerated, so this
removes most of the Merkle regression. It does not on its own reach the v1
baseline (the t=6 leaf Poseidon + 20 unaccelerated SHA remain); unit 2 closes
that residual.

- Scope: `core/src/registry.rs` only (host delegates to `RegistryTree`).
- Delete `poseidon2` + `fr_from_bytes` (now unused). Add `node_hash(l,r)=SHA256(l||r)`.
- Node-hash sites: `verify_membership` fold, `RegistryTree::build` (empties + combine).
- Root value changes (tree reshape — explicitly permitted by the LOCKED-leaf comment;
  no deployed verifiers pin the old root).
- Security note: fixed depth (20) + `leaf_index < 2^20` already defeat leaf/node
  confusion, so plain untagged SHA256(l||r) matches the original untagged Poseidon(l,r).
- TDD: existing hash-agnostic membership tests are the regression guard (must stay
  green). Add a vector test pinning `node_hash` == SHA-256(l||r) so it can't drift.
- Verify: `cargo test -p nce-core`; dev-mode full suite; then ONE prod prove on
  `real.eml` to record the new prove-time/size in BENCHMARKS.md. Nullifier must stay
  bit-identical (`20939a2d…`) — it's leaf/BN254, untouched.

### 2. RISC0 accelerator patches (separate lever, pushes BELOW v1 baseline)
Apply RISC0's `sha2` + bigint (`num-bigint-dig`) accelerator patches in
`methods/guest/Cargo.toml [patch.crates-io]`. Accelerates RSA-2048 verify + body
SHA-256 + (after unit 1) the SHA Merkle nodes. Needs version-pinned patch tags
matching `risc0-zkvm` 3.x — look up current tags, do not guess. No math change →
proof/nullifier stay bit-identical; validate with a prod prove.

### 3. v2-B — DNSSEC-in-ZK (one record authentic)
Prove one DKIM TXT record is authentic via the DNSSEC chain in-ZK, removing the
"trust the registry builder for that record" assumption. Design stub: 0PO-316.

### 4. v2-C — proof-carrying registry (root is ZK-attested)
Make the whole `registry_root` ZK-attested so the verifier trusts no oracle.
Leaf semantics stay LOCKED; tree may move to an indexed tree for revocation.
Design stub: 0PO-317.

## Resume notes
- Guest unit tests: `cd methods/guest && cargo test`. dev: `RISC0_DEV_MODE=1`.
- Prod prove recipe: BENCHMARKS.md "How to reproduce". ~31min expected post-unit-1.
- Canonical nullifier (must not change): `20939a2deaf4f262356c519eed580641dddf2f72d5e527a75fd3a7b3ce3bc27b`.
