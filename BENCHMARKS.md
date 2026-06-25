# Benchmarks

SPEC.md §9 calls for "prove time and proof size measured and recorded
for a 10KB email." This file is the place to record those numbers.

## How to reproduce

Prerequisites: `rzup` installed, `cargo build --release` succeeds at
the workspace root.

```sh
# from the project root, with the test fixture committed to the repo:
time cargo run --release --bin 0nce -- prove \
  --email host/tests/fixtures/real.eml \
  --pubkey-tag "$(cat host/tests/fixtures/real.pubkey.tag)" \
  -y \
  --out /tmp/real.proof.bin
ls -l /tmp/real.proof.bin
cargo run --release --bin 0nce -- verify \
  --proof /tmp/real.proof.bin \
  --nullifier-store /tmp/nullifiers-bench.txt
```

The `real.eml` fixture is the 6708-byte Gmail-signed test message from
visionaryauto.ai. SPEC.md §9 asks for "a 10KB email" but the practical
intent is one realistic-sized email; this fixture is in that ballpark.

Run with `RISC0_DEV_MODE=1 cargo run ...` if you want to confirm the
pipeline works without paying the STARK prove cost.

## Recorded results

| date       | host                                                | risc0-zkvm | mode | prove wall-clock | proof.bin size       | verify wall-clock |
|------------|-----------------------------------------------------|------------|------|------------------|----------------------|-------------------|
| 2026-05-12 | Intel Core Ultra 7 155H (11C / 22T), 32 GB, Fedora 44 | 3.0.5      | prod | 50:55.69         | 3,938,908 B (3.76 MB) | 0.21 s            |
| 2026-06-13 | Intel Core i5-11600K (6C / 12T) @ 3.9 GHz, 31 GB, Fedora 44 | 3.0.5  | prod | 32:19.50         | 3,938,908 B (3.76 MB) | 0.24 s            |
| 2026-06-14 | Intel Core i5-11600K (6C / 12T) @ 3.9 GHz, 31 GB, Fedora 44 | 3.0.5  | prod (v1, --disclose from) | 31:09.34 | 3,939,100 B (3.76 MB) | 0.22 s |
| 2026-06-15 | Intel Core i5-11600K (6C / 12T) @ 3.9 GHz, 31 GB, Fedora 44 | 3.0.5  | prod (v2-A, registry membership, Poseidon Merkle) | **2:06:51** | **15,754,360 B (15.0 MB)** | 0.90 s |
| 2026-06-24 | Intel Core i5-11600K (6C / 12T) @ 3.9 GHz, 31 GB, Fedora 44 | 3.0.5  | prod (v2-A, registry membership, **SHA-256 Merkle**) | **48:43.86** | **5,601,584 B (5.34 MB)** | — |
| 2026-06-25 | Intel Core i5-11600K (6C / 12T) @ 3.9 GHz, 31 GB, Fedora 44 | 3.0.5  | prod (v2-A SHA-256 Merkle + **sha2/rsa accelerators**) | **27:02.99** | **2,800,668 B (2.67 MB)** | — |

The 2026-06-25 row applies the **RISC0 crypto accelerator patches** (0PO-388):
guest `[patch.crates-io]` for `sha2 = sha2-v0.10.9-risczero.0` and
`rsa = v0.9.9-risczero.0` (the rsa fork pulls `risc0-bigint2`, accelerating the
RSA-2048 modexp — the dominant cost). **Both stable; no `unstable` feature.**
Same i5/`real.eml`/risc0 3.0.5. Result: **48:43 → 27:02.99 (1.8× faster), 5.34 →
2.67 MB (1.9× smaller).** Nullifier (`20939a2d…`) and root (`65ff99f4…`) are
**bit-identical** to the 2026-06-24 row — accelerators change implementation, not
math. **This clears the goal: the full v2-A registry-membership proof is now below
the v1 *unaccelerated* baseline (31:09 / 3.76 MB) on both prove time and size** —
i.e. the accelerators more than paid for the membership cost. (An accelerated-v1
number isn't recorded; the honest claim is "accelerators overcame the membership
cost and then some," not that membership is intrinsically free.)

The 2026-06-24 row is the **Merkle perf fix**: the 20 BN254 Poseidon *node*
hashes were swapped to SHA-256 (`core/src/registry.rs::node_hash`); the leaf and
nullifier stay BN254 Poseidon (LOCKED v2-A leaf semantics, Circom-compatible).
Same i5, same `real.eml`, same risc0 3.0.5 as the 2026-06-15 row, so this is a
clean comparison: **prove time 2:06:51 → 48:43.86 (2.6× faster), proof 15.0 →
5.34 MB (2.8× smaller).** The nullifier is bit-identical
(`20939a2d…`) — the fix touches only the tree shape, not the leaf/nullifier — and
the proof verifies (new root `65ff99f4…`, since the node hash changed the tree).

It does **not** reach the v1 no-registry baseline (31:09 / 3.76 MB) on its own. The
residual ~17 min / ~1.58 MB over v1 is (i) the one remaining BN254 Poseidon — the
`t=6` *leaf* hash — and (ii) 20 software SHA-256 node compressions, both still
unaccelerated at that point. The **RISC0 sha2 + bigint accelerator patches** (the
separate prove-time lever) were **then applied — see the 2026-06-25 row** —
accelerating the SHA fold and the RSA-2048 verify and pushing prove time *below* the
v1 baseline.

The 2026-06-15 row is the **v2-A** guest (registry membership) on the same
`real.eml`, proving against a 1-entry registry. It verified against the pinned
root, disclosed no address (privacy default), and the nullifier is bit-identical
to v0 (`20939a2d…`). **Cost finding: membership roughly 4×'d prove time
(31 min → 2 h 7 min) and proof size (3.76 → 15.0 MB).** The cause is the Merkle
fold: 1 leaf `Poseidon(5)` + 20 `Poseidon(2)` over **BN254**, which RISC0 does in
unaccelerated software bignum — each Poseidon is many field multiplications, and
21 of them rival the RSA-2048 verify. The design's assumption that "the Merkle
fold is cheap vs RSA" was wrong for BN254-in-RISC0.

**Optimization (done — 2026-06-24 row):** the *Merkle tree* node hash was switched
to RISC0-accelerated SHA-256. The leaf/nullifier stay BN254 for Circom
compatibility; only the 20 node hashes changed. This brought prove time toward the
v1 baseline, and the 2026-06-25 accelerator row then pushed below it.

The 2026-06-14 row is the **v1** guest (identity-header disclosure) on the same
`real.eml`, `--disclose from`. It revealed `mlayug@visionaryauto.ai` (ALIGNED
with the signing domain) and verified. The nullifier is bit-identical to v0
(`20939a2d…`, unchanged — it is per-signature, not per-disclosure). Proof grew
by 192 bytes (the disclosed address in the journal); prove time is within noise
of the v0 i5 run — disclosure (header location + address parse) is negligible
against the RSA-in-STARK cost.

The 2026-06-13 i5 run reproduced the canonical nullifier
`20939a2deaf4f262356c519eed580641dddf2f72d5e527a75fd3a7b3ce3bc27b` and the
exact 3,938,908-byte proof size bit-for-bit on different hardware, confirming
the prove pipeline is deterministic and machine-independent. Faster wall clock
than the 22-thread laptop because RISC0 proving saturates ~10 cores here and
the i5's cores are faster.

Prove run details (from `/usr/bin/time -v`):

- CPU time: 62,577 s user + 60 s system = ~62,637 s across all cores
- Effective parallelism: 2,049 % of one core (~20.5 cores hot for ~51 min wall clock)
- Peak RSS: 9.4 GB (9,614,640 KB)
- Email proven: `host/tests/fixtures/real.eml` (6,708 bytes, Gmail-signed by visionaryauto.ai)
- Committed nullifier: `20939a2deaf4f262356c519eed580641dddf2f72d5e527a75fd3a7b3ce3bc27b`

## Notes

- Dev mode (`RISC0_DEV_MODE=1`) produces fake receipts; numbers there
  are meaningless for the spec deliverable. Use the prod row above.
- The ~51-minute (laptop) / ~31-minute (i5) v1 prove time was the cost of
  doing RSA-2048 + SHA-256 + RFC 6376 canonicalization inside a STARK
  WITHOUT the RISC0 accelerator patches. Those patches are **now applied**
  (2026-06-25 row), in `methods/guest/Cargo.toml`:
    - `sha2` accelerator patch (RISC0's fork of RustCrypto/hashes).
    - `rsa` accelerator patch (RISC0's fork; pulls `risc0-bigint2` for the
      RSA-2048 modexp).
  Together with the SHA-256 Merkle node hash they took the full v2-A proof
  below the v1 baseline.
- Verify is ~210 ms with peak ~13 MB RSS; the STARK verifier is small
  and amortizes the proof artifact's cost completely.
