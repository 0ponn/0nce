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

Prove run details (from `/usr/bin/time -v`):

- CPU time: 62,577 s user + 60 s system = ~62,637 s across all cores
- Effective parallelism: 2,049 % of one core (~20.5 cores hot for ~51 min wall clock)
- Peak RSS: 9.4 GB (9,614,640 KB)
- Email proven: `host/tests/fixtures/real.eml` (6,708 bytes, Gmail-signed by visionaryauto.ai)
- Committed nullifier: `20939a2deaf4f262356c519eed580641dddf2f72d5e527a75fd3a7b3ce3bc27b`

## Notes

- Dev mode (`RISC0_DEV_MODE=1`) produces fake receipts; numbers there
  are meaningless for the spec deliverable. Use the prod row above.
- The ~51-minute prove time on a 22-thread laptop CPU is the cost of
  doing RSA-2048 + SHA-256 + RFC 6376 canonicalization inside a STARK
  WITHOUT the RISC0 accelerator patches. Two patches are the obvious
  v1 prove-time levers, each documented in `methods/guest/Cargo.toml`:
    - `sha2` accelerator patch (RISC0's fork of RustCrypto/hashes).
    - `rsa` / `num-bigint` bigint accelerator patch (RISC0's bigint2
      syscalls, accessed via the patched num-bigint).
  These typically deliver an order of magnitude or more on prove time
  for this workload shape.
- Verify is ~210 ms with peak ~13 MB RSS; the STARK verifier is small
  and amortizes the proof artifact's cost completely.
