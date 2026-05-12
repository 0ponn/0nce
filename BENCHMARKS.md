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

| date | host | risc0-zkvm | mode  | prove wall-clock | proof.bin size | verify wall-clock |
|------|------|------------|-------|------------------|----------------|-------------------|
| TBD  | TBD  | 3.x        | prod  | TBD              | TBD            | TBD               |
| TBD  | TBD  | 3.x        | dev   | < 1s             | TBD            | < 1s              |

## Notes

- Dev mode (`RISC0_DEV_MODE=1`) produces fake receipts; numbers there
  are meaningless for the spec deliverable. Use the prod (default) row.
- Optimization knobs not adopted in v0: the RISC0 `sha2` accelerator
  patch and the bigint accelerator patch for `rsa` / `num-bigint`.
  Both are documented in `methods/guest/Cargo.toml` as v1 candidates.
