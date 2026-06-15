# 0nce v2-A — implementation plan (task ledger)

Design: `docs/superpowers/specs/2026-06-14-0nce-v2a-registry-membership-design.md`.
Linear: 0PO-309..315 (A), 0PO-316/317 (B/C stubs). Branch: `feat/v2a-registry-membership`.

TDD: core crypto + IO unit tests first; guest membership wired; CLI integration
in dev mode. Commit per unit. Update Linear as each lands.

Key reuse: `nullifier.rs` pattern — `bytes_to_field = Fr::from_be_bytes_mod_order(Sha256(x))`,
Poseidon via `light-poseidon` new_circom(n). Leaf = per-input field compression
(cleaner than concat; each input is its own Poseidon lane). `dns::parse_dkim_tag → (n,e)`.

## Units (in order)

1. **core registry module** (0PO-312 primitives) — add light-poseidon/ark-bn254/ark-ff/sha2
   to core/Cargo.toml. New `core/src/registry.rs`:
   - `DOMAIN_SEPARATOR_REGISTRY_V2 = b"0nce-v2-registry-leaf"`, `REGISTRY_DEPTH = 20`
   - `registry_leaf(domain, selector, n, e) -> [u8;32]` = Poseidon5(f(sep),f(dom),f(sel),f(n),f(e))
   - `poseidon2([u8;32],[u8;32]) -> [u8;32]`, `empty_leaf()`
   - `verify_membership(leaf, path:&[[u8;32]], leaf_index, root) -> bool`
   - `build_tree(leaves) -> (root, paths)` for the host tool
   Unit tests: leaf determinism/uniqueness, membership true/false, build↔verify roundtrip.

2. **core IO** (0PO-310) — PublicInputs: drop claimed_pubkey_n/e, add registry_root:[u8;32].
   Witness: add pubkey_n/e, merkle_path:Vec<[u8;32]>, leaf_index:u32. PublicOutputs: add registry_root.

3. **guest** (0PO-311/312) — main.rs §4.6 RSA uses witness.pubkey_n/e; new step: leaf via
   nce_core::registry_leaf, assert path.len()==DEPTH, assert verify_membership(...==registry_root),
   echo registry_root. (No new guest module — reuse core.)

4. **host registry** (0PO-313) — host/src/registry.rs: RegistryFile{depth,root,entries:[{domain,
   selector,n,e,index,path}]}, serde_json. build from DNS list OR --pubkey-tag (1-entry).
   main.rs: `registry build` subcommand + --registry/--registry-root args.

5. **host prove/verify** (0PO-313) — prove: --registry <file> (or --pubkey-tag → inline 1-entry)
   populates witness pubkey/path/index + registry_root input. verify: --registry-root <hex> optional;
   if present assert journal root == it (reject mismatch); else report root + "not pinned" warning.

6. **fix existing tests** (0PO-314) — must_pass/adversarial/disclosure use --pubkey-tag; keep that
   working (inline 1-entry registry). They should pass unchanged modulo new output lines.

7. **new tests + demo** (0PO-314) — host/tests/registry.rs: forger-key-not-in-registry → no proof;
   forger fake-root → verify rejects on pin mismatch; corrupt path → panic; privacy guard (no
   pubkey/selector in journal). demo.sh (dev mode): honest ACCEPTED vs forgery→no proof.

8. **build + suite** — cargo build -p host; full cargo test green (dev mode).

9. **docs** (0PO-309/315) — README+SPEC: gap closed vs prover forgery, residual oracle trust→B/C.
   BENCHMARKS after real prove.

10. **real prove** (0PO-315) — prod prove against a DNS-built registry (background ~31min); confirm
    no pubkey/selector in journal + verifies. Then PR.

## Resume notes
- Guest unit tests: `cd methods/guest && cargo test`. PATH += ~/.risc0/bin. dev: RISC0_DEV_MODE=1.
- core now pulls ark-bn254/light-poseidon (compiles for both host x86 + guest riscv; guest already uses them).
- dkimpy venv /tmp/dkimvenv for forger-key fixtures.
