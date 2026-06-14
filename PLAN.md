# 0nce v1 — implementation plan (task ledger)

Design of record: `docs/superpowers/specs/2026-06-13-0nce-v1-design.md`.
Linear: 0PO-301..308. Branch: `feat/v1-org-disclosure`.

TDD: module unit tests (`cd methods/guest && cargo test`, `cargo test -p nce-core`)
first where a unit test fits; CLI integration tests in dev mode for end-to-end.
Commit per unit. Update Linear issue → in_progress/Done as each lands.

## Units (in order)

1. **core IO** (0PO-302) — `HeaderKind {From,To}` enum (Serialize/Deserialize,
   Copy, Eq) with `header_name()->&'static [u8]`; `PublicInputs.disclosed_header_kind`;
   `PublicOutputs.disclosed_address: Vec<u8>`. Gate: `cargo build` of core.
   ⚠ Touching the wire format breaks host+guest until both updated — expect red
   until units 2–5 land.

2. **guest address.rs** (0PO-304) — new module. `extract_address(value, claimed_domain)
   -> Vec<u8>`: unfold, strip display-name, parse `local@domain` restricted grammar
   (dot-atom local; LDH domain), assert domain==claimed_domain (lowercased), return
   `local@lowercased_domain`. Panics on malformed / mismatch. Unit tests first.

3. **guest signed_set.rs** (0PO-303) — add `pub fn h_contains(h_tag_value, name)->bool`
   and `pub fn signed_header_value(email, name)->Option<Vec<u8>>` (bottom-most match in
   header block = the instance the signature covers; header-prepend-safe). Unit tests.

4. **guest main.rs** (0PO-303/304) — `mod address;`; after RSA verify: assert
   h_contains(disclosed kind) else panic "not covered by h="; fetch signed_header_value;
   `address::extract_address`; commit `disclosed_address` in PublicOutputs.

5. **host** (0PO-305/306) — `--disclose <from|to>` (default from) → HeaderKind in
   PublicInputs (prove.rs ProveArgs + main.rs). verify.rs prints `disclosed_address`.

6. **fixtures** (0PO-307) — `host/tests/fixtures/gen_org.py` (dkimpy, own key →
   `org.pubkey.tag`): `org.eml` (From+To @insider.test, h=from:to:subject:date),
   `org_nonh_to.eml` (To NOT in h=), `org_misaligned.eml` (From @other.test, d=insider.test),
   `org_malformed_from.eml` (From has no @). Commit generated .eml + .tag + generator.

7. **integration tests** (0PO-307) — `host/tests/disclosure.rs`:
   - must-pass: disclose from → whistle@insider.test, verifies; disclose to → ops@insider.test.
   - adversarial: header-prepend (in-test mutate org.eml; disclosed == signed instance, not attacker);
     non-h= To → panic; misaligned domain → panic; malformed From → panic.

8. **build + suite** — `cargo build -p host`; full `cargo test -p host` green (dev mode).

9. **docs** (0PO-301/308) — README v1 statement + non-statements + demo-not-prod caveat;
   SPEC §4.9/§4.10 note; BENCHMARKS v1 row after real prove.

10. **real prove** (0PO-308) — prod-mode prove on org.eml (background, ~30min), confirm
    disclosed_address in output + verifies. Then v1 §9 DoD sign-off.

## Resume notes
- Guest unit tests: `cd methods/guest && cargo test` (crate is outside the workspace).
- Toolchain: `export PATH="$HOME/.risc0/bin:$PATH"`. dev-mode prove via `RISC0_DEV_MODE=1`.
- dkimpy venv: `/tmp/dkimvenv/bin/python`.
