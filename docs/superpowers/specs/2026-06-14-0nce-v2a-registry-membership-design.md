# 0nce v2-A — Registry Membership (design)

Date: 2026-06-14
Status: approved (design); pending implementation plan
Builds on: `SPEC.md` (v0) + the v1 disclosure design. v0 section numbers are
referenced as `v0 §N`.

Part of **0nce v2 — trustless DKIM key registry** (sub-projects A → B → C).
This spec is **A** only. B (DNSSEC-in-ZK validator) and C (trustless /
recursive registry population) are separate specs, summarized in §12.

## 0. One-paragraph summary

v2-A closes the only true soundness hole in 0nce (v0 §6 step 2): today the
verifier accepts `claimed_pubkey` **from the prover** and must confirm it
out-of-band, so a malicious prover can supply their own key and forge any
domain. A removes the pubkey from the public inputs entirely. The prover now
**witnesses** the key and proves, in-ZK, that it is a member of a **DKIM key
registry** committed by a public `registry_root` the verifier trusts. A forger
whose key is not in the registry cannot produce a proof against that root.
After A, trust drops from "the prover" to "whoever built the root" (a DNS
oracle); B/C later remove even that.

## 1. Why this is the MVP gate

Without A, every 0nce proof carries an asterisk: the domain binding rests on a
pubkey the prover handed over. A sharp relying party (a lender consuming a
CHAP income proof) asks "couldn't the prover just supply a fake key?" — and
today the answer is yes. A makes the answer no. It is the difference between a
"the ZK machinery works" demo and a "you cannot forge it" product.

## 2. Statement change (replaces v0 §2 condition (c))

v0 §2 (c): *"the RSA signature in H verifies against `claimed_pubkey` (a public
input) over the canonicalized signed portion of M."*

v2-A (c′): *"the prover possesses an RSA public key P and a Merkle authentication
path such that (i) the RSA signature in H verifies against P, and (ii)
`leaf = Poseidon(domain_separator_registry_v2, claimed_domain, selector, P)` is
a member, at the witnessed index, of the Merkle tree whose root equals the
public input `registry_root`."*

The verifier learns `registry_root` and `claimed_domain`; it **never** sees or
trusts a prover-supplied pubkey. `P` and `selector` are private (witness).

This is load-bearing: condition (ii) is what makes the proof unforgeable for a
verifier that pins a trusted `registry_root`.

## 3. Trust model after A

- **Closed:** prover can no longer forge with their own key. To match a known
  trusted `registry_root`, the key must already be a leaf in that tree; a
  forger's key is not, so the in-guest membership assertion fails → no proof.
  (If a forger instead supplies their *own* fake root + matching path, the
  proof carries that fake root in the journal and the verifier's
  trusted-root check rejects it.)
- **Still trusted (removed by B/C):** the provenance of `registry_root`. In A
  the root is built by a DNS-lookup tool — i.e. an oracle trusting
  unauthenticated DNS at build time. B proves a single DNS record authentic via
  DNSSEC-in-ZK; C makes the whole root ZK-attested, removing the oracle.
- **Privacy improvement:** `P` and `selector` move into the witness, so the
  verifier no longer learns the public key or the selector — strictly more
  private than v0/v1. It learns only the domain and that the key is registered.

## 4. Public inputs / witness / outputs (extends v0 §3, `core`)

`PublicInputs`:
- **Remove** `claimed_pubkey_n`, `claimed_pubkey_e`.
- **Add** `registry_root: [u8; 32]` — the Merkle root the verifier pins (BN254
  field element, the Poseidon output encoding already used for the nullifier).
- Keep `claimed_domain`, and the v1 `disclosed_header_kind: Option<HeaderKind>`.

`Witness`:
- **Add** `pubkey_n: Vec<u8>`, `pubkey_e: Vec<u8>` (RSA modulus + exponent,
  big-endian — moved from public inputs).
- **Add** `merkle_path: Vec<[u8; 32]>` (sibling hashes, leaf→root) and
  `leaf_index: u32` (the path direction bits). Length of `merkle_path` MUST
  equal the fixed tree depth `REGISTRY_DEPTH` (§7); the guest asserts this.
- Keep `email_raw`, `dkim_header_index`, `selector`, `signature`, `body_hash`.

`PublicOutputs`:
- **Add** `registry_root: [u8; 32]` (echoed from the input, so the verifier can
  re-check the proof was made against the root it expects — same pattern as
  `claimed_domain`).
- Keep `claimed_domain`, `nullifier`, `disclosed_address`.

## 5. Guest pipeline additions (extend v0 §4)

v0 §4.1–§4.5 unchanged. §4.6 changes; a new membership step is added.

### §4.6′ RSA verify against the **witnessed** key
Identical RSA-PKCS1v1.5-SHA256 verify as v0 §4.6, but the modulus/exponent come
from `witness.pubkey_n/e` instead of public inputs.

### §4.6a (new) Registry membership
- Compute `leaf = Poseidon(DOMAIN_SEPARATOR_REGISTRY_V2, claimed_domain,
  selector, pubkey_n, pubkey_e)`. Byte→field packing reuses the length-prefixed
  scheme already in `nullifier.rs` (so variable-length inputs are unambiguous);
  factor the shared packing into a helper if not already.
- Assert `merkle_path.len() == REGISTRY_DEPTH`.
- Fold the path: `node = leaf`; for each level `i`, `node = Poseidon(left,
  right)` where (left, right) order is chosen by bit `i` of `leaf_index`.
- **Assert the folded root equals `public_inputs.registry_root`.** Failure =
  guest panic = no proof. This is the soundness assertion.
- Echo `registry_root` into `PublicOutputs`.

v1 §4.9/§4.10 (disclosure) and v0 §4.7/§4.8 (nullifier, commit) run as before;
the commit now also carries `registry_root`.

`DOMAIN_SEPARATOR_REGISTRY_V2 = b"0nce-v2-registry-leaf"` (locked; distinct from
the nullifier separator).

## 6. Registry tool + host/verifier changes

New `registry` subcommand (host, off-ZK):
- `0nce registry build --domains <file> --out registry.json` — for each
  `(domain, selector)` line, resolve `<selector>._domainkey.<domain>` via DNS
  (reusing `dns.rs`), parse the RSA key, compute its leaf, build the
  fixed-depth Poseidon Merkle tree (leaves sorted by leaf value, padded with a
  constant empty leaf), and write `registry.json = { depth, root,
  entries: [{domain, selector, n, e, index, path}] }`.
- `0nce registry build --pubkey-tag <tag> --domain <d> --selector <s> --out …`
  — single-entry offline registry, for tests/demos/air-gapped use.

`prove`:
- New `--registry <registry.json>` (replaces the trust role of `--pubkey-tag`;
  `--pubkey-tag` may remain as sugar that builds a one-entry registry inline).
- Look up the prover's `(domain, selector)` entry, populate `pubkey_n/e`,
  `merkle_path`, `leaf_index`, and set `registry_root` from the file.

`verify`:
- New `--registry-root <hex>` (the pinned trusted root). Assert the journal's
  echoed `registry_root` equals it; reject on mismatch (this is the verifier's
  trust anchor). Print the root and `claimed_domain`; pubkey/selector are not in
  the journal, so nothing to print.

## 7. Merkle / registry design details

- **Hash:** Poseidon, BN254 field, Circom/Iden3 params via `light-poseidon` —
  same primitive as the nullifier, already compiled into the guest. 2-to-1
  compression `node = Poseidon(left, right)`.
- **Tree:** fixed depth `REGISTRY_DEPTH = 20` (≤ 2²⁰ ≈ 1.05M keys — ample for
  any realistic DKIM-key set; padding cost is negligible since unused subtrees
  collapse to a precomputed empty-node ladder). Fixed depth avoids
  path-length-ambiguity forgeries.
- **Empty leaf:** `EMPTY_LEAF = Poseidon(b"0nce-v2-registry-empty")`, a domain-
  separated constant distinct from any real leaf.
- **Leaf placement:** leaves sorted by leaf value, assigned dense indices from
  0; remaining slots are `EMPTY_LEAF`. (Sorted placement is deterministic and
  makes the tool reproducible. Non-membership / revocation proofs are **not** in
  A — they need an indexed/sparse tree, which is C's concern.)
- **Forward-compat with C:** the *leaf semantics* (`Poseidon(sep, domain,
  selector, n, e)`) are fixed here and MUST NOT change in C. C may swap the
  *tree shape* (e.g. to an indexed Merkle tree for efficient trustless updates
  and revocation) without redefining a leaf. The guest's membership-fold is
  isolated in `merkle.rs` behind a `verify_membership(leaf, path, index, root)`
  interface so C can replace the tree mechanics independently.

## 8. Demo deliverable (in scope for A)

`demo.sh` (runs in `RISC0_DEV_MODE=1` so it is instant — the membership and RSA
assertions execute in dev mode, only the STARK receipt is mocked; a real
3.94 MB receipt still takes ~31 min and is out of the demo path):

1. **Honest:** build a registry containing the real signing key, prove a real
   `.eml`, `verify --registry-root <real root>` → ACCEPTED, revealing only the
   domain (and, if `--disclose`d, the address).
2. **Forgery defeated:** a "malicious prover" self-signs an email with their own
   key claiming the same domain and tries to prove against the **real** root →
   membership assertion fails → **no proof**. Contrast with v1 (same attack
   produces a passing proof). This before/after is the headline.

## 9. Out of scope (A)

- DNSSEC validation (B). Trustless / recursive registry population, revocation,
  non-membership proofs (C).
- On-chain root anchoring; key-rotation root-windowing (A pins a single current
  root; the verifier may be configured with a set of accepted roots, but
  rotation policy is operational, not specified here).
- Multi-signature emails, anything already out of scope in v0/v1.

## 10. Test plan (extend v0 §7)

Must-pass:
- Registered key + real email → proof verifies; `verify --registry-root <root>`
  → ACCEPTED.
- The journal contains no pubkey and no selector (privacy regression guard).
- `registry build` from a `--pubkey-tag` produces a one-entry root that a real
  email proves against.

Adversarial (load-bearing):
- **Forger's own key (not in registry), targeting the real root** → membership
  fold ≠ root → guest panics, no proof. *(The headline.)*
- Forger supplies their own fake root + matching path → proof is produced but
  `verify --registry-root <real>` rejects on echoed-root mismatch.
- Swap the witnessed pubkey to a different registered key → leaf changes →
  membership fails (or RSA fails first) → no proof.
- Corrupt one sibling / wrong `leaf_index` → folded root ≠ `registry_root` →
  panic.
- `merkle_path.len() != REGISTRY_DEPTH` → panic.

Fixtures: extend the hermetic `gen_org.py` / `gen_resigned.py` generators and a
small registry-builder helper to mint a registry with the synthetic
`insider.test` key plus an unregistered forger key.

## 11. Definition of done (A)

- Builds end-to-end (host + guest) with the RISC0 toolchain.
- A real prod-mode prove against a DNS-built registry verifies; pubkey/selector
  absent from the journal; BENCHMARKS row added (prove time expected within
  noise of v1 — Merkle fold is cheap vs RSA).
- All §10 must-pass + adversarial tests green; the forger-defeated test is the
  gate.
- `demo.sh` runs the before/after forgery demo in dev mode.
- README + SPEC updated: the v0 §6-step-2 soundness gap is now **closed against
  prover forgery** (trust moved to `registry_root`); the residual oracle/DNS
  trust and its B/C resolution are documented.
- Guest membership logic isolated in `merkle.rs`, hand-reviewed; second-model
  sign-off that §2 (c′) is what is actually proven.

## 12. The v2 arc (B and C — separate specs)

- **B — DNSSEC-in-ZK validator.** Prove one DNS record authentic via the DNSSEC
  chain (DS/DNSKEY/RRSIG) to the root KSK (public constant). Heavy: ~3–4
  signature verifies in-STARK. Prototyped standalone; output is "this
  `(domain, selector, pubkey)` is the real DNS record."
- **C — Trustless population.** Admit registry entries via B's proofs
  (proof-carrying registry, RISC0 recursion), so `registry_root` is ZK-attested,
  not oracle-built. Likely **mixed admission**: DNSSEC-attested where a domain
  has DNSSEC; oracle-attested (and marked as such in the leaf or a per-entry
  trust tag) where it does not — most corporate domains lack DNSSEC. Needs the
  indexed-tree shape flagged in §7.

## 13. Linear

New project **0nce v2 — trustless DKIM key registry** (team 0PO). A's issues:
§2 statement (c′); `core` IO changes; §4.6′ witnessed-key RSA; §4.6a membership
+ `merkle.rs`; `registry build` tool; host prove/verify wiring; demo.sh; tests;
DoD. Plus tracking stubs for **B** and **C**. Labels `v2`; `soundness-critical`
on §4.6a.
