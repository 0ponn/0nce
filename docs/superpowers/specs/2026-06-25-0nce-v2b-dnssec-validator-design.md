# 0nce v2-B — DNSSEC-in-ZK validator (design)

**Status:** design / spec only. No implementation in this pass. Supersedes the
v2-A design §12 sketch for **B**. **C** (proof-carrying / trustless registry
population) remains a separate later spec.

**Goal.** Prove, in zero knowledge, that a specific DNS record — the DKIM public
key at `<selector>._domainkey.<domain>` — is **authentically published** under the
global DNSSEC chain of trust, rooted at the IANA root KSK (a public constant). The
output is the fact "`(domain, selector, pubkey)` is the real DNS record," with no
trust in the party that fetched it. This removes the **registry-builder oracle**
that v2-A still trusts (v2-A is sound against *prover* forgery but trusts whoever
built `registry_root` from unauthenticated DNS).

**Scope reality (why B is a component, not a product).** Only ~6.75% of the
top-million domains are DNSSEC-signed, and major DKIM senders (Gmail/Workspace,
Outlook) are **not** signed. B therefore cannot cover most domains. It is a
reusable trust component that removes the oracle *where DNSSEC exists*; the v2-A
registry/oracle path remains the fallback for unsigned domains (decision 0PO-389:
component, not a product pivot). Prior art to mine before building: **NOPE**
(DeStefano/Ma/Bonneau/Walfish, SOSP 2024) and **zk-dnssec** (envoy1084, SP1).

---

## 1. Threat model

**In scope:**
- A malicious prover supplying a forged or altered DNS chain (wrong keys, wrong
  signatures, swapped DS digests, a chain for a *different* domain replayed for the
  target, an expired/replayed RRSIG set).
- An untrusted host that gathered the chain — anything it could lie about is
  re-verified in-guest.

**Out of scope:**
- Denial of existence (NSEC/NSEC3) — B proves a record *exists* and is authentic,
  not that something is absent.
- Wildcard-expanded answers, CNAME/DNAME indirection at the leaf.
- DNSSEC algorithm rollover *mid-chain* edge cases beyond verifying whatever single
  algorithm each link actually used.
- Registry admission, recursion, mixed trust-tagging, revocation — all **C**.
- Unsigned-domain coverage — stays the v2-A oracle path, unchanged.

---

## 2. Component boundary

A new pure-Rust crate **`dnssec-core`**: `no_std`, no proof/zkVM dependencies,
compiles identically on the host (unit-tested against real captures) and inside the
RISC0 guest. It is **email-agnostic** — it knows DNSSEC, not DKIM or 0nce.

```
verify_chain(anchor: &TrustAnchor,
             chain: &ChainWitness,
             query: &Query)            // owner name + RR type
        -> Result<AuthenticatedRecord, ChainError>
```

`AuthenticatedRecord` = the verified owner name, type, and RDATA set. The B **guest**
is a thin wrapper: read the witness, call `verify_chain`, commit the public outputs
(§7). 0nce and **C** are consumers of the crate and/or the B proof; neither is
referenced by `dnssec-core`.

---

## 3. Witness model (prover-supplied, untrusted)

The witness is an ordered list of delegation **links** from the root down to the
leaf zone, plus the leaf RRset:

- **Per link** (one per zone cut, e.g. `.` → `com` → `example.com`):
  - the child zone's `DNSKEY` RRset (contains its KSK(s) and ZSK(s));
  - `RRSIG(DNSKEY)` — the DNSKEY RRset self-signed by the child KSK;
  - the parent's `DS` RRset for the child + `RRSIG(DS)` signed by the parent ZSK
    (absent for the root, which is pinned by the anchor instead).
- **Leaf:** the `TXT` RRset at `<selector>._domainkey.<domain>` and its
  `RRSIG(TXT)` signed by the leaf zone's ZSK.

Each RRSIG carries its signer name, algorithm, key tag, labels, original TTL,
inception, and expiration. The host gathers all of this with `dig +dnssec` (or an
equivalent resolver) and serializes it into the witness. Nothing here is trusted;
§4 re-verifies all of it.

---

## 4. Chain-walk validation (the soundness core)

Maintain a single `trusted_ds` (the KSK digest currently trusted), initialized to
the root **anchor**. Walk zones from the root down to the leaf zone; for each zone Z:

1. **Bind Z's KSK.** Find the KSK in Z's `DNSKEY` RRset whose DS digest (canonical
   RDATA, §5) equals `trusted_ds`. (For the root, `trusted_ds` is the anchor.)
2. **Trust Z's key set.** Verify `RRSIG(DNSKEY)` over Z's canonical `DNSKEY` RRset
   under that KSK. Z's DNSKEYs (KSK + ZSKs) are now trusted.
3. **Extend trust to the child** (non-leaf zones only). Verify `RRSIG(DS)` over the
   child zone's `DS` RRset under a ZSK from Z's now-trusted set, then set
   `trusted_ds ← that child DS digest` and descend to the child.
4. **Owner-name chaining (anti-replay).** Assert Z's name is the next label suffix
   toward `domain`, so the walked chain provably corresponds to `domain` and a valid
   chain for one domain cannot be presented for another.

At the leaf zone, after step 2, verify `RRSIG(TXT)` over the canonical leaf RRset
under a ZSK from the leaf zone's trusted set, and assert the leaf owner name equals
`<selector>._domainkey.<domain>` and the type is `TXT`. Parse the DKIM `p=` public
key from the TXT RDATA.

Any assertion failure → guest panic → no proof. RRSIG validity (inception/expiration)
is enforced per §6 at every signature.

---

## 5. Canonicalization (RFC 4034 §6 + §3.1.8.1)

For each RRSIG verification, reconstruct the signed message exactly:

- **RRset canonical form (§6.2/§6.3):** owner name lowercased and in canonical wire
  form; each RR's RDATA in canonical form (names within RDATA lowercased where the
  type requires); RRs sorted in canonical order by RDATA; original TTL from the
  RRSIG substituted.
- **Signed message (§3.1.8.1):** `RRSIG_RDATA` with the signature field removed,
  prepended to the canonical RRset.

This is the DNSSEC analog of 0nce's DKIM canonicalization (`canonical.rs`) — its own
module in `dnssec-core`, hand-reviewed, with its own unit tests. Mis-canonicalization
fails closed (signature mismatch → reject), never opens an acceptance path.

---

## 6. Algorithms, digests, and freshness

**Signature algorithms** (dispatch on the DNSKEY/RRSIG algorithm field):
- `8` RSA/SHA-256 — reuses 0nce's accelerated RSA verify path.
- `13` ECDSA P-256/SHA-256 — via the RISC0 p256 precompile.
- `15` Ed25519 — via the RISC0 ed25519 precompile.
Any other algorithm → reject (documented restriction).

**DS digest types:** `2` SHA-256, `4` SHA-384. Others → reject.

**Trust anchor.** The current IANA root KSK (key tag 20326) is an embedded guest
constant, expressed as the anchor DS digest. KSK rollovers are infrequent (years);
handled by a documented constant bump + a version tag on the anchor so proofs state
which anchor they were verified under.

**Freshness (decision).** The guest takes a verifier-supplied `current_time` public
input and asserts `inception ≤ current_time ≤ expiration` for **every** RRSIG in the
chain. The verifier supplies and trusts its own clock; the proof then means "this
record was DNSSEC-valid at `current_time`," rejecting expired or pre-dated chains.

---

## 7. Public outputs and integration

The B guest commits:
- `domain`, `selector`, and the parsed DKIM `pubkey` (n, e) — the authenticated record.
- `registry_leaf = Poseidon(DOMAIN_SEPARATOR_REGISTRY_V2, domain, selector, n, e)` —
  the **exact v2-A leaf** (shared `nce-core::registry::registry_leaf`). This lets
  **C** admit a B-proof straight into the registry tree with no re-derivation, and
  lets 0nce bind a DKIM proof to a DNSSEC-attested key.
- `anchor_version` and the `current_time` used.

Emitting the leaf keeps B standalone (it is just an extra Poseidon over already-proven
values) while unlocking C's proof-carrying registry cleanly. B does **not** itself
build or modify a registry — that is C.

---

## 8. Definition of done (for the eventual implementation, not this spec)

- `dnssec-core` verifies a real captured chain for a DNSSEC-signed exemplar domain;
  host unit tests green, including the §5 canonicalization vectors.
- B guest produces a prod proof that a real DKIM TXT record is authentic under the
  pinned anchor; verifies; commits the v2-A `registry_leaf`.
- All §1 adversarial cases fail closed (broken link, wrong/mismatched algorithm,
  expired RRSIG, mismatched owner name, DS-digest mismatch, swapped key, replayed
  cross-domain chain).
- `dnssec-core` is `no_std`, email-agnostic, second-model-reviewed for soundness.
- Prove time / proof size recorded in BENCHMARKS for one real chain.

**Implementation prerequisite.** The current 0nce fixture domain `visionaryauto.ai`
is almost certainly not DNSSEC-signed; the prototype needs a real DNSSEC-signed
exemplar that publishes a DKIM key (a controlled domain, or a captured public one).
Secure this before implementation.

---

## 9. The v2 arc (context)

- **A (done):** registry membership — sound vs prover forgery; trusts `registry_root`.
- **B (this spec):** DNSSEC-in-ZK validator — removes the oracle for signed domains;
  standalone; emits the v2-A leaf for C.
- **C (later):** proof-carrying registry — admit B-proofs via recursion; mixed
  admission (DNSSEC-attested vs oracle-attested, trust-tagged) since most domains
  lack DNSSEC; indexed tree for revocation.

Linear: 0PO-316 (B). Implementation is a separate session — brainstorming's terminal
step (writing-plans) is intentionally **not** taken here, per "spec only."
