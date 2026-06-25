# DRAFT — A BN254-Poseidon Merkle cost trap in RISC0, and the stable 3.0 accelerator recipe

**Status: DRAFT — all placeholders resolved.** The accelerator number is now measured
(0PO-388, 2026-06-25). The **soundness sign-off is complete** — an
independent module-level audit (Kosmos T1-complete, 2026-06-25) found the guest enforces
the §2 statement with no exploitable host/prover deviation; its only finding was a
non-soundness RFC-conformance caveat (WSP-before-colon header canonicalization), since
fixed. Everything else is measured and reproducible.

**Framing (honest, post-validation).** Neither finding is a discovery. Independent
validation (Edison Scientific Kosmos, 2026-06-25) confirmed both are *partially* novel:
the community already knows zkVM Merkle trees should ride accelerators, and the RISC0
patch ingredients are public. The contribution is **quantification and assembly** — the
measured magnitude on a real DKIM/RSA workload, a mixed-hash design that recovers most of
it without changing leaf semantics, and the exact stable 3.0.5 patch tuple as one block.
Positioned that way, with prior art cited, it's a useful engineering note — not a landmark.

---

## 1. Context

0nce is a RISC0 zkVM proof that a prover possesses an email DKIM-signed (RFC 6376,
rsa-sha256, relaxed/relaxed) by a claimed domain, without revealing the email. v2-A added
**registry membership**: the signing key is witnessed (private) and proven in-ZK to be a
member of a verifier-pinned Merkle root, closing a gap where a malicious prover could
supply their own key. The membership check is a depth-20 Merkle fold inside the guest.

## 2. The trap: BN254 Poseidon Merkle in RISC0

Adding the membership fold — implemented as the same BN254 Poseidon primitive as the
project's Circom-compatible nullifier — **4×'d the proof.** Measured on the same email and
machine:

| guest | prove (i5-11600K) | proof size |
|---|---|---|
| v1 (no registry) | 31:09 | 3.94 MB |
| v2-A (BN254 Poseidon Merkle) | **2:06:51** | **15.0 MB** |

The cause: the fold is 1 leaf `Poseidon(5)` + 20 `Poseidon(2)` over **BN254**, which RISC0
executes as **unaccelerated software bignum**. Each Poseidon permutation is hundreds of
256-bit field multiplications; 21 of them rivaled the RSA-2048 verify in cycle count. The
design's "the Merkle fold is cheap vs. RSA" assumption was simply false for BN254-in-RISC0.

This is **known in principle** — RISC0 documents that performance hinges on precompiles
[precompiles docs], an open RISC0 issue asks for zk-friendly hashes specifically "to
implement Merkle trees efficiently" [risc0/risc0#3206], and public zkVM Merkle benchmarks
default to SHA-256 on RISC0 rather than BN254 Poseidon [inertialabsxyz/zkvm-merkle-
comparison]. What was not public is the **magnitude on a DKIM/RSA workload** and a concrete
recovery design.

## 3. The fix: a mixed-hash tree

Keep the **leaf** on BN254 Poseidon (it must stay Circom-compatible — the nullifier shares
that primitive and is a stable public output), and swap only the **2-to-1 node hash** to
SHA-256, which rides the RISC0 SHA accelerator and is ~2 orders of magnitude cheaper than a
BN254 Poseidon permutation. Leaf semantics unchanged; only the tree shape changes.

| guest | prove | proof | nullifier |
|---|---|---|---|
| v2-A BN254 Poseidon Merkle | 2:06:51 | 15.0 MB | `20939a2d…` |
| v2-A **SHA-256 Merkle** | **48:43.86** | **5.34 MB** | `20939a2d…` (bit-identical) |

**2.6× faster, 2.8× smaller**, nullifier untouched.

**Why the untagged `SHA-256(left‖right)` node is sound** (no leaf/node domain-separation
byte): the safety does *not* come from the `leaf_index < 2^20` bound alone, as an early
note implied. It comes from three enforced properties together — **fixed-depth
verification** (the fold is always exactly 20 hashes; no variable-depth re-labeling of an
internal node as a leaf), **in-circuit leaf derivation** (the guest computes
`leaf = Poseidon(sep, domain, selector, n, e)`; the prover cannot hand the checker an
arbitrary 32-byte string), and **second-preimage resistance** of the node hash. A confusion
attack would require a real SHA-256 second preimage or a Poseidon collision — standard-
infeasible. (Independently confirmed sound, Kosmos T1.)

## 4. The residual, and the stable RISC0 3.0.5 accelerator recipe

The SHA-Merkle fix removes the 20 node Poseidons but does **not** reach the v1 baseline:
~17 min / ~1.66 MB remain, from the one surviving BN254 Poseidon (the `t=6` leaf) plus
still-unaccelerated software SHA-256 and the RSA-2048 verify. The lever for the rest is
RISC0's stable crypto accelerators. The exact working tuple for a **risc0-zkvm 3.0.5** guest
(verified to apply; **no `unstable` feature required** — only `tiny-keccak` needs it):

```toml
# methods/guest/<guest>/Cargo.toml  — guest is its own workspace root
[dependencies]
sha2 = { version = "=0.10.9", features = ["oid"] }
rsa  = "=0.9.9"   # fork's latest tag; RSA-PKCS1v1.5 verify unchanged vs 0.9.10

[patch.crates-io]
sha2 = { git = "https://github.com/risc0/RustCrypto-hashes", tag = "sha2-v0.10.9-risczero.0" }
rsa  = { git = "https://github.com/risc0/RustCrypto-RSA",    tag = "v0.9.9-risczero.0" }
```

The `rsa` fork transitively pulls `risc0-bigint2`, accelerating the RSA-2048 modexp (the
dominant cost). Confirm application by grepping the *guest* `Cargo.lock` for the fork
sources. The ingredients are public in RISC0's precompile docs; what's scarce is this
**assembled, version-matched tuple** confirmed stable on 3.0.5 — the official docs present
the pieces, not this copy-paste block.

**Measured (2026-06-25, same i5 / risc0 3.0.5 / real.eml):** prove **48:43 → 27:02.99**
(1.8× faster), proof **5.34 → 2.67 MB** (1.9× smaller). Nullifier (`20939a2d…`) and root
(`65ff99…`) bit-identical — accelerators change implementation, not the math. This puts the
full v2-A registry-membership proof **below the v1 *unaccelerated* baseline (31:09 / 3.94
MB)** on both axes: the accelerators more than paid for the membership cost. (No
accelerated-v1 number is recorded, so the honest claim is "accelerators overcame the
membership cost and then some," not that membership is free.)

## 5. Reproducibility

All numbers are real prod proves (not dev mode) on an i5-11600K (6C/12T), 31 GB, Fedora 44,
risc0-zkvm 3.0.5, on a 6,708-byte Gmail-signed fixture. The pipeline is deterministic: the
nullifier and proof size reproduced **bit-identical across two different machines**, which
is what licenses treating these as measurements rather than anecdotes.

## 6. What the proof does and does not prove (scoping)

A deliberate honesty stance, and arguably the most reusable idea here: the proof shows
**possession**, not authorship, recipienthood, recency, or current affiliation — a
forwarded copy still proves. Many ZK-email descriptions blur these; stating the non-claims
plainly is cheap and load-bearing for anyone who builds on it.

## References (to verify/complete before publishing)

- RISC0 cryptographic precompiles: `dev.risczero.com/api/zkvm/precompiles` (+ Mintlify mirror).
- risc0/risc0#3206 — "Expose zk-friendly hashes to guest, for more efficient Merkle trees."
- inertialabsxyz/zkvm-merkle-comparison — defaults SHA-256 on RISC0/SP1/OpenVM.
- risc0/RustCrypto-hashes, risc0/RustCrypto-RSA — the accelerated forks.
