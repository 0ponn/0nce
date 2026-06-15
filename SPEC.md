# SPEC.md — ZK-Email Insider Proof, v0

**Status:** v0 learning scope. Single prover, single verifier, single domain. No platform, no receivers, no UI. CLI in / CLI out.

**Goal:** Build a working zero-knowledge proof system where a prover, in possession of an email DKIM-signed by a domain they do not control, can convince a verifier that they hold such an email — without revealing the email's contents, headers, local-part, or any identifier beyond the signing domain.

This is a learning project. The cryptographic statement must be precise, the implementation must be small enough to audit by hand, and the verifier must be unable to be fooled by a malicious prover even if the prover wrote the prover code.

---

## 1. Threat model (v0)

**In scope:**
- Malicious prover trying to forge a proof without possessing a valid DKIM-signed email from the target domain.
- Malicious prover trying to reuse another prover's proof (replay).
- Malicious prover trying to claim a different domain than the one actually signed.
- Honest-but-curious verifier learning more than the spec allows.

**Out of scope for v0:**
- Network anonymity (no Tor, no mixnet — local CLI only).
- Receiver coercion, key compromise, endpoint compromise.
- DKIM key rotation, selector lookup over DNS at verify time.
- Multiple receivers, nullifier coordination across receivers.
- Source-side OPSEC (file metadata in the source email file, etc.).
- Any UI, any network transport, any persistence beyond local files.

These are real concerns. They are deferred because they are not what this project is for.

---

## 2. Cryptographic statement

The proof, when verified, convinces the verifier of exactly the following statement and nothing more:

> "The prover possesses an email message M and a DKIM-Signature header H such that:
> (a) H is well-formed per RFC 6376,
> (b) The signing domain in H equals the public input `claimed_domain`,
> (c) The RSA signature in H verifies against the public key `claimed_pubkey` over the canonicalized signed portion of M as specified by H's `c=` and `h=` tags,
> (d) The Merkle root of the nullifier set published by the verifier does NOT yet contain the nullifier N, where N = Poseidon(domain_separator_v0, claimed_domain, H.signature)."

The verifier learns: `claimed_domain`, `claimed_pubkey`, `N`, and `valid: bool`.

The verifier does NOT learn: the email body, any header other than the domain field of `DKIM-Signature`, the local-part of any From/To/Cc, the email's timestamp, the selector, or the signature itself (only its hash, via N).

**Non-statements** (things this proof does NOT claim, to be stated explicitly so neither prover, verifier, nor reader confuses them):
- The proof does NOT claim the prover authored the email.
- The proof does NOT claim the prover is the recipient.
- The proof does NOT claim the email is recent.
- The proof does NOT claim the prover currently works at `claimed_domain`.
- The proof claims only that the prover, at some point, came into possession of a message DKIM-signed by `claimed_domain`. Anyone who ever received such a message — including a forwarded copy — can produce this proof.

This last point is critical and must be documented in any user-facing material. v0 deliberately does not address it. Future versions can tighten it via fresher-than-X-days constraints, recipient-binding via opaque headers, or org-issued credentials.

---

## 3. Public inputs / private inputs / public outputs

**Public inputs (verifier-supplied, in the proof's public input vector):**
- `claimed_domain: bytes` — the domain the prover claims the email is signed by (e.g., `b"corp.example"`).
- `claimed_pubkey: RSAPublicKey` — the RSA public key for that domain/selector. Out-of-band lookup in v0; verifier fetches this via DNS TXT and supplies it.
- `nullifier_root: Field` — the Merkle root of nullifiers already seen by this verifier. v0: a single root, no Merkle path proof of non-inclusion; verifier checks N's absence by linear scan of its local store after extracting N from the proof's public outputs.

**Private inputs (witness, prover-only):**
- `email_raw: bytes` — the full RFC 5322 email message as received, including headers.
- `dkim_header_index: u32` — byte offset where `DKIM-Signature:` header begins.
- `selector: bytes` — the DKIM selector (e.g., `b"google"`); private because the selector can narrow the anonymity set in some deployments.
- `signature: bytes` — extracted from DKIM-Signature `b=` tag.
- `body_hash: bytes` — extracted from DKIM-Signature `bh=` tag (witnessed; circuit also recomputes and asserts equality).

**Public outputs (committed by the proof):**
- `claimed_domain` (echoed; binds the proof to the input).
- `nullifier: Field` — `Poseidon(domain_separator_v0, claimed_domain, signature)`.

The proof itself is a single byte blob produced by the chosen zkVM (RISC0 or SP1; pick one in week 1, do not switch).

---

## 4. What the zkVM guest program must do

Guest = the program whose execution is proven. Must be small, readable, hand-reviewed.

In order:

1. Parse `email_raw` enough to locate the `DKIM-Signature` header at `dkim_header_index`. Assert the header starts with the exact bytes `DKIM-Signature:` (case-insensitive per RFC 6376 §3.2). Parse its tag-value list.

2. Extract from the DKIM-Signature header: `v`, `a`, `c`, `d`, `s`, `h`, `bh`, `b`, and any others present. Assert `v=1`. Assert `a` is `rsa-sha256` (v0 supports only this; document the restriction). Assert `d` (domain field) equals the public input `claimed_domain`. Assert `s` equals the witnessed `selector`. Assert the `l=` (body-length-limit) tag is **not present** — v0 does not implement body-length truncation; accepting `l=` unhandled would let an attacker shrink the body-hash scope, so we reject. Deferred to v1 (§8).

3. Apply the canonicalization specified by `c=` (header/body algorithm pair) to the relevant portions of `email_raw`. v0 supports `relaxed/relaxed` only. Document the restriction. Other canonicalizations are a future-version task; assert and fail otherwise.

4. Compute SHA-256 of the canonicalized body. Assert it equals `bh` from the header.

5. Construct the canonicalized header set per the `h=` tag, with the DKIM-Signature header itself appended last with `b=` value emptied (per RFC 6376 §3.7).

6. Verify the RSA signature `b` over the SHA-256 of that constructed header set, using `claimed_pubkey`. This is the expensive step.

7. Compute `nullifier = Poseidon(domain_separator_v0_constant, claimed_domain, signature)`. Emit as public output.

8. Emit `claimed_domain` as public output.

If any assertion fails, the guest panics, no proof is produced.

**Explicit non-goals for the guest:**
- No body parsing beyond the canonicalization step.
- No header parsing beyond what's needed to find DKIM-Signature and apply `h=`.
- No timestamp handling.
- No selector validation against DNS (verifier does that out-of-band).

---

## 5. What the host program (prover side) does

Outside the zkVM:

1. Read email file from disk.
2. Locate DKIM-Signature header, extract `d=`, `s=`, `b=`, `bh=`. (Yes, this is duplicated work with the guest. The host extracts to populate the witness; the guest re-extracts and asserts to prevent the host from lying to the guest.)
3. Resolve `s._domainkey.d` via DNS TXT, parse the RSA public key. (v0: log a warning and prompt to confirm; this is out of the trust boundary.)
4. Populate witness struct.
5. Invoke zkVM prove. This will take seconds to minutes depending on email size.
6. Write proof artifact and public inputs to disk.

The host is not trusted. Anything the host could lie about must be re-asserted inside the guest.

---

## 6. What the verifier does

1. Receive proof artifact + claimed public inputs from prover.
2. Independently resolve `s._domainkey.d` for the claimed domain... wait, no — the selector is private in v0. Therefore the verifier must trust the prover's claimed pubkey, OR the verifier fetches all currently-published selectors for the claimed domain and accepts the proof if it verifies against any.
   - **v0 decision:** verifier accepts a `claimed_pubkey` as a public input from the prover, but logs it and the operator must manually confirm via a separate DNS query that this pubkey is currently or recently published for the claimed domain. This is a known weakness, documented here, and addressed in v1 by either (a) making the selector public, (b) proving against a Merkle tree of known-good pubkeys for the domain, or (c) doing DNSSEC-in-ZK. Each has tradeoffs. v0 punts.
3. Run the zkVM verifier on the proof + public inputs. If it returns false, reject.
4. Extract `nullifier` from public outputs. Check it is not in the local nullifier store. If present, reject as replay. Otherwise insert.
5. Output: `(accepted: bool, claimed_domain, nullifier)`.

---

## 7. Test plan

The proof of correctness for this v0 is the test suite, not vibes.

**Must-pass tests:**
- Real DKIM-signed email from a controlled domain → proof verifies.
- Same email submitted twice → second submission rejected (nullifier replay).
- Email from a different domain than `claimed_domain` → guest panics, no proof.
- Email with tampered body → bh mismatch, guest panics.
- Email with tampered DKIM-Signature → RSA verification fails, guest panics.

**Adversarial tests (the part most ZK projects skip):**
- Prover supplies a valid email but lies about `claimed_domain` in public inputs → guest catches mismatch, panics.
- Prover supplies a forged DKIM-Signature header that "verifies" against a key the prover controls but claims a different domain → must fail. (This is the attack the public input binding in step 2 of the guest is designed to prevent. Test it explicitly.)
- Prover supplies an email with TWO DKIM-Signature headers, one valid and one for the claimed domain → must not be exploitable. Document v0 behavior (probably: only the header at `dkim_header_index` is considered; if it's not the claimed domain, fail).
- Empty email, malformed email, email with no DKIM-Signature, email with malformed DKIM tags → all must fail gracefully, never produce a proof.
- Same email body, different DKIM-Signature (re-signed) → different nullifier, both accepted. Document this; may or may not be desired in v1.

**Soundness sanity check:** flip a single bit in the signature, regenerate proof — should panic in guest, no proof produced. Then flip a bit in the *proof artifact itself* after generation — verifier should reject. Both paths must be tested.

---

## 8. Out-of-scope decisions to revisit in v1

Listed here so they're not forgotten and not silently smuggled in:

- Selector privacy vs. pubkey-trust tradeoff (§6 step 2). **DONE in v2-A** — registry membership: the pubkey is witnessed and proven a member of a verifier-pinned `registry_root`, and the selector is now private. See `docs/superpowers/specs/2026-06-14-0nce-v2a-registry-membership-design.md`. (Body disclosure below is DONE in v1; freshness/recipient-binding/canon modes remain.)
- Freshness — proving the email is recent. Probably via DKIM signature timestamp + a verifier-supplied recent-block-hash or similar.
- Recipient binding — proving the prover received the email, not merely possesses it.
- Body content disclosure — selectively revealing one regex match from the body (the standard ZK-Email selective disclosure pattern).
- Multiple canonicalization modes, multiple signature algorithms (Ed25519 is in RFC 8463).
- DKIM body-length-limit (`l=` tag) support. v0 rejects emails whose DKIM-Signature includes `l=`. v1 would canonicalize the body then truncate to `l` bytes before SHA-256.
- Network transport, Tor, receiver federation, all the platform-level concerns.

---

## 9. Definition of done for v0

- All must-pass and adversarial tests pass.
- Guest program is under 500 lines of Rust, hand-readable.
- A second reviewer (adversarial-review model pass + you, separately) has read the guest line by line and signed off that the cryptographic statement in §2 is what's actually being proven.
- README documents the non-statements in §2 prominently.
- Prove time and proof size are measured and recorded for a 10KB email.

Not in scope for done: usability, deployment, more than one signature algorithm, anything in §8.
