# Hand-review of the guest

This file is the SPEC.md §9 "second-reviewer hand-review" deliverable. The reviewer reads `methods/guest/src/*.rs` line by line and confirms that the code proves the SPEC.md §2 statement, nothing more and nothing less. Findings go inline; sign-off at the bottom.

**Reviewed:** _add your name and date when complete_

**Commit reviewed:** _add the `git log -1 --format=%h main` short hash you read against_

**Guest line count at review time:** _run `for f in methods/guest/src/*.rs; do awk '/^#\[cfg\(test\)\]/{exit} /^[[:space:]]*$/{next} /^[[:space:]]*\/\//{next} {n++} END{print n+0, FILENAME}' $f; done | sort -rn` and paste the totals_

---

## The statement being reviewed (SPEC.md §2 verbatim)

> The prover possesses an email message *M* and a DKIM-Signature header *H* such that:
> (a) *H* is well-formed per RFC 6376,
> (b) The signing domain in *H* equals the public input `claimed_domain`,
> (c) The RSA signature in *H* verifies against the public key `claimed_pubkey` over the canonicalized signed portion of *M* as specified by *H*'s `c=` and `h=` tags,
> (d) The Merkle root of the nullifier set published by the verifier does NOT yet contain the nullifier *N*, where *N* = Poseidon(`domain_separator_v0`, `claimed_domain`, *H*.signature).

Clause (d) is split. The guest computes and commits *N*. The verifier-side check against the local store lives in `host/src/verify.rs` + `host/src/nullifier_store.rs` and is outside the scope of this review. For the *guest* you are confirming (a)-(c) plus the correct construction of *N*.

---

## File-by-file checklist

### `main.rs` (≈48 lines)

- [ ] Reads `Witness` then `PublicInputs` from `risc0_zkvm::guest::env`, in that order (matches what the host writes).
- [ ] Calls every §4 step in order: §4.1+§4.2 `dkim::locate_and_parse` → §4.4 `body::verify_body_hash` → §4.5 `signed_set::build_signed_data` → §4.6 `verify::verify_rsa_signature` → §4.7 `nullifier::compute_nullifier` → §4.8 `env::commit(&PublicOutputs)`.
- [ ] `PublicOutputs` carries exactly `{ claimed_domain, nullifier }` and nothing else. (Anything extra in the journal becomes part of the proof's public claim.)
- [ ] No `eprintln!` / `env::log` / temporary debug output left behind.

### `dkim.rs` (≈126 lines, the load-bearing file)

`locate_and_parse` is where the soundness-critical assertions live.

- [ ] `dkim_header_index` bounds-checked against `email_raw.len()`.
- [ ] Bytes at the offset compared case-insensitively to literal `"DKIM-Signature:"` (RFC 6376 §3.2). No prefix-match, no case-sensitive compare.
- [ ] Header end is located via CRLF-not-followed-by-WSP (RFC 5322 unfolding-aware).
- [ ] Tag list parse splits on `;`, then on the first `=` in each piece. Trims SP/HTAB/CR/LF around tag names.

Required tag extractions (every one of these must be present and asserted):

- [ ] `v` extracted and asserted equal to `"1"`.
- [ ] `a` extracted and asserted equal to `"rsa-sha256"`.
- [ ] `c` extracted and asserted equal to `"relaxed/relaxed"`.
- [ ] **`d` extracted and asserted equal to `claimed_domain` (public-input binding)**. This is THE soundness-critical line. If it goes missing or gets weakened to a substring/suffix match, a malicious prover can supply an email from attacker.com and claim it came from corp.example. The §7 adversarial #1/#2 and must-pass #3 tests specifically probe this assertion.
- [ ] `s` extracted and asserted equal to `witnessed_selector`.
- [ ] `b` and `bh` extracted; their WSP-stripped values asserted equal to `witnessed_signature_b64` and `witnessed_body_hash_b64` (the §5 host-trust guard).
- [ ] `l=` tag asserted absent. (v0 doesn't implement body-length-limit; accepting an unhandled `l=` would let an attacker truncate the body-hash scope. Formalized in SPEC.md §4.2 + §8.)

Decoding:

- [ ] `b` and `bh` are base64-decoded, with WSP/CRLF stripped from the input first (RFC 6376 §3.5).
- [ ] The returned `DkimHeader` carries the decoded bytes (not the raw base64 strings) in its `signature` and `body_hash` fields.

### `signed_set.rs` (≈117 lines)

`build_signed_data` constructs the bytes the RSA signature covers.

- [ ] h= value is split on `:` with each name trimmed using `trim_wsp_crlf` (not just `trim_wsp`), so folded h= values like `subject\r\n         :date` don't produce bogus names.
- [ ] Header lookup is **bottom-to-top with per-name `lastindex` cursor** (dkimpy convention), not top-to-bottom. The first mention of a name in h= picks the LAST occurrence in the message.
- [ ] **Missing headers are SKIPPED, not emitted as empty `name:\r\n` placeholders.** This matches real-world signers and dkimpy. RFC 6376 §5.4 text says "null string" but practice diverges and we follow practice.
- [ ] Each found header is canonicalized via `canonical::canonicalize_header_relaxed(name, value)` and appended.
- [ ] The DKIM-Signature header itself is appended last via `null_b_tag` + `strip_trailing_crlf`:
  - [ ] `null_b_tag` empties only the `b` tag's value, NOT `bh` (the prefix-confusion guard test in `null_b_tag_does_not_touch_bh_tag` is in place).
  - [ ] The trailing CRLF of the DKIM-Signature is stripped (RFC 6376 §3.7 / §5.4 step 2).
- [ ] The output bytes do NOT end with CRLF (the `output_ends_without_crlf` test enforces this).

### `canonical.rs` (≈92 lines)

`canonicalize_header_relaxed` (RFC 6376 §3.4.2):
- [ ] Lowercases the field name.
- [ ] Unfolds continuation lines (CRLF followed by WSP → just WSP).
- [ ] Collapses WSP runs to single SP.
- [ ] Strips leading + trailing WSP from the value.
- [ ] Output format: `<lowercased name>` `:` `<canonicalized value>` `\r\n`.

`canonicalize_body_relaxed` (RFC 6376 §3.4.4):
- [ ] Per line: collapses WSP runs to single SP, strips trailing WSP.
- [ ] Strips trailing empty lines.
- [ ] **Unconditionally terminates with CRLF.** Empty body canonicalizes to `b"\r\n"` (matches what real DKIM signers produce, despite the RFC text being ambiguous here).

### `body.rs` (≈23 lines)

- [ ] `find_body_start` returns the byte offset just past the first `\r\n\r\n` (RFC 5322 header/body separator), or `email.len()` if no separator.
- [ ] `verify_body_hash` canonicalizes the body region with `canonical::canonicalize_body_relaxed`, SHA-256s the result, and asserts byte-equality with `expected_body_hash` (the bh from §4.2's parse, already base64-decoded).
- [ ] Panics on mismatch (the §7 must-pass #4 path).

### `verify.rs` (≈16 lines)

- [ ] Constructs `RsaPublicKey` from `BigUint::from_bytes_be(pubkey_n)` and `BigUint::from_bytes_be(pubkey_e)`.
- [ ] SHA-256s `signed_data` and PKCS#1 v1.5 verifies with `Pkcs1v15Sign::new::<Sha256>()`.
- [ ] Panics on any failure: invalid pubkey, hash-size mismatch, or crypto verification failure.

### `nullifier.rs` (≈24 lines)

- [ ] `compute_nullifier(domain_sep, claimed_domain, signature)` SHA-256s each of the three inputs and reduces each digest mod the BN254 prime via `Fr::from_be_bytes_mod_order`, producing three field elements.
- [ ] The three field elements are passed to `Poseidon::<Fr>::new_circom(3).hash(&[f1, f2, f3])` in the order `(domain_sep, claimed_domain, signature)`. SPEC.md §3 says exactly this order; swapping arguments would still be deterministic but would diverge from any independent implementation of the same spec.
- [ ] Result is converted to a 32-byte big-endian array via `into_bigint().to_bytes_be()` with left-padding if shorter than 32 bytes.

### `bytes_util.rs` (≈31 lines)

- [ ] `is_wsp` = SP or HTAB only.
- [ ] `is_wsp_or_crlf` = SP, HTAB, CR, or LF.
- [ ] `trim_wsp` strips SP/HTAB only (CRLF preserved).
- [ ] `trim_wsp_crlf` strips SP/HTAB/CR/LF.
- [ ] `strip_wsp_crlf` filters out all of those (returns a fresh Vec).
- [ ] `strip_trailing_crlf` strips a trailing CRLF if present, returns input unchanged otherwise.
- [ ] `bytes_eq_case_insensitive` is length-checked and ASCII-only.

---

## Non-statements to verify (SPEC.md §2)

For each, sit with the code in mind for a moment and confirm nothing in the guest accidentally makes it true.

- [ ] The proof does NOT claim the prover authored the email. (No author-identity check anywhere.)
- [ ] The proof does NOT claim the prover is the recipient. (No To: header binding except its appearance in the signed set if h= names it.)
- [ ] The proof does NOT claim the email is recent. (No timestamp parsing; `t=` and `x=` are part of the signed bytes but never inspected.)
- [ ] The proof does NOT claim the prover currently works at `claimed_domain`. (The proof says "someone signed an email with d=claimed_domain at some past moment.")
- [ ] **Anyone who ever received a DKIM-signed message from the domain can produce this proof** (including forwarded copies). This is acknowledged in the README and is the v0 honest framing.

## Other things worth noticing

- [ ] The `--claimed-domain` and `--dkim-header-offset` CLI flags exist in `host/src/main.rs` purely as adversarial-test hooks. They are documented as such inline. They do not weaken any guest assertion.
- [ ] §6 step-2 known weakness (verifier trusts prover-supplied pubkey) is acknowledged in the README and is NOT something the guest is supposed to solve. v1 candidates are documented in SPEC.md §8.

---

## Findings

If something doesn't match the §2 statement, note it here with a file:line reference. Otherwise leave empty.

```
(none)
```

---

## Sign-off

I, _name_, have read the guest line by line at commit _hash_ and confirm the code proves SPEC.md §2 as written, no more and no less, modulo the findings above.

Signed: ______________________  Date: ______________________
