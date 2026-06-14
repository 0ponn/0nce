# REVIEW-v1 — adversarial self-review (implementer pass)

Implementer's adversarial pass over the v1 disclosure feature. A second model
/ human still owes the line-by-line guest sign-off (v1 DoD §9). This records
what I checked, what holds, and the one decision that needs the human.

## What v1 proves (confirm against the guest)

Guest pipeline (`methods/guest/src/main.rs`), in order: §4.1/4.2 locate+parse
DKIM-Signature → §4.4 body hash → §4.5 build signed set → §4.6 RSA verify →
§4.7 nullifier → **§4.9** assert disclosed header ∈ `h=` + read bottom-most
(signed) instance → **§4.10** parse address → §4.8 commit
`{claimed_domain, nullifier, disclosed_address}`.

That matches design §2 (e)/(f): the disclosed address is taken from a header
the signature covers, and is revealed. ✔

## Holds (checked)

1. **Header-prepend safety.** `signed_set::signed_header_value` returns the
   bottom-most matching header; `build_signed_data` selects the same bottom-up
   instance for RSA. So the disclosed instance == the signed instance. A
   `From:` prepended above the signed one is never selected (still RSA-valid,
   discloses the real one); a `From:` appended below changes the signed data
   and fails RSA. Both paths covered by `disclosure.rs` +
   `signed_set::signed_header_value_returns_bottom_most_instance`. ✔
2. **Grammar rejects multi-address / group.** Two `@` → panic; covered. So a
   multi-recipient `To:` or group syntax can't be disclosed in v1 (intended
   restriction). ✔
3. **Alignment is observable, not assumed.** Guest emits the address; verifier
   computes ALIGNED/NOT aligned from the two public values. No soundness rides
   on alignment. ✔
4. **Nullifier unchanged.** Per-signature; disclosing From then To of the same
   email yields one nullifier (second = replay). Tests use separate stores. ✔

## NEEDS THE HUMAN — design fork

**v1 currently makes disclosure mandatory.** Every proof now reveals an
identity address. That removes v0's "anonymous within the domain" capability
(prove possession of *some* email from `claimed_domain` without naming who).

Option to restore it: make the input `Option<HeaderKind>` and add
`--disclose none|from|to` (default could stay `from`, or flip to `none` to
keep v0 behavior the default). When `none`, skip §4.9/§4.10 and commit an
empty `disclosed_address` — v1 becomes strictly additive over v0.

I did **not** make this change unilaterally: it alters the proven statement,
and this project's ethos is "SPEC §2 is the contract; drift = drift." The
approved v1 design states disclosure as an added condition (always on). If you
want the anonymous mode preserved, say so and I'll wire optionality (small,
~1 commit). Otherwise mandatory disclosure stands as designed.

## For the second-model sign-off

- Verify the §4.9 selection-consistency claim under oversigning (`h=From:From`):
  `signed_header_value` returns the first-mention (bottom-most) instance; confirm
  that is the intended disclosed instance and that it can't diverge from what
  RSA covered.
- Confirm the restricted address grammar (`address.rs`) has no parser path that
  accepts an address spanning unsigned bytes (it only ever sees the value
  returned from the signed set, so it shouldn't — but verify).
- Re-confirm the demo-not-production caveat: the pubkey-trust gap means a
  malicious prover can still forge key + email + disclosure. v1 is not
  lending-sound until that closes.
