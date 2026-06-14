#!/usr/bin/env python3
"""Generate org-membership disclosure fixtures for the v1 design §8 tests.

The aligned happy-path (disclose From/To) and the header-prepend and
misaligned cases all reuse `resigned_a.eml` (in-test), so this script only
mints the two fixtures that require a *real signature over crafted content*:

  org_nonh_to.eml      — To present but NOT in h= (signed h=from:subject:date).
                         disclose To => guest panics "not covered by h=".
  org_malformed_from.eml — From value has no parseable address (signed, in h=).
                         disclose From => guest panics in address parsing.

Both are signed with one synthetic key → org.pubkey.tag. Hermetic; needs no
live mailbox. relaxed/relaxed, rsa-sha256, no l= — the v1 guest contract.

Requires: dkimpy, cryptography. Re-running regenerates the key; the committed
.eml/.tag files are the canonical fixtures.
"""
import base64
import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DOMAIN = b"insider.test"
SELECTOR = b"v0test"

def message(from_value: str) -> bytes:
    return (
        f"From: {from_value}\r\n"
        f"To: ops <ops@insider.test>\r\n"
        f"Subject: org membership\r\n"
        f"Date: Mon, 01 Jun 2026 09:00:00 +0000\r\n"
        f"\r\nbody\r\n"
    ).encode()

def sign(msg: bytes, privkey_pem: bytes, headers) -> bytes:
    sig = dkim.sign(
        msg, SELECTOR, DOMAIN, privkey_pem,
        include_headers=headers,
        canonicalize=(b"relaxed", b"relaxed"),
    )
    return sig + msg

def main():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    privkey_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    spki_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    tag = b"v=DKIM1;k=rsa;p=" + base64.b64encode(spki_der)

    # To present in the message but excluded from h= -> not covered.
    nonh = sign(message("whistle <whistle@insider.test>"), privkey_pem,
                [b"from", b"subject", b"date"])
    # From with no parseable address, but signed and in h=.
    malformed = sign(message("noatsign-here"), privkey_pem,
                     [b"from", b"to", b"subject", b"date"])

    with open("org_nonh_to.eml", "wb") as f: f.write(nonh)
    with open("org_malformed_from.eml", "wb") as f: f.write(malformed)
    with open("org.pubkey.tag", "wb") as f: f.write(tag)
    print("wrote org_nonh_to.eml, org_malformed_from.eml, org.pubkey.tag")

if __name__ == "__main__":
    main()
