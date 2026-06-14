#!/usr/bin/env python3
"""Generate the re-signed-email fixtures for SPEC.md §7 adversarial #5.

Produces two emails with IDENTICAL bodies but DIFFERENT DKIM signatures
(same synthetic domain + key, different Date header => different `b=`),
plus the matching DKIM public-key tag. Feeds
`adversarial.rs::re_signed_email_yields_different_nullifier_both_accepted`:
v0 computes nullifier = Poseidon(domain_sep, claimed_domain, signature),
so two distinct signatures over the same domain must yield two distinct
nullifiers, both accepted as separate events.

Unlike `real.eml` (a real Gmail-signed capture), these are synthetic so
the fixture is hermetic and needs no live mailbox. Signed with
relaxed/relaxed, rsa-sha256, no `l=` tag, matching the v0 guest contract.

Requires: dkimpy, cryptography.  Re-running regenerates the key and thus
new signatures; the committed .eml/.tag files are the canonical fixtures.
"""
import base64
import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DOMAIN = b"insider.test"
SELECTOR = b"v0test"
HEADERS = [b"from", b"to", b"subject", b"date"]

BODY = (
    "Heads up: the Q3 numbers were moved before the board saw them.\r\n"
    "I have the original deck.\r\n"
)

def message(date: str) -> bytes:
    return (
        f"From: insider <whistle@insider.test>\r\n"
        f"To: verifier <v@example.org>\r\n"
        f"Subject: the thing\r\n"
        f"Date: {date}\r\n"
        f"\r\n{BODY}"
    ).encode()

def sign(msg: bytes, privkey_pem: bytes) -> bytes:
    sig = dkim.sign(
        msg, SELECTOR, DOMAIN, privkey_pem,
        include_headers=HEADERS,
        canonicalize=(b"relaxed", b"relaxed"),
    )
    return sig + msg  # dkim.sign returns the "DKIM-Signature: ...\r\n" header

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

    a = sign(message("Mon, 01 Jun 2026 09:00:00 +0000"), privkey_pem)
    b = sign(message("Tue, 02 Jun 2026 14:30:00 +0000"), privkey_pem)
    assert a != b, "signatures must differ"

    with open("resigned_a.eml", "wb") as f: f.write(a)
    with open("resigned_b.eml", "wb") as f: f.write(b)
    with open("resigned.pubkey.tag", "wb") as f: f.write(tag)
    print("wrote resigned_a.eml, resigned_b.eml, resigned.pubkey.tag")

if __name__ == "__main__":
    main()
