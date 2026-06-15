#!/usr/bin/env bash
# 0nce v2-A — "watch the forgery stop working" demo.
#
# Runs in RISC0_DEV_MODE so it is instant: the registry-membership and RSA
# assertions execute in dev mode (only the STARK receipt is mocked). A real
# cryptographic proof of the same flow takes ~31 min; see BENCHMARKS.md.
set -euo pipefail
export PATH="$HOME/.risc0/bin:$PATH"
export RISC0_DEV_MODE=1
cd "$(dirname "$0")"

BIN=${BIN:-target/debug/0nce}
F=host/tests/fixtures
TMP=$(mktemp -d)
hr() { printf '%s\n' "----------------------------------------------------------------"; }

if [ ! -x "$BIN" ]; then
  echo "Building $BIN ..."; cargo build -p host >/dev/null 2>&1
fi

hr; echo "1. The VERIFIER builds the trusted DKIM key registry for insider.test"; hr
"$BIN" registry build \
  --pubkey-tag "$(cat "$F/resigned.pubkey.tag")" \
  --domain insider.test --selector v0test \
  --out "$TMP/registry.json"
ROOT=$("$BIN" registry build \
  --pubkey-tag "$(cat "$F/resigned.pubkey.tag")" \
  --domain insider.test --selector v0test \
  --out "$TMP/registry.json" | grep -oE '[0-9a-f]{64}')
echo "Verifier pins root: $ROOT"

hr; echo "2. HONEST prover: real insider.test email -> proof -> verify (pinned)"; hr
"$BIN" prove --email "$F/resigned_a.eml" --registry "$TMP/registry.json" -y \
  --out "$TMP/honest.proof" | sed 's/^/    /'
"$BIN" verify --proof "$TMP/honest.proof" --registry-root "$ROOT" \
  --nullifier-store "$TMP/nf-honest.txt" | sed 's/^/    /'
echo ">>> ACCEPTED. The signing key was a registry member; nothing else leaked."

hr; echo "3. FORGER: signs with their OWN key, builds their OWN registry"; hr
"$BIN" registry build \
  --pubkey-tag "$(cat "$F/org.pubkey.tag")" \
  --domain insider.test --selector v0test \
  --out "$TMP/forger-registry.json" >/dev/null
"$BIN" prove --email "$F/org_nonh_to.eml" --registry "$TMP/forger-registry.json" -y \
  --out "$TMP/forged.proof" >/dev/null
echo "Forger produced a proof — but against THEIR root, not the verifier's."
echo "Verifier pins the real root and checks:"
if "$BIN" verify --proof "$TMP/forged.proof" --registry-root "$ROOT" \
     --nullifier-store "$TMP/nf-forge.txt" 2>&1 | sed 's/^/    /'; then
  echo ">>> BUG: forgery accepted"; exit 1
else
  echo ">>> REJECTED: registry root mismatch. The forgery cannot pass the pin."
fi

hr; echo "4. FORGER, other path: forge an email for the REAL registry"; hr
echo "Trying to prove an email NOT signed by the registered key:"
OUT=$("$BIN" prove --email "$F/org_nonh_to.eml" --registry "$TMP/registry.json" -y \
        --out "$TMP/forged2.proof" 2>&1 || true)
if grep -qi 'RSA signature verification failed' <<<"$OUT"; then
  grep -i 'RSA signature verification failed' <<<"$OUT" | sed 's/^/    /'
  echo ">>> NO PROOF: the registered key is used for RSA verify, which fails."
else
  echo ">>> BUG: expected RSA failure"; printf '%s\n' "$OUT" | sed 's/^/    /'; exit 1
fi

hr
echo "v2-A closes the v0 pubkey-trust gap: the verifier trusts a pinned"
echo "registry root, and a prover can no longer forge with their own key."
rm -rf "$TMP"
