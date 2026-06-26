#!/usr/bin/env bash
# Worker: one "region|category|domain" -> CSV line. Used via xargs -P.
SELECTORS="selector1 selector2 google default dkim mail s1 s2 k1 k2"
IFS='|' read -r region cat dom <<<"$1"
[ -z "$dom" ] && exit 0

dv() { local o; o=$(delv "$1" "$2" 2>&1); echo "$o" | grep -q "fully validated" && ! echo "$o" | grep -q "unsigned answer"; }

apex=$(dv "$dom" DNSKEY && echo signed || echo unsigned)
sel=""; kind=""; dkv=""
for s in $SELECTORS; do
  D="${s}._domainkey.${dom}"
  cn=$(dig +short +time=2 +tries=1 "$D" CNAME 2>/dev/null | head -1)
  txt=$(dig +short +time=2 +tries=1 "$D" TXT 2>/dev/null | head -1)
  if [ -n "$cn" ] && dig +short +time=2 +tries=1 "$D" TXT 2>/dev/null | grep -qi DKIM1; then
    sel="$s"; kind="cname"; dkv=$(dv "$D" TXT && echo yes || echo no); break
  elif echo "$txt" | grep -qi 'v=DKIM1'; then
    sel="$s"; kind="direct"; dkv=$(dv "$D" TXT && echo yes || echo no); break
  fi
done
echo "${region},${cat},${dom},${apex},${sel:-none},${kind:-none},${dkv:-na}"
