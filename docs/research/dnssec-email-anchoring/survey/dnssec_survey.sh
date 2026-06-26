#!/usr/bin/env bash
# US vs EU DNSSEC + DKIM-anchoring survey. Uses delv (validates from root anchor)
# so results are real, not resolver-dependent. CSV to stdout.
SELECTORS="default dkim mail selector1 selector2 google s1 s2 k1 k2 dkim1 key1 smtp mx ed25519 fm1 fm2 fm3 protonmail1 scph0123 pic 202401 202501 2024 dec2024 jun2025"

# region|category|domain
DOMAINS='
US|gov|gsa.gov
US|gov|fcc.gov
US|gov|nasa.gov
US|gov|nist.gov
US|gov|cisa.gov
US|gov|irs.gov
US|gov|state.gov
US|gov|treasury.gov
US|gov|whitehouse.gov
US|gov|usa.gov
US|infra|verisign.com
US|infra|icann.org
US|infra|arin.net
US|infra|isc.org
US|infra|internet2.edu
US|tech|google.com
US|tech|microsoft.com
US|tech|apple.com
US|tech|amazon.com
US|tech|cloudflare.com
US|tech|github.com
US|finance|jpmorganchase.com
US|finance|bankofamerica.com
US|finance|wellsfargo.com
US|finance|citi.com
US|edu|mit.edu
US|edu|stanford.edu
US|edu|berkeley.edu
US|news|nytimes.com
US|news|wsj.com
EU|gov|bund.de
EU|gov|europa.eu
EU|gov|service-public.fr
EU|gov|government.nl
EU|gov|gov.pl
EU|gov|gov.it
EU|gov|lamoncloa.gob.es
EU|gov|bund.gv.at
EU|gov|gov.uk
EU|gov|riksdagen.se
EU|infra|afnic.fr
EU|infra|nlnetlabs.nl
EU|infra|nic.cz
EU|infra|ripe.net
EU|infra|denic.de
EU|infra|sidn.nl
EU|tech|sap.com
EU|tech|spotify.com
EU|tech|booking.com
EU|tech|adyen.com
EU|finance|ing.com
EU|finance|bnpparibas.com
EU|finance|santander.com
EU|finance|deutsche-bank.de
EU|edu|ethz.ch
EU|edu|tudelft.nl
EU|edu|sorbonne-universite.fr
EU|news|bbc.co.uk
EU|news|lemonde.fr
EU|news|spiegel.de
'

delv_validates() {
  # Validated iff delv reports "fully validated" AND no "unsigned answer"
  # downgrade anywhere in the chain (catches CNAME -> unsigned-SaaS keys).
  local out; out=$(delv "$1" "$2" 2>&1)
  echo "$out" | grep -q "fully validated" && ! echo "$out" | grep -q "unsigned answer"
}

echo "region,category,domain,dnssec_apex,dkim_selector,dkim_kind,dkim_validated"
echo "$DOMAINS" | grep -v '^$' | while IFS='|' read -r region cat dom; do
  apex=$(delv_validates "$dom" DNSKEY && echo signed || echo unsigned)
  sel=""; kind=""; dkv=""
  for s in $SELECTORS; do
    D="${s}._domainkey.${dom}"
    cn=$(dig +short "$D" CNAME 2>/dev/null | head -1)
    txt=$(dig +short "$D" TXT 2>/dev/null | head -1)
    if [ -n "$cn" ]; then
      # CNAME present — is there a key at the end?
      [ -z "$(dig +short "$D" TXT 2>/dev/null | grep -i DKIM1)" ] && continue
      sel="$s"; kind="cname:${cn%%._domainkey*}"; kind="${kind:0:24}"
      dkv=$(delv_validates "$D" TXT && echo yes || echo no); break
    elif echo "$txt" | grep -qi 'v=DKIM1'; then
      sel="$s"; kind="direct"
      dkv=$(delv_validates "$D" TXT && echo yes || echo no); break
    fi
  done
  echo "${region},${cat},${dom},${apex},${sel:-none},${kind:-none},${dkv:-na}"
done
echo "SURVEY_DONE"
