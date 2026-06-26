# Email trust-anchoring across governments — a DNS census

**Question.** For government and DNS-infrastructure domains, is the zone DNSSEC-signed and
validated to the DNS root, and — the part almost nobody checks — does the **DKIM
email-signing key** itself validate to root, or does it sit in an unsigned zone a
DNS-spoofing adversary could swap?

**Scope.** A **full census of all 1,343 US federal `.gov` domains** (CISA/GSA official
list), a `.mil` sample (DoD publishes no list), and an **international landscape** of ~30
countries (flagship government domain + national DNS registry each). Validation is real:
`delv`, from the IANA root trust anchor, independent of any resolver. Snapshot: June 2026.

> **HTML version:** [`report.html`](report.html) — self-contained, open in any browser.
> **Reproducibility:** scripts + raw data in [`survey/`](survey/).

---

## Bottom line (the hypothesis was wrong, in an interesting way)

The premise going in was a US-vs-EU DNSSEC deficit. **The data refutes it.** What's actually
true:

1. **US federal civilian DNSSEC is strong and, if anything, ahead.** 75.4% of all 1,343
   federal `.gov` domains validate to root — *higher* than the international flagship-government
   sample (~61% signed), where many Western governments' main portals are unsigned
   (`service-public.fr`, `admin.ch`, `canada.ca`, `australia.gov.au`, `governo.it`, `gov.ie`).
2. **The real divide is operator culture, not geography.** **DNS registries** sign their zones
   almost everywhere (~92% of those sampled) and hold nearly all the root-anchored email keys.
   Governments and commercial senders mostly don't. This pattern is the same on both sides of
   the Atlantic.
3. **The US-specific weak spot is the military.** Major `.mil` domains — including **CYBERCOM**
   and **DISA, which operates the `.mil` TLD** — are **not DNSSEC-signed**.
4. **Email keys are almost never anchored, anywhere.** Even DNSSEC-signed domains `CNAME` their
   DKIM key into a mail provider's **unsigned** zone (Microsoft 365, SendGrid, Mailchimp; DoD365
   for the military). 76% of federal `.gov` domains that publish DKIM do this. Only ~4% of
   federal civilian domains, and 0% of sampled `.mil`, have a key that validates to root.

**One line:** *governments are decent at signing their zones and bad at anchoring their email
keys; the US military lags its own civilian agencies; and the people who actually do it right
are the DNS registries, everywhere.*

---

## Part 1 — US federal deep-dive (census, n = 1,343)

| Metric | Result |
|---|---|
| Zone DNSSEC-signed (validated to root) | **1,012 / 1,343 = 75.4%** |
| DKIM key found (common selectors) | 316 |
| …outsourced via CNAME to an unsigned SaaS zone | 239 = **76%** of those |
| **DKIM key anchored to root** (direct + validated) | **56 = 4.2%** |

**`.mil` (sample, n = 17): ~47% signed, 0 keys anchored.** Not DNSSEC-signed (each individually
verifiable): `army.mil`, `navy.mil`, `af.mil`, `marines.mil`, `spaceforce.mil`, `cybercom.mil`,
`disa.mil`, `pacom.mil`, `dla.mil`. Signed: `darpa.mil`, `uscg.mil`, `dtic.mil`, `socom.mil`,
`northcom.mil`, `dau.mil`, `health.mil`, `dvidshub.mil`. DoD email runs DoD365 → CNAME into
`*.onmicrosoft.us` (unsigned).

**Who does it right in `.gov`:** the 56 root-anchored domains skew to the **intelligence
community** (`cia.gov`, `ic.gov`, `odci.gov`, `ucia.gov`) and **national labs** (`lbl.gov`,
`ameslab.gov`, `nnss.gov`, `fbilab.gov`), plus a few services (`noaa.gov`, `gps.gov`,
`recreation.gov`, `gsa.gov`). The most sensitive-mail organizations are the ones self-hosting
signed keys.

---

## Part 2 — International landscape (~30 countries)

Each country: its **flagship government domain** + its **national DNS registry**. One domain per
role, so read this as a *landscape of facts about specific domains*, **not** a country ranking
(too thin to rank governments).

### Flagship government domains — DNSSEC-signed?

| Signed | Unsigned |
|---|---|
| 🇩🇪 bund.de · 🇳🇱 government.nl · 🇧🇪 belgium.be · 🇬🇧 gov.uk · 🇸🇪 regeringen.se · 🇳🇴 regjeringen.no · 🇩🇰 borger.dk · 🇪🇪 eesti.ee · 🇨🇿 gov.cz · 🇵🇱 gov.pl · 🇸🇮 gov.si · 🇪🇸 lamoncloa.gob.es · 🇵🇹 gov.pt · 🇬🇷 gov.gr · 🇯🇵 japan.go.jp · 🇳🇿 govt.nz · 🇸🇬 gov.sg · 🇲🇽 gob.mx · 🇧🇷 gov.br | 🇫🇷 service-public.fr · 🇨🇭 admin.ch · 🇨🇦 canada.ca · 🇦🇺 australia.gov.au · 🇫🇮 valtioneuvosto.fi · 🇮🇪 gov.ie · 🇮🇹 governo.it · 🇮🇸 island.is · 🇦🇹 oesterreich.gv.at · 🇰🇷 korea.kr · 🇮🇳 india.gov.in · 🇿🇦 gov.za |

**~19/31 ≈ 61% signed** — *below* the US federal census (75%). Western Europe is split ~50/50;
Central/Eastern Europe (CZ, EE, PL, SI) is the strongest cluster in this sample.

### National DNS registries — the real adopters

**~22/24 ≈ 92% signed.** Registries sign their own zones almost universally (DENIC, AFNIC,
SIDN, Nominet, CIRA, .cz/.it/.ch/.pt/.no/.se/.sg/.jp …). The DNS-operator community practices
what it standardizes — regardless of country.

### Email keys that actually validate to root (the rare set)

`nic.ch` · `nic.cz` · `denic.de` · `afnic.fr` · `nic.it` · `dns.pt` · `traficom.fi` ·
`internetnz.nz` — **registries** — plus two **governments**: 🇩🇰 `borger.dk`, 🇪🇸 `lamoncloa.gob.es`.
Everyone else CNAMEs DKIM into an unsigned provider zone. ~10 of 56 international domains
(~18%, mostly registries) anchor their key — the same concentration seen in the US (IC + labs).

---

## Reliability — and three traps caught before publishing

- **Validation is real.** `delv` from the root anchor; controls pass (a known-good signed domain
  validates; deliberately-broken `dnssec-failed.org` is rejected).
- **Spot-check clean.** Re-validating 15 random "unsigned" `.gov` domains serially found **0**
  parallel-load timeout artifacts; 5/5 "signed" reconfirmed.
- **Three traps fixed, each of which would have *over*-reported success:** (1) a non-validating
  test resolver (the AD flag was useless → switched to `delv`); (2) `delv` prints two verdicts
  for a CNAME chain (`fully validated` for the signed pointer, `unsigned answer` for the key) —
  a naive grep passed every outsourced key; (3) parallel-load false positives → **only direct,
  fully-validated keys count as anchored.**
- **Calibration note.** The 75.4% federal figure is ~double the last published academic number
  (~38% in Sept 2023). Most likely real, mandate-driven growth — but treat it as a *June-2026
  snapshot by this method*; NIST's per-domain monitor is the authoritative cross-reference. The
  *structural* findings do not depend on the absolute number.
- **Limits.** International rows are **one domain per role** — per-domain facts, not country
  rankings. DKIM detection used ~10 guessed selectors (no mail corpus), so DKIM presence is
  undercounted in both directions equally. Single snapshot.

---

## Why it matters (and the 0pon tie-in)

A zero-knowledge DNSSEC proof (0nce **v2-B**) lets a verifier confirm an email key is
authentically published — **but only if the key is anchored to root in the first place.** This
census quantifies how rare that precondition is (~4% US federal civilian, ~0% military, ~18% of
sampled international infra) and yields concrete validating test vectors (`gsa.gov`, `cia.gov`,
`noaa.gov`, `denic.de`, `afnic.fr`). It also names a concrete remediation ask: **publish your
DKIM key as a signed record in your own DNSSEC zone, not a CNAME into an unsigned tenant.**

## To make it fully rigorous

- Per-country **government domain censuses** (where lists exist) instead of one flagship each.
- Real **selector discovery** (mail-corpus / provider patterns) to remove the DKIM undercount.
- Trend tracking — DoD is mid-migration to DoD365; the `.mil` numbers will move.

---

*Sources: domain list — CISA/GSA `dotgov-data` (federal `.gov`). Validation — `delv` (ISC BIND),
IANA root trust anchor. 2023 baseline — Dark Reading / measurement report. Authoritative monitor —
NIST USGv6/DNSSEC. 0pon DNS security census, June 2026.*
