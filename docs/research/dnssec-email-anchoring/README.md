# Email trust-anchoring across governments — a DNS census

**Question.** For government and DNS-infrastructure domains, is the zone DNSSEC-signed and
validated to the DNS root, and — the part almost nobody checks — does the **DKIM
email-signing key** itself validate to root, or does it sit in an unsigned zone a
DNS-spoofing adversary could swap?

**Scope.** A **full census of all 1,343 US federal `.gov` domains** (CISA/GSA official
list), and an **international landscape** of ~31
countries (each country's flagship government domain, plus the national DNS registry for the 25
where one was sampled — 6 are government-only). Validation is real:
`delv`, from the IANA root trust anchor, independent of any resolver. Snapshot: June 2026.

> **HTML version:** [`report.html`](report.html) — self-contained, open in any browser.
> **Reproducibility:** scripts + raw data in [`survey/`](survey/).

---

## Bottom line (the hypothesis was wrong, in an interesting way)

The premise going in was a US-vs-EU DNSSEC deficit. **The data refutes it.** What's actually
true:

1. **US federal civilian DNSSEC is strong and, if anything, ahead.** 76% of all 1,343
   federal `.gov` domains validate to root — *higher* than the international flagship-government
   sample (~61% signed), where many Western governments' main portals are unsigned
   (`service-public.fr`, `admin.ch`, `canada.ca`, `australia.gov.au`, `governo.it`, `gov.ie`).
2. **The real divide is operator culture, not geography.** **DNS registries** sign their zones
   almost everywhere (~92% of those sampled) and hold nearly all the root-anchored email keys.
   Governments and commercial senders mostly don't. This pattern is the same on both sides of
   the Atlantic.
3. **Email keys are almost never anchored, anywhere.** Even DNSSEC-signed domains `CNAME` their
   DKIM key into a mail provider's **unsigned** zone (Microsoft 365, SendGrid, Mailchimp). 76% of
   federal `.gov` domains that publish DKIM do this; only ~4% have a key that validates to root.

**One line:** *governments are decent at signing their zones and bad at anchoring their email
keys; and the people who actually do it right
are the DNS registries, everywhere.*

---

## Part 1 — US federal deep-dive (census, n = 1,343)

| Metric | Result |
|---|---|
| Zone DNSSEC — **validates to root** | **1,019 / 1,343 = 76%** |
| &nbsp;&nbsp;— deployed but **broken** (DS published, signatures fail) | 108 = 8% |
| &nbsp;&nbsp;— unsigned (no DNSSEC) | 216 = 16% |
| DKIM key found (common selectors) | 316 |
| …outsourced via CNAME to an unsigned SaaS zone | 239 = **76%** of those |
| **DKIM key anchored to root** (direct + validated) | **56 = 4.2%** |

Beyond the 76% that validate, **8% (108 domains) have DNSSEC deployed but broken** — a DS record
published while the zone's own signatures fail to validate, which protects nothing and can make the
domain unreachable for validating resolvers. The validating rate has roughly doubled since 2023 (~36%);
the federal mandate is working, unevenly.

**Who does it right in `.gov`:** the 56 root-anchored domains skew to the **intelligence
community** (`cia.gov`, `ic.gov`, `odci.gov`, `ucia.gov`) and **national labs** (`lbl.gov`,
`ameslab.gov`, `nnss.gov`, `fbilab.gov`), plus a few services (`noaa.gov`, `gps.gov`,
`recreation.gov`, `gsa.gov`). The most sensitive-mail organizations are the ones self-hosting
signed keys.

---

## Part 2 — International landscape (~31 countries)

Per country: its **flagship government domain**, plus its **national DNS registry** where one was
sampled (25 of ~31 countries; the rest are government-only). One domain per role — so read this as
a *landscape of facts about specific domains*, **not** a country ranking (too thin to rank governments).

### Flagship government domains — DNSSEC-signed?

| Signed | Unsigned |
|---|---|
| 🇩🇪 bund.de · 🇳🇱 government.nl · 🇧🇪 belgium.be · 🇬🇧 gov.uk · 🇸🇪 regeringen.se · 🇳🇴 regjeringen.no · 🇩🇰 borger.dk · 🇪🇪 eesti.ee · 🇨🇿 gov.cz · 🇵🇱 gov.pl · 🇸🇮 gov.si · 🇪🇸 lamoncloa.gob.es · 🇵🇹 gov.pt · 🇬🇷 gov.gr · 🇯🇵 japan.go.jp · 🇳🇿 govt.nz · 🇸🇬 gov.sg · 🇲🇽 gob.mx · 🇧🇷 gov.br | 🇫🇷 service-public.fr · 🇨🇭 admin.ch · 🇨🇦 canada.ca · 🇦🇺 australia.gov.au · 🇫🇮 valtioneuvosto.fi · 🇮🇪 gov.ie · 🇮🇹 governo.it · 🇮🇸 island.is · 🇦🇹 oesterreich.gv.at · 🇰🇷 korea.kr · 🇮🇳 india.gov.in · 🇿🇦 gov.za |

**~19/31 ≈ 61% signed** — *below* the US federal census (76%). Western Europe is split ~50/50;
Central/Eastern Europe (CZ, EE, PL, SI) is the strongest cluster in this sample.

### National DNS registries — the real adopters

**23/25 ≈ 92% signed.** Registries sign their own zones almost universally (DENIC, AFNIC,
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
- **Calibration note.** The 76% validating rate was re-confirmed three ways — controls, an
  independent census of DS records in the `.gov` parent, and serial re-validation of every domain
  whose two signals disagreed (which resolved a small parallel-run undercount: 7 false negatives,
  while the other 108 DS-having "unsigned" domains are genuinely **broken DNSSEC**). It is ~2× the
  2023 measurement (~36%), a real mandate-driven surge. NIST's monitor is the authoritative reference.
- **Limits.** International coverage is uneven — one flagship government domain per country, and a
  national registry for 25 of ~31 (6 government-only). These are **per-domain facts, not country
  rankings.** DKIM detection used ~10 guessed selectors (no mail corpus), so DKIM presence is
  undercounted in both directions equally. Single snapshot.

---

## What this means — trust is not a control

The pattern is identical across the federal estate and the international sample: organizations have outsourced the
*operation* of email and DNS without preserving the ability to *verify* it. The signed zone protects the
front door; the key that authenticates the mail sits, unverifiable, in a vendor's unsigned zone. Each
arrangement is a *trust-me*. None of it is negligence — it is the rational result of cloud-first,
shared-services IT.

But a system that has deliberately stopped *owning* its infrastructure — cloud-first, *zero trust* by
policy — is one where *trust-me* is precisely what is meant to disappear. You cannot establish trust by
owning what you no longer own; the only path left is to **verify**. **Prove it; don't trust it.** The
immediate fix is unglamorous (publish your DKIM key as a signed record in your own DNSSEC zone, not a
CNAME into an unsigned tenant); the general one is turning the trust-me assertions that govern
compliance, supply chains, and identity into proofs anyone can check. The gap here is one instance of a
larger question: *in a system that runs on outsourced trust, what else is asserted that no one can verify?*

**0pon** builds verifiable attestation — the means to *prove* a security or compliance claim, not assert
it (the 0nce / DNSSEC-in-ZK work is one arrow). Validating test vectors fall out of this census for free
(`gsa.gov`, `cia.gov`, `denic.de`, `afnic.fr`).


## To make it fully rigorous

- Per-country **government domain censuses** (where lists exist) instead of one flagship each.
- Real **selector discovery** (mail-corpus / provider patterns) to remove the DKIM undercount.

---

*Sources: domain list — CISA/GSA `dotgov-data` (federal `.gov`). Validation — `delv` (ISC BIND),
IANA root trust anchor. 2023 baseline — Dark Reading / measurement report. Authoritative monitor —
NIST USGv6/DNSSEC. 0pon DNS security census, June 2026.*
