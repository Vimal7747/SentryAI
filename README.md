# SentryAI v1.1.1

Agentic phishing-email analyser. It takes an email (as JSON or pulled from
Gmail), runs a six-stage analysis pipeline, enriches indicators of compromise
(IOCs) against live threat-intel services, maps findings to MITRE ATT&CK /
ATLAS techniques, and returns a single structured JSON verdict.

SentryAI is a **defensive** tool. Email content is always treated as untrusted
data — instructions embedded in an email body are never executed, and a
prompt-injection attempt is itself scored as a strong phishing signal.

## Why it's built this way

- **Zero required dependencies.** Pure Python 3.9+ standard library (incl. the
  live API enrichment, which uses `urllib`). No installs, no build step.
- **Pluggable threat intel.** The pipeline never calls the network itself; it
  asks an `Enricher` for reputation data, so the source is swappable: offline
  stub, prefetched cache, or live APIs.
- **Untrusted by construction.** Later stages operate only on structured signal
  labels, never on raw email text, so attacker-controlled content cannot steer
  the analysis or leak into the verdict.

## Architecture

See `docs/architecture_diagram.svg`. The flow:

```
Email source ── Gmail connector (gmail_adapter) ──┐
   or raw JSON / .eml ─────────────────────────────┤
                                                    ▼
Stage 1  Header auth        SPF / DKIM / DMARC / From↔Reply-To mismatch
Stage 2  Content signals    urgency · credential-harvest · impersonation ·
                            evasion · prompt-injection
Stage 3  IOC enrichment ───▶ Enricher ──▶ AbuseIPDB · GreyNoise · VirusTotal · RDAP
Stage 4  MITRE mapping  ◀─── ATT&CK / ATLAS technique store
Stage 5  Scoring            sum risk points → thresholds
Stage 6  Verdict            structured JSON
```

| Stage | Module | Responsibility |
|------|--------|----------------|
| 1 | `stage1_headers.py` | SPF/DKIM/DMARC + From↔Reply-To mismatch; queues originating IP |
| 2 | `stage2_content.py` | Urgency, credential-harvest, impersonation, evasion, prompt-injection |
| 3 | `stage3_iocs.py` | Extracts IPs/URLs/domains/hashes/emails and enriches them via an `Enricher` |
| 4 | `stage4_mitre.py` | Maps signals to ATT&CK / ATLAS techniques from `data/mitre_attack.json` |
| 5 | `stage5_scoring.py` | Sums risk points, applies classification thresholds |
| 6 | `stage6_verdict.py` | Assembles the strict-schema JSON verdict and recommended actions |

Orchestrated by `pipeline.py` (`analyze`, `analyze_batch`). Shared URL/domain/
email parsing lives in `textutils.py`; Gmail mapping in `gmail_adapter.py`;
live API enrichment in `api_enrichment.py`; `.env` loading in `config.py`.

## Usage

```bash
# Offline stub intel (no network, no keys)
python -m sentryai examples/sample_email.json

# Live threat-intel APIs (reads keys from env / .env)
# URLs are deduped by registrable domain; distinct-domain lookups capped at 15.
python -m sentryai examples/sample_email.json --live

# Raise/lower the per-email URL lookup budget
python -m sentryai email.json --live --max-url-lookups 30

# Mail that lacks Authentication-Results (e.g. Gmail) — don't penalise missing auth
python -m sentryai gmail_email.json --live --trust-missing-auth

# Prefetched intel cache (e.g. gathered out-of-band)
python -m sentryai email.json --intel my_intel_cache.json

# stdin, compact, and batch (JSON array) all work
cat emails.json | python -m sentryai --compact
```

Enrichment source precedence: `--intel` > `--live` > offline stub (default).

### Input schema

```json
{
  "email_id": "<uuid>",
  "headers": {
    "from": "...", "reply_to": "...", "subject": "...",
    "received_spf": "pass|fail|neutral|none",
    "dkim_result": "pass|fail|none",
    "dmarc_result": "pass|fail|none",
    "x_originating_ip": "..."
  },
  "body_text": "...", "body_html": "...",
  "attachments": [{"filename": "...", "sha256": "...", "mime_type": "..."}],
  "urls_extracted": ["..."]
}
```

Missing fields are treated as null and noted in `processing_notes`. A missing
`email_id` is auto-assigned a UUID. Bodies over 200,000 characters are
truncated for analysis (and noted) to bound resource use.

## Pulling mail from Gmail

`gmail_adapter.py` maps the Gmail connector's `get_thread` output into the input
schema:

```python
from sentryai.gmail_adapter import gmail_message_to_email_input
from sentryai.pipeline import analyze

verdict = analyze(gmail_message_to_email_input(gmail_message),
                  trust_missing_auth=True)
```

Gmail exposes the body + common headers but **not** the raw
`Authentication-Results` header, so SPF/DKIM/DMARC arrive as absent. Use
`trust_missing_auth=True` (CLI: `--trust-missing-auth`) for Gmail-sourced mail
so legitimate messages aren't auto-flagged for headers the source can't
provide. Explicit `fail`/`none`/`neutral` results are still scored.

## Threat-intel backends (`Enricher`)

- **`StubEnricher`** (default) — offline, deterministic; clean/neutral except a
  small built-in demo table. Runs and tests with no network or keys.
- **`PrefetchedEnricher`** — serves results gathered out-of-band (the `--intel`
  cache); falls back to the stub for IOCs not in the cache.
- **`ApiEnricher`** (`--live`) — live lookups via AbuseIPDB, GreyNoise,
  VirusTotal v3, and RDAP (domain age). Stdlib `urllib`, defensive (any
  network/HTTP error → `unknown` + note, never raises). If any lookup fails,
  overall confidence is downgraded to `low`. Optional `request_interval`
  throttles outbound calls to respect provider rate limits (e.g. 15s ⇒
  VirusTotal's 4/min).

### Rate-limit protection (URL dedupe + lookup budget)

URLs are deduped by **registrable domain** before enrichment, so an email with
dozens of tracking links to the same host costs a single reputation lookup and
is scored once (sibling URLs are still listed as IOCs but inherit the verdict
with 0 points). On top of that, `--max-url-lookups N` caps the number of
distinct-domain URL lookups — defaulting to **15 under `--live`** (unlimited
otherwise). URLs beyond the budget are marked `unknown` with a note, with no
extra API calls. Together these keep a normal marketing email (which can carry
50+ links) comfortably inside the free-tier limits.

### API keys (environment variables)

`ApiEnricher` reads keys from the environment; they are never hard-coded:

| Variable | Service | Free tier |
|----------|---------|-----------|
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 | 500/day, 4/min, non-commercial |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | 1,000 checks/day |
| `GREYNOISE_API_KEY` | GreyNoise (optional) | community tier works keyless |

Provide them via real OS environment variables (recommended) or a local,
gitignored `.env` (see `.env.example`; the CLI auto-loads it). **Do not** keep a
`.env` with real keys in a cloud-synced folder. RDAP/WHOIS needs no key.

```powershell
setx VIRUSTOTAL_API_KEY "..."
setx ABUSEIPDB_API_KEY  "..."
```

## Scoring & classification

| Score | Verdict | Confidence |
|------:|---------|-----------|
| 0–19 | BENIGN | high if <10, else medium |
| 20–44 | SUSPICIOUS | medium |
| 45–59 | PHISHING | medium |
| 60+ | PHISHING | high |

A detected prompt injection raises the effective floor to 50 (never BENIGN).
Scores of 15–24 with no malicious IOC set `human_review_recommended: true`.
Confidence is reported `low` when enrichment was incomplete (reflects data
completeness, not verdict strength).

## Tests

```bash
python -m unittest discover -s tests -v
```

61 tests across six files:

- `test_sentryai.py` — each stage, security module, scoring thresholds, the
  spec example, batch isolation, missing fields, no body-text leakage.
- `test_review_fixes.py` — one regression test per code-review finding.
- `test_gmail_adapter.py` — Gmail→schema mapping (validated against a real
  `get_thread` payload) and end-to-end through the pipeline.
- `test_api_enrichment.py` — `ApiEnricher` field mapping with mocked HTTP
  (offline), incl. 404/missing-key/network-failure handling.
- `test_trust_missing_auth.py` — absent auth neutralised, explicit failures
  still scored, Gmail false-positive fixed, bad mail still caught.
- `test_live_budget.py` — URL dedupe-by-domain (one lookup, scored once) and
  the `--max-url-lookups` budget cap.

## Detection notes (learned the hard way)

- **Lookalike domains** are judged on the registrable domain (eTLD+1), so brand
  subdomains (`accounts.google.com`) aren't flagged — only homoglyphs
  (`paypa1.com`), hyphenated brand tokens (`paypal-verify.com`), and
  brand-as-subdomain on a foreign registrable domain (`paypal.evil.com`).
- **Base64 evasion** requires a real signal (a `;base64,` data-URI marker or a
  word-boundaried blob that actually looks base64 in plain text), not any long
  alphanumeric run.
- **IP validation** uses stdlib `ipaddress`, not the in-text extraction regex.
- **Gmail has no auth headers** → use `--trust-missing-auth` or absent SPF/DKIM/
  DMARC will push legitimate mail to PHISHING.
- **VirusTotal's web GUI is CAPTCHA-walled** → use the API (`--live`), not
  browser scraping.

## Project layout

```
sentry AI/
├── sentryai/
│   ├── models.py          # dataclasses: EmailInput, Verdict, ...
│   ├── security.py        # prompt-injection detection
│   ├── enrichment.py      # Enricher / StubEnricher / PrefetchedEnricher
│   ├── api_enrichment.py  # ApiEnricher (AbuseIPDB/GreyNoise/VirusTotal/RDAP)
│   ├── gmail_adapter.py   # Gmail get_thread -> input schema
│   ├── textutils.py       # shared URL / domain / email parsing
│   ├── config.py          # minimal .env loader
│   ├── stage1_headers.py … stage6_verdict.py
│   ├── pipeline.py        # analyze / analyze_batch
│   ├── cli.py, __main__.py
│   └── data/mitre_attack.json
├── examples/
│   ├── sample_email.json
│   └── intel_cache.template.json
├── tests/                 # 5 test modules, 56 tests
├── docs/architecture_diagram.svg
├── .env.example           # key placeholders (.env is gitignored)
├── .gitignore
├── DEPLOY_CHECKLIST.md
├── requirements.txt
└── README.md
```

## License

MIT — see [LICENSE](LICENSE).

## Status

v1.1.1 — pipeline + Gmail adapter + live API enrichment (with URL dedupe +
lookup budget) + missing-auth handling; all code-review findings resolved;
61/61 tests passing. Not yet deployed (see `DEPLOY_CHECKLIST.md`).
