# Changelog

All notable changes to SentryAI are documented here. Versioning is semantic.

## [1.1.1] - 2026-06-02
### Added
- URL dedupe by registrable domain (one reputation lookup per host; siblings
  reuse the verdict and are not re-counted).
- `--max-url-lookups N` budget cap on distinct-domain URL lookups (default 15
  under `--live`) to protect rate-limited API quotas.
- Optional `ApiEnricher(request_interval=...)` outbound throttle.
### Fixed
- Hostless/malformed URLs no longer trigger a reputation lookup.
- Negative `--max-url-lookups` is treated as unlimited.
- Removed dead `_stub_ioc_analysis`.

## [1.1.0] - 2026-06-02
### Added
- Gmail adapter (`gmail_adapter.py`) mapping `get_thread` payloads to the input schema.
- Live API enrichment (`api_enrichment.py`): AbuseIPDB, GreyNoise, VirusTotal v3, RDAP.
- `--live` flag and `.env` support (`config.py`); keys read from environment.
- `--trust-missing-auth` so sources without `Authentication-Results` (e.g. Gmail)
  aren't auto-flagged; explicit fail/none results are still scored.

## [1.0.1] - 2026-06-01
### Fixed
- Lookalike-domain detection uses the registrable domain (no longer flags brand
  subdomains like `accounts.google.com`).
- Base64-evasion false positives tightened (data-URI marker / plain-text blobs only).
- Unified URL/domain/email parsing in `textutils.py` (Stage 2 / Stage 3 parity).
- IP validation via stdlib `ipaddress`; body-size guard; `low` confidence on
  degraded enrichment; bounded lure regex.

## [1.0.0] - 2026-06-01
### Added
- Initial six-stage pipeline: header auth, content signals, IOC extraction +
  enrichment, MITRE ATT&CK/ATLAS mapping, scoring, JSON verdict.
- Prompt-injection defense; offline `StubEnricher`; CLI; test suite.
