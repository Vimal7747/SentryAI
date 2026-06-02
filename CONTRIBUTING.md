# Contributing to SentryAI

Thanks for your interest! SentryAI is a defensive security tool — contributions
should preserve its safety posture: email content is untrusted data and is never
executed, and raw body text must never leak into a verdict.

## Development
- Python 3.9+, standard library only (no runtime dependencies).
- Run the tests before sending a change:
  ```bash
  python -m unittest discover -s tests -v
  ```
- Add a regression test for any bug fix or detection change — pin both a true
  positive and a legitimate-traffic negative where relevant.

## Secrets
- Never commit API keys. Use environment variables or a local, gitignored `.env`
  (see `.env.example`). The free-tier keys for VirusTotal/AbuseIPDB are personal.

## Style
- Keep detection logic content-free in descriptions (summarise the pattern,
  never echo attacker text).
- Prefer the shared `textutils` helpers over per-module parsing.
