# Deploy Checklist: SentryAI v1.0

**Date:** 2026-06-01 | **Deployer:** Vimal
**Ship method:** Git repo / folder hand-off · **Path:** staging → prod · **Prod intel:** live browser automation

> Status: awaiting deploy permission. This is the pre-flight plan — do not ship until sign-off.

---

## Pre-Deploy

- [ ] All 22 tests passing locally (`python -m unittest discover -s tests -v`) — no CI connected, so run manually and paste the summary into the release notes
- [ ] `python -m sentryai examples/sample_email.json` returns the expected PHISHING / high / score ≥ 85 verdict
- [ ] Code reviewed and approved (self-review or peer) — focus areas: scoring math, prompt-injection regexes, no email body text leaking into verdicts
- [ ] No known critical bugs in this release
- [ ] `git status` clean; scratch/throwaway files excluded; `.gitignore` covers `__pycache__/`, `*.pyc`, local intel caches with real IOCs
- [ ] No secrets, API keys, or real customer email content committed (browser-automation path needs no keys — confirm none crept in)
- [ ] README and DEPLOY_CHECKLIST included in the repo; version tagged (`v1.0.0`)
- [ ] Python version pinned/documented (3.9+); confirm target hosts meet it
- [ ] N/A — no database migrations
- [ ] N/A — no feature flags
- [ ] Rollback plan documented (see below)
- [ ] Reviewer/approver for security verdicts identified (who owns false-positive disputes)

## Browser-automation intel — readiness (prod-critical)

This is the most fragile part of the system; the offline stub masks failures, so verify the live path explicitly.

- [ ] Browser driver/automation available and authenticated on the staging host
- [ ] Live lookup verified end-to-end: real IP checked on abuseipdb.com, real URL on virustotal.com, results parsed into the `--intel` cache shape
- [ ] Parser tolerant of layout/markup changes on both sites (graceful "unknown" + note, never a crash)
- [ ] Rate-limit / throttling behavior confirmed; backoff in place so a burst of emails doesn't get the driver blocked
- [ ] Defined fallback when a lookup fails twice: IOC marked `unknown`, noted in `processing_notes`, pipeline continues (per spec rule 5) — confirm it does NOT silently fall back to clean
- [ ] Decide whether stub fallback is acceptable in prod or should be disabled (a stub "clean" on malicious infra is a dangerous false negative)
- [ ] Timeout per lookup set so one slow page can't stall the queue

## Deploy

- [ ] Deploy to staging and verify imports + CLI run on a clean checkout (fresh clone, no `__pycache__`)
- [ ] Run smoke tests on staging: single email, stdin, batch array, `--intel` cache, and a known prompt-injection email (must classify ≥ SUSPICIOUS, never BENIGN)
- [ ] Confirm verdict JSON validates against the strict output schema
- [ ] Promote to production
- [ ] Process a small known-good + known-bad sample set in prod; spot-check verdicts for 15 min
- [ ] Verify key flows: benign email → BENIGN, spec phishing example → PHISHING, injection → flagged

## Post-Deploy

- [ ] Confirm processing succeeds on real inbound volume; no unhandled exceptions in logs
- [ ] Sample a handful of live verdicts for accuracy (false-positive / false-negative spot check)
- [ ] Confirm no email body content appears verbatim in stored verdicts (PII/leakage check)
- [ ] Update release notes / changelog (`v1.0.0`: pipeline, browser-intel path, 22 tests)
- [ ] Notify stakeholders that SentryAI is live
- [ ] Close related tickets

## Rollback Triggers

- Live intel lookups fail or return malformed data for **> 10%** of IOCs (verdict quality compromised)
- Any email body content leaks verbatim into a verdict (immediate rollback — data exposure)
- A prompt-injection email is ever classified BENIGN (security control broken)
- Unhandled exception rate **> 1%** of processed emails
- Browser driver blocked/captcha-walled by abuseipdb or virustotal (intel goes dark)
- Per-email processing latency exceeds your throughput budget (define target, e.g. **> 30s/email**)

**Rollback action:** revert to the previous git tag (or pull the service); since there is no DB or persistent state, rollback is a clean checkout of the prior version. If only the intel path is broken, optionally fall back to `--intel` with cached results or the offline stub as a stopgap **only if** an analyst is reviewing verdicts manually.

---

### Open items to confirm before sign-off
1. Throughput target (emails/min) and acceptable per-email latency.
2. Whether the offline stub is permitted as a prod fallback or must be hard-disabled.
3. Who owns verdict disputes / false-positive escalation.
4. Data retention: how long verdicts (and any IOCs) are stored, and where.
