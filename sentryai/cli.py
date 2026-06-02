"""CLI entry point for SentryAI.

Usage
=====
Read from a file::

    python -m sentryai email.json
    python -m sentryai email.json --pretty
    python -m sentryai email.json --compact
    python -m sentryai email.json --intel intel_cache.json

Read from stdin::

    cat email.json | python -m sentryai
    cat emails.json | python -m sentryai --compact

Input may be a single email JSON object or a JSON array of email objects
(batch mode). Output is JSON only -- no preamble, no trailing text.

Exit codes
==========
  0 -- success (output written to stdout).
  1 -- input/parse error.
  2 -- pipeline error (should not happen in normal operation; check stderr).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, List, Union


def _read_input(file_path):
    """Read JSON from a file path or from stdin. Exits(1) on failure."""
    try:
        if file_path:
            with open(file_path, encoding="utf-8") as fh:
                raw = fh.read()
        else:
            raw = sys.stdin.read()
    except OSError as exc:
        print(f"sentryai: error reading input: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"sentryai: invalid JSON input: {exc}", file=sys.stderr)
        sys.exit(1)


def _make_enricher(intel_path):
    """Build an enricher.

    With ``--intel FILE`` (a cache of reputation results gathered out-of-band,
    e.g. by a browser-automation agent that visited abuseipdb.com /
    virustotal.com), use ``PrefetchedEnricher`` backed by ``StubEnricher`` for
    any IOC the cache does not cover. Otherwise return None so the pipeline
    uses its default offline ``StubEnricher``.
    """
    from sentryai import enrichment as enr

    if not intel_path:
        return None

    try:
        with open(intel_path, encoding="utf-8") as fh:
            cache = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"sentryai: could not read --intel cache: {exc}", file=sys.stderr)
        sys.exit(1)

    return enr.PrefetchedEnricher(cache, fallback=enr.StubEnricher())


def _run(data, intel_path=None, live=False, trust_missing_auth=False, max_url_lookups=None):
    """Dispatch to the pipeline (single or batch) and return verdict dict(s)."""
    try:
        from sentryai.pipeline import analyze, analyze_batch
    except ImportError as exc:
        print(f"sentryai: pipeline import error: {exc}", file=sys.stderr)
        sys.exit(2)

    if intel_path:
        enricher = _make_enricher(intel_path)
    elif live:
        from sentryai.api_enrichment import ApiEnricher
        enricher = ApiEnricher()
        if max_url_lookups is None:
            max_url_lookups = 15  # sane default to protect free-tier budgets
    else:
        enricher = None

    # A negative budget is meaningless; treat it as "unlimited".
    if max_url_lookups is not None and max_url_lookups < 0:
        max_url_lookups = None

    try:
        if isinstance(data, list):
            return analyze_batch(data, enricher=enricher,
                                 trust_missing_auth=trust_missing_auth,
                                 max_url_lookups=max_url_lookups)
        return analyze(data, enricher=enricher,
                       trust_missing_auth=trust_missing_auth,
                       max_url_lookups=max_url_lookups)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"sentryai: pipeline error: {exc}", file=sys.stderr)
        sys.exit(2)


def main(argv=None):
    """Parse arguments, run the pipeline, and write JSON to stdout."""
    parser = argparse.ArgumentParser(
        prog="sentryai",
        description=(
            "SentryAI -- phishing email analysis pipeline. "
            "Reads email JSON from FILE or stdin; writes verdict JSON to stdout."
        ),
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        metavar="FILE",
        help="Path to email JSON file. Omit to read from stdin.",
    )
    parser.add_argument(
        "--intel",
        metavar="CACHE.json",
        default=None,
        help=(
            "Path to a prefetched threat-intel cache (JSON) gathered "
            "out-of-band, e.g. by browser automation against abuseipdb.com / "
            "virustotal.com. Buckets: abuseipdb, greynoise, virustotal_url, "
            "virustotal_hash, whois. Missing IOCs fall back to offline stub."
        ),
    )

    parser.add_argument(
        "--live",
        action="store_true",
        default=False,
        help=(
            "Use live threat-intel APIs (AbuseIPDB / GreyNoise / VirusTotal / "
            "RDAP) via the ApiEnricher. Reads keys from VIRUSTOTAL_API_KEY and "
            "ABUSEIPDB_API_KEY (GREYNOISE_API_KEY optional). Ignored if --intel "
            "is given."
        ),
    )

    parser.add_argument(
        "--max-url-lookups",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Cap distinct-domain URL reputation lookups (protects rate-limited "
            "API budgets). URLs are deduped by registrable domain first. "
            "Defaults to 15 when --live is set, unlimited otherwise."
        ),
    )
    parser.add_argument(
        "--trust-missing-auth",
        action="store_true",
        default=False,
        help=(
            "Treat ABSENT SPF/DKIM/DMARC headers as neutral instead of failing. "
            "Use for sources that do not expose Authentication-Results (e.g. the "
            "Gmail connector). Explicit fail/none/neutral results are still scored."
        ),
    )

    fmt_group = parser.add_mutually_exclusive_group()
    fmt_group.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output with indentation (default).",
    )
    fmt_group.add_argument(
        "--compact",
        action="store_true",
        default=False,
        help="Emit compact (single-line) JSON output.",
    )

    args = parser.parse_args(argv)

    # Load a local .env (gitignored) so --live can read API keys.
    from sentryai.config import load_dotenv
    load_dotenv()

    indent = None if args.compact else 2

    data = _read_input(args.input_file)
    result = _run(data, intel_path=args.intel, live=args.live,
                  trust_missing_auth=args.trust_missing_auth,
                  max_url_lookups=args.max_url_lookups)

    print(json.dumps(result, indent=indent, default=str))
    sys.exit(0)
