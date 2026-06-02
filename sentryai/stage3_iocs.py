"""Stage 3 — IOC extraction and threat-intelligence enrichment.

Extracts Indicators of Compromise (IPs, URLs, domains, file hashes, email
addresses) from a parsed EmailInput and enriches each one via the provided
Enricher backend.  All lookups are wrapped in retry logic: one automatic
retry on exception, then a note is recorded and processing continues so that
a single bad lookup never aborts the pipeline.

All email content is UNTRUSTED DATA.  Regex patterns are applied to body
text only for *extraction* purposes; extracted strings are never executed or
evaluated.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from sentryai.enrichment import Enricher, MALICIOUS, SUSPICIOUS, CLEAN, UNKNOWN
from sentryai.models import EmailInput, IOCResult
from sentryai.textutils import (
    domain_from_url as _shared_domain_from_url,
    domain_from_email as _shared_domain_from_email,
    email_from_field as _shared_email_from_field,
    extract_urls as _shared_extract_urls,
    registrable_domain as _registrable_domain,
)


# ---------------------------------------------------------------------------
# Compiled patterns (anchored/bounded where possible to avoid ReDoS)
# ---------------------------------------------------------------------------

# IPv4: four decimal octets, each 0-255.
_IPV4_RE = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d))\b"
)

# IPv6: simplified — matches the common full and compressed forms embedded in
# text.  False positives are rejected by _looks_like_ipv6.
_IPV6_RE = re.compile(
    r"\b("
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"          # full
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"                        # trailing ::
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"                        # leading ::
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"       # one :: middle
    r"|::(?:[fF]{4}(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|\d)\d?)\.){3}"
    r"(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|\d)\d?)"             # IPv4-mapped
    r")\b"
)

# RFC-5321-ish email address: local@domain.tld
_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

# A SHA-256 hash is exactly 64 lower/upper hex characters.
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_iocs(email: EmailInput) -> Dict[str, List[str]]:
    """Extract and de-duplicate IOCs from a parsed email.

    Reads structured header fields and unstructured body text/HTML.  All
    values are de-duplicated in a stable, insertion-order-preserving manner.

    Returns a dict with keys: "ips", "urls", "domains", "hashes", "emails".
    Values are lists of strings, each unique, in discovery order.
    """
    ips: List[str] = []
    urls: List[str] = []
    domains: List[str] = []
    hashes: List[str] = []
    emails: List[str] = []

    # ------------------------------------------------------------------ IPs
    if email.headers.x_originating_ip:
        ip = email.headers.x_originating_ip.strip()
        if ip and _is_valid_ip(ip):
            _append_unique(ips, ip)

    for corpus in _bodies(email):
        for m in _IPV4_RE.finditer(corpus):
            ip = m.group(1)
            if _validate_ipv4(ip):
                _append_unique(ips, ip)
        for m in _IPV6_RE.finditer(corpus):
            candidate = m.group(1)
            if _is_valid_ip(candidate):
                _append_unique(ips, candidate)

    # ----------------------------------------------------------------- URLs
    # Use the shared extractor so Stage 2 and Stage 3 see identical URLs.
    urls = _shared_extract_urls(_bodies(email), seed=email.urls_extracted)

    # --------------------------------------------------------------- Domains
    # Derive from URLs.
    for url in urls:
        d = _domain_from_url(url)
        if d and not _is_bare_ip(d):
            _append_unique(domains, d)

    # Derive from From and Reply-To addresses.
    for addr in (email.headers.from_, email.headers.reply_to):
        if addr:
            d = _domain_from_email_address(addr)
            if d and not _is_bare_ip(d):
                _append_unique(domains, d)

    # --------------------------------------------------------------- Hashes
    for att in (email.attachments or []):
        if att.sha256 and _SHA256_RE.match(att.sha256):
            _append_unique(hashes, att.sha256.lower())

    # --------------------------------------------------------------- Emails
    for addr in (email.headers.from_, email.headers.reply_to):
        if addr:
            extracted = _email_from_address_field(addr)
            if extracted:
                _append_unique(emails, extracted.lower())

    for corpus in _bodies(email):
        for m in _EMAIL_RE.finditer(corpus):
            _append_unique(emails, m.group(0).lower())

    return {
        "ips": ips,
        "urls": urls,
        "domains": domains,
        "hashes": hashes,
        "emails": emails,
    }


def enrich_iocs(
    iocs: Dict[str, List[str]],
    enricher: Enricher,
    max_url_lookups: Optional[int] = None,
) -> Tuple[List[IOCResult], List[str]]:
    """Enrich extracted IOCs via the given Enricher backend.

    Each lookup is attempted once.  On exception the call is retried once
    more.  If the retry also fails, a note is recorded and enrichment
    continues with whatever data (if any) was accumulated.

    Returns:
        results: One IOCResult per IOC, in ioc-type order (ips, urls,
                 domains, hashes, emails).
        notes:   Human-readable strings describing any lookup failures.
    """
    results: List[IOCResult] = []
    notes: List[str] = []

    # ------------------------------------------------------------------ IPs
    for ip in iocs.get("ips", []):
        result = _enrich_ip(ip, enricher, notes)
        results.append(result)

    # ----------------------------------------------------------------- URLs
    # Dedupe by registrable domain so a message with dozens of tracking links
    # to the same host costs ONE reputation lookup (and is scored once, not
    # N times). ``max_url_lookups`` caps distinct-domain lookups so a single
    # email cannot blow through a rate-limited API budget (code-review #1/#2).
    domain_cache: Dict[str, IOCResult] = {}
    url_lookups = 0
    for url in iocs.get("urls", []):
        host = _shared_domain_from_url(url)
        if not host:
            # Malformed URL with no resolvable host: record but never look up.
            results.append(IOCResult(
                ioc_type="url", value=url, sources_queried=[],
                verdict=UNKNOWN,
                detail="URL has no resolvable host; no reputation lookup performed.",
                points_contributed=0, raw={}))
            continue
        regdom = _registrable_domain(host) or host
        rep = domain_cache.get(regdom)
        if rep is not None:
            # Sibling URL on an already-checked domain: reuse verdict, 0 points.
            results.append(IOCResult(
                ioc_type="url", value=url, sources_queried=rep.sources_queried,
                verdict=rep.verdict,
                detail=(f"Same registrable domain as {rep.value}; verdict reused "
                        f"and not re-counted."),
                points_contributed=0, raw={}))
            continue
        if max_url_lookups is not None and url_lookups >= max_url_lookups:
            results.append(IOCResult(
                ioc_type="url", value=url, sources_queried=["virustotal"],
                verdict=UNKNOWN,
                detail=(f"URL reputation lookup skipped: exceeded the lookup "
                        f"budget of {max_url_lookups}."),
                points_contributed=0, raw={}))
            notes.append(
                f"URL lookup budget ({max_url_lookups}) reached; {url} not checked.")
            continue
        result = _enrich_url(url, enricher, notes)
        url_lookups += 1
        domain_cache[regdom] = result
        results.append(result)

    # --------------------------------------------------------------- Domains
    for domain in iocs.get("domains", []):
        result = _enrich_domain(domain, enricher, notes)
        results.append(result)

    # --------------------------------------------------------------- Hashes
    for sha256 in iocs.get("hashes", []):
        result = _enrich_hash(sha256, enricher, notes)
        results.append(result)

    # --------------------------------------------------------------- Emails
    for email_addr in iocs.get("emails", []):
        # No external lookup; recorded for completeness only.
        results.append(IOCResult(
            ioc_type="email",
            value=email_addr,
            sources_queried=[],
            verdict=UNKNOWN,
            detail="Email address recorded as IOC; no external lookup performed.",
            points_contributed=0,
            raw={},
        ))

    return results, notes


# ---------------------------------------------------------------------------
# Per-type enrichment helpers
# ---------------------------------------------------------------------------

def _enrich_ip(ip: str, enricher: Enricher, notes: List[str]) -> IOCResult:
    """Enrich a single IP address using AbuseIPDB and GreyNoise."""
    abuse = _safe_call(enricher.abuseipdb_lookup, ip, "abuseipdb_lookup", ip, notes)
    grey  = _safe_call(enricher.greynoise_lookup,  ip, "greynoise_lookup",  ip, notes)

    raw: Dict[str, Any] = {}
    if abuse is not None:
        raw["abuseipdb"] = abuse
    if grey is not None:
        raw["greynoise"] = grey

    verdict = UNKNOWN
    points = 0
    detail_parts: List[str] = []

    if abuse is None and grey is None:
        detail = "Both AbuseIPDB and GreyNoise lookups returned no data."
    else:
        abuse_score: int = (abuse or {}).get("abuse_confidence_score", 0) or 0
        gn_classification: str = ((grey or {}).get("classification") or "").lower()
        gn_noise: bool = bool((grey or {}).get("noise", False))

        if grey is not None:
            detail_parts.append(
                f"GreyNoise classification: {gn_classification or 'unknown'}"
                + (f" ({grey.get('name', '')})" if grey.get("name") else "")
                + "."
            )
        if abuse is not None:
            detail_parts.append(f"AbuseIPDB confidence score: {abuse_score}%.")

        # --- Verdict decision (spec order) ---
        if gn_classification == "malicious" or abuse_score >= 75:
            verdict = MALICIOUS
            points = 40
        elif abuse_score >= 25:
            verdict = SUSPICIOUS
            points = 20
        elif gn_noise and gn_classification != "benign":
            verdict = SUSPICIOUS
            points = 5
        else:
            verdict = CLEAN
            points = 0

        detail = " ".join(detail_parts) if detail_parts else ""

    return IOCResult(
        ioc_type="ip",
        value=ip,
        sources_queried=["abuseipdb", "greynoise"],
        verdict=verdict,
        detail=detail,
        points_contributed=points,
        raw=raw,
    )


def _enrich_url(url: str, enricher: Enricher, notes: List[str]) -> IOCResult:
    """Enrich a single URL using VirusTotal URL scan."""
    vt = _safe_call(enricher.virustotal_url_scan, url, "virustotal_url_scan", url, notes)

    raw: Dict[str, Any] = {}
    if vt is not None:
        raw["virustotal"] = vt

    verdict = UNKNOWN
    points = 0
    detail = ""

    if vt is None:
        detail = "VirusTotal URL scan returned no data."
    else:
        mal: int = vt.get("malicious_votes", 0) or 0
        sus: int = vt.get("suspicious_votes", 0) or 0
        cats: List[str] = vt.get("categories", []) or []
        cat_str = ", ".join(cats) if cats else "none"

        detail = (
            f"VirusTotal: {mal} malicious vote(s), {sus} suspicious vote(s); "
            f"categories: {cat_str}."
        )

        if mal >= 3:
            verdict = MALICIOUS
            points = 45
        elif mal >= 1 or sus >= 3:
            verdict = SUSPICIOUS
            points = 25
        else:
            verdict = CLEAN
            points = 0

    return IOCResult(
        ioc_type="url",
        value=url,
        sources_queried=["virustotal"],
        verdict=verdict,
        detail=detail,
        points_contributed=points,
        raw=raw,
    )


def _enrich_domain(domain: str, enricher: Enricher, notes: List[str]) -> IOCResult:
    """Enrich a single domain using WHOIS (domain age signal)."""
    whois = _safe_call(enricher.whois_lookup, domain, "whois_lookup", domain, notes)

    raw: Dict[str, Any] = {}
    if whois is not None:
        raw["whois"] = whois

    verdict = UNKNOWN
    points = 0
    detail = ""

    if whois is None:
        detail = "WHOIS lookup returned no data."
    else:
        age: Optional[int] = whois.get("age_days")
        registrar: str = whois.get("registrar", "unknown") or "unknown"
        country: str = whois.get("country", "unknown") or "unknown"

        if age is not None and age < 30:
            verdict = SUSPICIOUS
            points = 20
            detail = (
                f"Domain is only {age} day(s) old (registrar: {registrar}, "
                f"country: {country}); recently registered domains are a "
                f"strong phishing indicator."
            )
        else:
            verdict = CLEAN
            points = 0
            age_display = f"{age} day(s)" if age is not None else "unknown"
            detail = (
                f"Domain age: {age_display} (registrar: {registrar}, "
                f"country: {country}); no age-based concerns."
            )

    return IOCResult(
        ioc_type="domain",
        value=domain,
        sources_queried=["whois"],
        verdict=verdict,
        detail=detail,
        points_contributed=points,
        raw=raw,
    )


def _enrich_hash(sha256: str, enricher: Enricher, notes: List[str]) -> IOCResult:
    """Enrich a file hash using VirusTotal hash lookup."""
    vt = _safe_call(enricher.virustotal_hash_lookup, sha256, "virustotal_hash_lookup", sha256, notes)

    raw: Dict[str, Any] = {}
    if vt is not None:
        raw["virustotal"] = vt

    verdict = UNKNOWN
    points = 0
    detail = ""

    if vt is None:
        detail = "VirusTotal hash lookup returned no data."
    else:
        mal: int = vt.get("malicious_votes", 0) or 0
        sus: int = vt.get("suspicious_votes", 0) or 0
        ftype: str = vt.get("file_type", "unknown") or "unknown"

        detail = (
            f"VirusTotal: {mal} malicious vote(s), {sus} suspicious vote(s); "
            f"file type: {ftype}."
        )

        if mal >= 1:
            verdict = MALICIOUS
            points = 60
        elif sus >= 1:
            verdict = SUSPICIOUS
            points = 30
        else:
            verdict = CLEAN
            points = 0

    return IOCResult(
        ioc_type="hash",
        value=sha256,
        sources_queried=["virustotal"],
        verdict=verdict,
        detail=detail,
        points_contributed=points,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Retry-wrapped lookup helper
# ---------------------------------------------------------------------------

def _safe_call(
    fn,
    arg: str,
    tool_name: str,
    ioc_value: str,
    notes: List[str],
) -> Optional[Dict[str, Any]]:
    """Call fn(arg), retrying once on exception.

    Returns the result dict or None.  Appends a human-readable note on
    double failure so the caller can record the gap without crashing.
    """
    try:
        return fn(arg)
    except Exception as first_exc:  # noqa: BLE001
        try:
            return fn(arg)
        except Exception as second_exc:  # noqa: BLE001
            notes.append(
                f"{tool_name}({ioc_value!r}) failed after retry: "
                f"{type(second_exc).__name__}: {second_exc} "
                f"(first error: {type(first_exc).__name__}: {first_exc})"
            )
            return None


# ---------------------------------------------------------------------------
# Extraction utilities
# ---------------------------------------------------------------------------

def _bodies(email: EmailInput) -> List[str]:
    """Return non-empty body texts to search."""
    out = []
    if email.body_text:
        out.append(email.body_text)
    if email.body_html:
        out.append(email.body_html)
    return out


def _append_unique(lst: List[str], value: str) -> None:
    """Append value to lst only if not already present (order-stable dedup)."""
    if value not in lst:
        lst.append(value)


def _is_valid_ip(value: str) -> bool:
    """Return True if value is a valid IPv4 or IPv6 address.

    Uses the stdlib ``ipaddress`` parser rather than the in-text extraction
    regexes (those carry \\b word-boundary anchors for scanning bodies and
    would reject valid addresses such as ``::1``). Code-review #7.
    """
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _validate_ipv4(ip: str) -> bool:
    """Return True if every octet of an IPv4 address is in 0-255."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _is_bare_ip(value: str) -> bool:
    """Return True if value is a raw IPv4 or IPv6 address (not a hostname)."""
    if _IPV4_RE.fullmatch(value):
        return True
    if ":" in value:  # IPv6
        return True
    return False


# Domain / email parsing delegates to the shared textutils module so every
# stage extracts identical values (see code-review finding #3/#5).
def _domain_from_url(url: str) -> str:
    return _shared_domain_from_url(url)


def _domain_from_email_address(address: str) -> str:
    return _shared_domain_from_email(address)


def _email_from_address_field(address: str) -> str:
    return _shared_email_from_field(address)
