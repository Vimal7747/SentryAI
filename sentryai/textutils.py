"""Shared text / domain extraction utilities.

Single source of truth for URL, domain, and email-address parsing so that
every stage extracts the *same* values from the same input (previously each
stage carried its own near-duplicate regex, which could diverge).

All inputs here are UNTRUSTED email data — these helpers only parse strings,
they never fetch, resolve, or execute anything.
"""

from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import urlparse

# Single canonical URL pattern used by every stage. Stops at whitespace,
# quotes, angle brackets, and common trailing/closing punctuation.
URL_RE = re.compile(r"https?://[^\s\"'<>\])}]+", re.IGNORECASE)

_ANGLE_RE = re.compile(r"<([^>]+)>")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# Common multi-label public suffixes, so registrable_domain keeps the right
# number of labels (e.g. example.co.uk, not co.uk). Not exhaustive — a full
# Public Suffix List would be heavier than this stdlib-only project warrants.
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "gov.au",
    "com.br", "com.cn", "com.mx", "com.sg", "com.tr",
    "co.jp", "co.nz", "co.za", "co.in", "co.kr",
}


def domain_from_url(url: str) -> str:
    """Return the lowercase host of a URL (no port, no userinfo)."""
    try:
        host = urlparse(url).hostname or ""
    except Exception:  # noqa: BLE001 — never let a malformed URL crash parsing
        host = ""
    return host.strip().lower()


def domain_from_email(addr: Optional[str]) -> str:
    """Return the lowercase domain from an address or 'Name <a@b.com>' string."""
    if not addr:
        return ""
    addr = addr.strip()
    m = _ANGLE_RE.search(addr)
    if m:
        addr = m.group(1).strip()
    if "@" in addr:
        return addr.split("@", 1)[1].strip().lower().split(":")[0]
    return ""


def email_from_field(addr: Optional[str]) -> str:
    """Return a validated bare email address from a header field, else ''."""
    if not addr:
        return ""
    addr = addr.strip()
    m = _ANGLE_RE.search(addr)
    candidate = m.group(1).strip() if m else addr
    return candidate.lower() if EMAIL_RE.fullmatch(candidate) else ""


def extract_urls(texts: List[str], seed: Optional[List[str]] = None) -> List[str]:
    """Collect URLs from *seed* (kept first, in order) then from *texts*.

    De-duplicated, insertion-order stable.
    """
    seen = set()
    out: List[str] = []
    for url in (seed or []):
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    for text in texts:
        if not text:
            continue
        for m in URL_RE.finditer(text):
            url = m.group(0)
            if url not in seen:
                seen.add(url)
                out.append(url)
    return out


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain (eTLD+1) for a host.

    Examples:
        www.paypal.com      -> paypal.com
        accounts.google.com -> google.com
        paypal.evil.com     -> evil.com
        example.co.uk       -> example.co.uk
    """
    host = (host or "").strip().lower().split(":")[0].strip(".")
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two
