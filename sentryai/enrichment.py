"""IOC enrichment backends.

The pipeline never talks to the internet directly. It asks an ``Enricher``
for reputation data on each IOC. This indirection lets us swap the data
source without touching pipeline logic:

* ``StubEnricher``      — offline, deterministic defaults so the project runs
                          error-free with zero network/keys. Includes a small
                          built-in reputation table for obviously-bad demo
                          infrastructure used in the spec example.
* ``PrefetchedEnricher``— returns results that were gathered out-of-band
                          (e.g. by a browser-automation agent that visited
                          abuseipdb.com / virustotal.com) and handed back a
                          JSON dict. This is the "browser automation" path:
                          an external driver fills the cache, the pipeline
                          consumes it.

Result dicts follow the shapes documented in the SentryAI tool definitions
(abuseipdb_lookup, greynoise_lookup, virustotal_url_scan,
virustotal_hash_lookup, whois_lookup).
"""

from __future__ import annotations

import abc
from typing import Any, Dict, List, Optional


# Verdict labels returned to the pipeline.
MALICIOUS = "malicious"
SUSPICIOUS = "suspicious"
CLEAN = "clean"
UNKNOWN = "unknown"


class Enricher(abc.ABC):
    """Abstract reputation provider. Subclasses implement the lookups."""

    #: tool names this backend reports as "called" (for metadata)
    name = "enricher"

    def __init__(self) -> None:
        self.tools_called: List[str] = []

    def _record(self, tool: str) -> None:
        if tool not in self.tools_called:
            self.tools_called.append(tool)

    @abc.abstractmethod
    def abuseipdb_lookup(self, ip: str) -> Optional[Dict[str, Any]]: ...

    @abc.abstractmethod
    def greynoise_lookup(self, ip: str) -> Optional[Dict[str, Any]]: ...

    @abc.abstractmethod
    def virustotal_url_scan(self, url: str) -> Optional[Dict[str, Any]]: ...

    @abc.abstractmethod
    def virustotal_hash_lookup(self, sha256: str) -> Optional[Dict[str, Any]]: ...

    @abc.abstractmethod
    def whois_lookup(self, domain: str) -> Optional[Dict[str, Any]]: ...


class StubEnricher(Enricher):
    """Offline backend. Returns unknown defaults unless an IOC appears
    in the small built-in demo reputation table.

    This guarantees the pipeline completes without network access or API
    keys. It is NOT a substitute for real intel in production; it exists so
    the project is runnable and testable out of the box.
    """

    name = "stub"

    # Minimal demo reputation table keyed by IOC value. Used for the spec
    # example and tests. Everything not listed returns None (unknown).
    KNOWN_BAD_IPS = {
        "185.220.101.45": {
            "abuse_confidence_score": 100,
            "usage_type": "Data Center/Web Hosting/Transit",
            "isp": "Tor Exit Node Operator",
            "domain": "torproject.org",
            "total_reports": 1200,
            "greynoise_classification": "malicious",
            "greynoise_name": "Tor Exit Scanner",
        },
    }
    KNOWN_BAD_URLS = {
        "http://paypa1-verify.com/login": {
            "malicious_votes": 14,
            "suspicious_votes": 3,
            "categories": ["phishing"],
            "final_url": "http://paypa1-verify.com/login",
        },
    }
    KNOWN_BAD_HASHES: Dict[str, Dict[str, Any]] = {}
    YOUNG_DOMAINS = {
        "paypa1-verify.com": {"age_days": 4, "registrar": "NameCheap", "country": "RU"},
    }

    def abuseipdb_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        self._record("abuseipdb_lookup")
        bad = self.KNOWN_BAD_IPS.get(ip)
        if bad:
            return {
                "ip": ip,
                "abuse_confidence_score": bad["abuse_confidence_score"],
                "is_public": True,
                "usage_type": bad["usage_type"],
                "isp": bad["isp"],
                "domain": bad["domain"],
                "total_reports": bad["total_reports"],
            }
        return None

    def greynoise_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        self._record("greynoise_lookup")
        bad = self.KNOWN_BAD_IPS.get(ip)
        if bad:
            return {
                "ip": ip,
                "noise": True,
                "riot": False,
                "classification": bad["greynoise_classification"],
                "name": bad["greynoise_name"],
                "last_seen": "recent",
            }
        return None

    def virustotal_url_scan(self, url: str) -> Optional[Dict[str, Any]]:
        self._record("virustotal_url_scan")
        bad = self.KNOWN_BAD_URLS.get(url)
        if bad:
            return {
                "url": url,
                "malicious_votes": bad["malicious_votes"],
                "suspicious_votes": bad["suspicious_votes"],
                "harmless_votes": 0,
                "categories": bad["categories"],
                "final_url": bad["final_url"],
            }
        return None

    def virustotal_hash_lookup(self, sha256: str) -> Optional[Dict[str, Any]]:
        self._record("virustotal_hash_lookup")
        bad = self.KNOWN_BAD_HASHES.get(sha256)
        if bad:
            return {
                "sha256": sha256,
                "malicious_votes": bad["malicious_votes"],
                "suspicious_votes": bad.get("suspicious_votes", 0),
                "file_type": bad.get("file_type", "unknown"),
                "first_seen": bad.get("first_seen", ""),
                "last_seen": bad.get("last_seen", ""),
            }
        return None

    def whois_lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        self._record("whois_lookup")
        young = self.YOUNG_DOMAINS.get(domain)
        if young:
            return {
                "domain": domain,
                "creation_date": "recent",
                "registrar": young["registrar"],
                "country": young["country"],
                "age_days": young["age_days"],
            }
        return None


class PrefetchedEnricher(Enricher):
    """Serves reputation results gathered out-of-band (browser automation).

    Expects a cache dict shaped like::

        {
          "abuseipdb": {"<ip>": {...}},
          "greynoise": {"<ip>": {...}},
          "virustotal_url": {"<url>": {...}},
          "virustotal_hash": {"<sha256>": {...}},
          "whois": {"<domain>": {...}}
        }

    Missing entries return ``None`` (the pipeline marks the IOC ``unknown``
    and notes the gap, rather than failing). ``fallback`` (default
    ``StubEnricher``) supplies a value when the cache has no entry, so a
    partial browser run still yields a usable verdict.
    """

    name = "prefetched"

    def __init__(self, cache: Dict[str, Dict[str, Any]], fallback: Optional[Enricher] = None) -> None:
        super().__init__()
        self.cache = cache or {}
        self.fallback = fallback  # may be None to force "unknown" on miss

    def _get(self, bucket: str, key: str, tool: str, fb_method: str) -> Optional[Dict[str, Any]]:
        self._record(tool)
        entry = (self.cache.get(bucket) or {}).get(key)
        if entry is not None:
            return entry
        if self.fallback is not None:
            return getattr(self.fallback, fb_method)(key)
        return None

    def abuseipdb_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        return self._get("abuseipdb", ip, "abuseipdb_lookup", "abuseipdb_lookup")

    def greynoise_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        return self._get("greynoise", ip, "greynoise_lookup", "greynoise_lookup")

    def virustotal_url_scan(self, url: str) -> Optional[Dict[str, Any]]:
        return self._get("virustotal_url", url, "virustotal_url_scan", "virustotal_url_scan")

    def virustotal_hash_lookup(self, sha256: str) -> Optional[Dict[str, Any]]:
        return self._get("virustotal_hash", sha256, "virustotal_hash_lookup", "virustotal_hash_lookup")

    def whois_lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        return self._get("whois", domain, "whois_lookup", "whois_lookup")


class BudgetEnricher(Enricher):
    """Limit provider calls per email, including retries, and isolate metadata."""
    def __init__(self, delegate: Enricher, maximum: int):
        super().__init__()
        self.delegate = delegate
        self.remaining = maximum
        self.exhausted = False

    def _call(self, method: str, value: str):
        if self.remaining <= 0:
            self.exhausted = True
            return None
        self.remaining -= 1
        self._record(method)
        return getattr(self.delegate, method)(value)

    def abuseipdb_lookup(self, ip):
        return self._call("abuseipdb_lookup", ip)
    def greynoise_lookup(self, ip):
        return self._call("greynoise_lookup", ip)
    def virustotal_url_scan(self, url):
        return self._call("virustotal_url_scan", url)
    def virustotal_hash_lookup(self, sha256):
        return self._call("virustotal_hash_lookup", sha256)
    def whois_lookup(self, domain):
        return self._call("whois_lookup", domain)
