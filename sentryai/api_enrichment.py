"""API-backed threat-intel Enricher for SentryAI.

Implements the ``Enricher`` interface against real services:
  - AbuseIPDB  /api/v2/check          (IP reputation)        [key required]
  - GreyNoise  community API          (IP noise/classification) [key optional]
  - VirusTotal /api/v3/urls|files     (URL & hash reputation)  [key required]
  - RDAP       rdap.org/domain/<d>    (domain age via WHOIS)   [no key]

Design notes:
  - Stdlib only (urllib). No third-party HTTP deps.
  - API keys are read from environment variables by default and are NEVER
    written to disk or logged. Pass them explicitly only for testing.
  - Every call is defensive: network/parse/HTTP errors return None, and the
    Stage 3 enricher harness turns None into an "unknown" verdict + a note
    (it also retries once). Nothing here raises into the pipeline.
  - An injectable ``http`` callable makes the class unit-testable offline.

Env vars: VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, GREYNOISE_API_KEY (optional).
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Tuple

from sentryai.enrichment import Enricher

# http callable contract: (method, url, headers, data) -> (status, json|None)
HttpFn = Callable[[str, str, Dict[str, str], Optional[bytes]], Tuple[int, Optional[Dict[str, Any]]]]


def _urllib_http(method: str, url: str, headers: Dict[str, str],
                 data: Optional[bytes], timeout: float = 15.0) -> Tuple[int, Optional[Dict[str, Any]]]:
    """Default HTTP transport using urllib. Returns (status, parsed_json|None)."""
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            try:
                return resp.status, json.loads(body) if body else None
            except json.JSONDecodeError:
                return resp.status, None
    except urllib.error.HTTPError as e:
        # 404 etc. — read body if present so callers can distinguish.
        try:
            body = e.read().decode("utf-8", "replace")
            parsed = json.loads(body) if body else None
        except Exception:  # noqa: BLE001
            parsed = None
        return e.code, parsed
    except Exception:  # noqa: BLE001 — DNS, timeout, TLS, connection refused
        return 0, None


class ApiEnricher(Enricher):
    """Live reputation provider backed by AbuseIPDB / GreyNoise / VirusTotal / RDAP."""

    name = "api"

    def __init__(
        self,
        vt_key: Optional[str] = None,
        abuseipdb_key: Optional[str] = None,
        greynoise_key: Optional[str] = None,
        timeout: float = 15.0,
        http: Optional[HttpFn] = None,
        request_interval: float = 0.0,
    ) -> None:
        super().__init__()
        self.vt_key = vt_key if vt_key is not None else os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.abuseipdb_key = (
            abuseipdb_key if abuseipdb_key is not None else os.environ.get("ABUSEIPDB_API_KEY", "")
        )
        self.greynoise_key = (
            greynoise_key if greynoise_key is not None else os.environ.get("GREYNOISE_API_KEY", "")
        )
        self.timeout = timeout
        # Optional client-side throttle (seconds between outbound calls) to
        # respect provider rate limits, e.g. VirusTotal public = 4/min -> 15s
        # (code-review #3). Default 0 = no throttle. Injected http skips it.
        self.request_interval = request_interval
        self._last_call = 0.0
        if http is not None:
            self._http: HttpFn = http
        else:
            self._http = self._throttled_urllib

    def _throttled_urllib(self, method, url, headers, data):
        if self.request_interval > 0:
            import time
            wait = self.request_interval - (time.monotonic() - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()
        return _urllib_http(method, url, headers, data, self.timeout)

    # ------------------------------------------------------------------ IP
    def abuseipdb_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        self._record("abuseipdb_lookup")
        if not self.abuseipdb_key:
            return None
        qs = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        url = f"https://api.abuseipdb.com/api/v2/check?{qs}"
        headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
        status, body = self._http("GET", url, headers, None)
        if status != 200 or not body or "data" not in body:
            return None
        d = body["data"]
        return {
            "ip": d.get("ipAddress", ip),
            "abuse_confidence_score": int(d.get("abuseConfidenceScore", 0) or 0),
            "is_public": bool(d.get("isPublic", True)),
            "usage_type": d.get("usageType") or "unknown",
            "isp": d.get("isp") or "unknown",
            "domain": d.get("domain") or "",
            "total_reports": int(d.get("totalReports", 0) or 0),
        }

    def greynoise_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        self._record("greynoise_lookup")
        url = f"https://api.greynoise.io/v3/community/{urllib.parse.quote(ip)}"
        headers = {"Accept": "application/json"}
        if self.greynoise_key:
            headers["key"] = self.greynoise_key
        status, body = self._http("GET", url, headers, None)
        # 404 => IP not observed by GreyNoise (treat as benign-ish unknown).
        if status == 404:
            return {"ip": ip, "noise": False, "riot": False,
                    "classification": "unknown", "name": "", "last_seen": ""}
        if status != 200 or not body:
            return None
        return {
            "ip": body.get("ip", ip),
            "noise": bool(body.get("noise", False)),
            "riot": bool(body.get("riot", False)),
            "classification": (body.get("classification") or "unknown").lower(),
            "name": body.get("name") or "",
            "last_seen": body.get("last_seen") or "",
        }

    # ------------------------------------------------------------------ URL
    def virustotal_url_scan(self, url: str) -> Optional[Dict[str, Any]]:
        self._record("virustotal_url_scan")
        if not self.vt_key:
            return None
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")
        api = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        status, body = self._http("GET", api, {"x-apikey": self.vt_key}, None)
        if status == 404:
            # Not previously analysed; "unknown" is safer than "clean".
            return None
        if status != 200 or not body:
            return None
        attrs = (body.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        cats = attrs.get("categories") or {}
        return {
            "url": url,
            "malicious_votes": int(stats.get("malicious", 0) or 0),
            "suspicious_votes": int(stats.get("suspicious", 0) or 0),
            "harmless_votes": int(stats.get("harmless", 0) or 0),
            "categories": sorted({str(v) for v in cats.values()}) if isinstance(cats, dict) else [],
            "final_url": attrs.get("last_final_url") or url,
        }

    # ------------------------------------------------------------------ Hash
    def virustotal_hash_lookup(self, sha256: str) -> Optional[Dict[str, Any]]:
        self._record("virustotal_hash_lookup")
        if not self.vt_key:
            return None
        api = f"https://www.virustotal.com/api/v3/files/{urllib.parse.quote(sha256)}"
        status, body = self._http("GET", api, {"x-apikey": self.vt_key}, None)
        if status == 404 or status != 200 or not body:
            return None
        attrs = (body.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        return {
            "sha256": sha256,
            "malicious_votes": int(stats.get("malicious", 0) or 0),
            "suspicious_votes": int(stats.get("suspicious", 0) or 0),
            "file_type": attrs.get("type_description") or "unknown",
            "first_seen": str(attrs.get("first_submission_date") or ""),
            "last_seen": str(attrs.get("last_analysis_date") or ""),
        }

    # ------------------------------------------------------------------ Domain
    def whois_lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        self._record("whois_lookup")
        api = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
        status, body = self._http("GET", api, {"Accept": "application/json"}, None)
        if status != 200 or not body:
            return None
        creation = ""
        for ev in (body.get("events") or []):
            if ev.get("eventAction") in ("registration", "last changed registration"):
                creation = ev.get("eventDate") or ""
                if ev.get("eventAction") == "registration":
                    break
        age_days = _age_days(creation)
        registrar = _rdap_registrar(body)
        country = body.get("country") or "unknown"
        return {
            "domain": domain,
            "creation_date": creation,
            "registrar": registrar,
            "country": country,
            "age_days": age_days,
        }


def _age_days(iso_date: str) -> Optional[int]:
    if not iso_date:
        return None
    try:
        s = iso_date.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError):
        return None


def _rdap_registrar(body: Dict[str, Any]) -> str:
    for ent in (body.get("entities") or []):
        roles = ent.get("roles") or []
        if "registrar" in roles:
            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and item and item[0] == "fn":
                        return item[3] if len(item) > 3 else "unknown"
            return ent.get("handle") or "unknown"
    return "unknown"
