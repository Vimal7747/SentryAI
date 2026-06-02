"""Adapter: Gmail connector payloads -> SentryAI input schema.

Maps a message/thread as returned by the Gmail MCP connector (`get_thread`)
into the dict shape ``sentryai.analyze()`` expects. Tolerant of the
connector's field naming: headers may arrive as a name->value dict, a list of
``{name, value}`` entries, or as flat top-level fields.

Gmail exposes the body and common headers but usually NOT the raw
Authentication-Results header, so SPF/DKIM/DMARC and x_originating_ip are
best-effort: parsed when present, left null otherwise (SentryAI treats null
auth as a risk signal, so the verdict still completes).

This adapter only RESHAPES data already fetched from Gmail; it performs no
network calls and never executes email content.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from sentryai.textutils import extract_urls

_AUTH_RESULT_KEYS = ("authentication-results", "arc-authentication-results")


def _headers_to_map(headers: Any) -> Dict[str, str]:
    """Normalise headers (dict | list[{name,value}]) into a lowercased map."""
    out: Dict[str, str] = {}
    if not headers:
        return out
    if isinstance(headers, dict):
        for k, v in headers.items():
            if isinstance(v, str):
                out[str(k).strip().lower()] = v
        return out
    if isinstance(headers, list):
        for h in headers:
            if isinstance(h, dict):
                name = h.get("name") or h.get("key")
                val = h.get("value")
                if name and isinstance(val, str):
                    out[str(name).strip().lower()] = val
    return out


def _first(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        v = d.get(k)
        if v:
            return v
    return None


def _parse_auth_results(value: str) -> Dict[str, str]:
    """Pull spf/dkim/dmarc results out of an Authentication-Results header."""
    out: Dict[str, str] = {}
    if not value:
        return out
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(mech + r"\s*=\s*([a-zA-Z]+)", value, re.I)
        if m:
            out[mech] = m.group(1).lower()
    return out


def _clean_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    m = re.search(r"[0-9A-Fa-f:.]+", value.replace("[", "").replace("]", ""))
    return m.group(0) if m else None


def gmail_message_to_email_input(
    msg: Dict[str, Any],
    email_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Map one Gmail message dict into the SentryAI input schema dict."""
    msg = msg or {}

    body_text = _first(msg, "plaintext_body", "plaintextBody", "body_text", "snippet")
    body_html = _first(msg, "html_body", "htmlBody", "body_html")

    hdr_map = _headers_to_map(msg.get("headers") or msg.get("payload_headers"))
    subject = _first(msg, "subject") or hdr_map.get("subject")
    sender = _first(msg, "from", "sender") or hdr_map.get("from")
    reply_to = _first(msg, "reply_to", "replyTo") or hdr_map.get("reply-to")

    auth: Dict[str, str] = {}
    for k in _AUTH_RESULT_KEYS:
        if k in hdr_map:
            for mech, res in _parse_auth_results(hdr_map[k]).items():
                auth.setdefault(mech, res)
    if "spf" not in auth and "received-spf" in hdr_map:
        m = re.match(r"\s*([a-zA-Z]+)", hdr_map["received-spf"])
        if m:
            auth["spf"] = m.group(1).lower()

    x_ip = _clean_ip(hdr_map.get("x-originating-ip") or hdr_map.get("x-original-sender-ip"))

    attachments: List[Dict[str, Any]] = []
    for a in (msg.get("attachments") or []):
        if isinstance(a, dict):
            attachments.append({
                "filename": a.get("filename") or a.get("name"),
                "sha256": a.get("sha256"),
                "mime_type": a.get("mime_type") or a.get("mimeType"),
            })

    urls = extract_urls([body_text or "", body_html or ""])

    return {
        "email_id": email_id or _first(msg, "id", "message_id", "messageId") or "",
        "headers": {
            "from": sender,
            "reply_to": reply_to,
            "subject": subject,
            "received_spf": auth.get("spf"),
            "dkim_result": auth.get("dkim"),
            "dmarc_result": auth.get("dmarc"),
            "x_originating_ip": x_ip,
        },
        "body_text": body_text,
        "body_html": body_html,
        "attachments": attachments,
        "urls_extracted": urls,
    }


def gmail_thread_to_email_inputs(thread: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Map a Gmail thread dict into a list of SentryAI input dicts (one per message)."""
    thread = thread or {}
    messages = thread.get("messages") or thread.get("related_messages") or []
    thread_id = thread.get("id") or thread.get("threadId") or "thread"
    out: List[Dict[str, Any]] = []
    for i, m in enumerate(messages):
        eid = (m.get("id") if isinstance(m, dict) else None) or f"{thread_id}-{i}"
        out.append(gmail_message_to_email_input(m, email_id=eid))
    return out
