"""Adapter: Gmail connector payloads -> SentryAI input schema.

Maps a message/thread as returned by the Gmail MCP connector (`get_thread`)
into the dict shape ``sentryai.analyze()`` expects. Tolerant of the
connector's field naming: headers may arrive as a name->value dict, a list of
``{name, value}`` entries, or as flat top-level fields.

Raw Authentication-Results, ARC-Authentication-Results and Received-SPF
headers have no verified provenance here and are ignored. A caller may supply
verified_auth_results separately after a trusted receiving system verifies
authentication. That caller must also authorize those normalized values with
analyze(..., trusted_auth_results=True). Missing auth always requires review.

This adapter only RESHAPES data already fetched from Gmail; it performs no
network calls and never executes email content.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional

from sentryai.textutils import extract_urls
from sentryai.validation import mapping, collection, text, validate_email, MAX_BODY_CHARS, MAX_ATTACHMENTS, MAX_BATCH



def _headers_to_map(headers: Any) -> Dict[str, str]:
    """Normalise headers (dict | list[{name,value}]) into a lowercased map."""
    out: Dict[str, str] = {}
    if headers is None:
        return out
    if isinstance(headers, dict):
        if len(headers) > 1000:
            raise ValueError("Too many Gmail headers")
        for k, v in headers.items():
            if isinstance(v, str):
                out[str(k).strip().lower()] = v
        return out
    if isinstance(headers, list):
        collection(headers, "Gmail headers", 1000)
        for h in headers:
            if isinstance(h, dict):
                name = h.get("name") or h.get("key")
                val = h.get("value")
                if name and isinstance(val, str):
                    out[str(name).strip().lower()] = val
    if not isinstance(headers, (dict, list)):
        raise ValueError("Gmail headers must be an object or array")
    return out


def _first(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        v = d.get(k)
        if v:
            return v
    return None


def _clean_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    candidate = value.strip().strip("[]")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def gmail_message_to_email_input(
    msg: Dict[str, Any],
    email_id: Optional[str] = None,
    verified_auth_results: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Map one Gmail message dict into the SentryAI input schema dict."""
    msg = mapping(msg, "Gmail message")

    body_text = _first(msg, "plaintext_body", "plaintextBody", "body_text", "snippet")
    body_html = _first(msg, "html_body", "htmlBody", "body_html")

    text(body_text, "body_text", MAX_BODY_CHARS)
    text(body_html, "body_html", MAX_BODY_CHARS)

    hdr_map = _headers_to_map(msg.get("headers") or msg.get("payload_headers"))
    subject = _first(msg, "subject") or hdr_map.get("subject")
    sender = _first(msg, "from", "sender") or hdr_map.get("from")
    reply_to = _first(msg, "reply_to", "replyTo") or hdr_map.get("reply-to")

    # Raw headers (including ARC/Received-SPF) are attacker-controlled.
    # Accept auth only from a separate, caller-supplied verifier result.
    auth = mapping(verified_auth_results, "verified_auth_results") if verified_auth_results is not None else {}
    for mechanism, result in auth.items():
        if mechanism not in ("spf", "dkim", "dmarc") or result not in (
                "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"):
            raise ValueError("Invalid verified authentication result")

    x_ip = _clean_ip(hdr_map.get("x-originating-ip") or hdr_map.get("x-original-sender-ip"))

    attachments: List[Dict[str, Any]] = []
    for a in collection(msg.get("attachments") if msg.get("attachments") is not None else [], "attachments", MAX_ATTACHMENTS):
        a = mapping(a, "attachment")
        attachments.append({
            "filename": a.get("filename") or a.get("name"),
            "sha256": a.get("sha256"),
            "mime_type": a.get("mime_type") or a.get("mimeType"),
        })

    urls = extract_urls([body_text or "", body_html or ""])

    return validate_email({
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
        "urls_extracted": urls[:100],
    })


def gmail_thread_to_email_inputs(thread: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Map a Gmail thread dict into a list of SentryAI input dicts (one per message)."""
    thread = mapping(thread, "Gmail thread")
    messages = collection(thread.get("messages") or thread.get("related_messages") or [], "messages", MAX_BATCH)
    thread_id = thread.get("id") or thread.get("threadId") or "thread"
    out: List[Dict[str, Any]] = []
    for i, m in enumerate(messages):
        eid = (m.get("id") if isinstance(m, dict) else None) or f"{thread_id}-{i}"
        out.append(gmail_message_to_email_input(m, email_id=eid))
    return out
