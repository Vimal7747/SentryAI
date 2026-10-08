"""Bounded validation for untrusted email submissions (stdlib only)."""
from typing import Any
import re

MAX_ATTACHMENTS = 100
MAX_URLS = 100
MAX_BATCH = 100
MAX_BODY_CHARS = 1_000_000
MAX_FIELD_CHARS = 4096
MAX_INPUT_BYTES = 2_000_000
MAX_IOCS = 200
DEFAULT_LOOKUP_CALLS = 100

class InputValidationError(ValueError):
    """Input does not match the supported email schema or resource limits."""

def mapping(value: Any, field: str) -> dict:
    if not isinstance(value, dict):
        raise InputValidationError(f"{field} must be an object")
    return value

def text(value: Any, field: str, limit: int = MAX_FIELD_CHARS):
    if value is not None and (not isinstance(value, str) or len(value) > limit):
        raise InputValidationError(f"{field} must be a string or null, at most {limit} characters")
    return value

def collection(value: Any, field: str, limit: int) -> list:
    if not isinstance(value, list) or len(value) > limit:
        raise InputValidationError(f"{field} must be an array with at most {limit} entries")
    return value

def validate_email(d: Any) -> dict:
    d = mapping(d, "email")
    text(d.get("email_id"), "email_id")
    headers = mapping(d.get("headers") if d.get("headers") is not None else {}, "headers")
    for key in ("from", "reply_to", "subject", "received_spf", "dkim_result", "dmarc_result", "x_originating_ip"):
        text(headers.get(key), f"headers.{key}")
    for key in ("received_spf", "dkim_result", "dmarc_result"):
        value = headers.get(key)
        if value is not None and value.strip().lower() not in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", ""):
            raise InputValidationError(f"headers.{key} has an unsupported authentication result")
    for key in ("body_text", "body_html"):
        text(d.get(key), key, MAX_BODY_CHARS)
    for item in collection(d.get("attachments") if d.get("attachments") is not None else [], "attachments", MAX_ATTACHMENTS):
        item = mapping(item, "attachment")
        for key in ("filename", "sha256", "mime_type"):
            text(item.get(key), f"attachment.{key}")
        digest = item.get("sha256")
        if digest and not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise InputValidationError("attachment.sha256 must contain 64 hexadecimal characters")
    for url in collection(d.get("urls_extracted") if d.get("urls_extracted") is not None else [], "urls_extracted", MAX_URLS):
        if not isinstance(url, str) or not url or len(url) > MAX_FIELD_CHARS:
            raise InputValidationError("urls_extracted entries must be nonempty strings of at most 4096 characters")
    return d

def budget(value: Any, field: str, maximum: int = 1000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise InputValidationError(f"{field} must be an integer between 0 and {maximum}")
    return value
