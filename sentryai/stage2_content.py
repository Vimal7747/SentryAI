"""Stage 2 — Content signal analysis.

Scans email body text, HTML, subject, and extracted URLs for behavioural
patterns that are strong indicators of phishing.  Returns a list of
ContentSignal objects, a prompt-injection flag, and the injection categories.

All email content is treated as UNTRUSTED DATA.  Nothing found in the body
is ever executed or interpreted as a code instruction.  Descriptions in
ContentSignal instances summarise the *pattern* detected, never verbatim
attacker text.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from sentryai.models import ContentSignal, EmailInput
from sentryai.security import detect_prompt_injection, describe_injection
from sentryai.textutils import (
    domain_from_url as _domain_from_url,
    extract_urls as _extract_urls,
    registrable_domain,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_content(
    email: EmailInput,
) -> Tuple[List[ContentSignal], bool, List[str]]:
    """Analyse email body content for phishing-indicator patterns."""
    signals: List[ContentSignal] = []

    body_text = email.body_text or ""
    body_html = email.body_html or ""
    subject = email.headers.subject or ""

    combined_text = " ".join(filter(None, [subject, body_text, body_html]))
    all_urls = _collect_urls(email.urls_extracted, body_text, body_html)

    urgency_signal = _check_urgency(combined_text)
    if urgency_signal:
        signals.append(urgency_signal)

    signals.extend(_check_credential_harvest(combined_text, body_html, all_urls))
    signals.extend(_check_impersonation(combined_text))
    signals.extend(_check_evasion(body_text, body_html, all_urls))

    injection_detected, injection_categories = detect_prompt_injection(
        body_text, body_html, subject
    )
    if injection_detected:
        signals.append(
            ContentSignal(
                signal_type="prompt_injection",
                description=describe_injection(injection_categories),
                points_contributed=50,
            )
        )

    return signals, injection_detected, injection_categories


# ---------------------------------------------------------------------------
# Urgency
# ---------------------------------------------------------------------------

_URGENCY_PHRASES: List[str] = [
    "urgent", "immediately", "account suspended", "verify now",
    "expires", "action required", "limited time",
]
_URGENCY_MAX = 40
_URGENCY_PER_HIT = 10


def _check_urgency(text: str):
    """Return a ContentSignal if urgency phrases are detected, else None."""
    lower = text.lower()
    hits = sum(1 for phrase in _URGENCY_PHRASES if phrase in lower)
    if hits == 0:
        return None
    points = min(hits * _URGENCY_PER_HIT, _URGENCY_MAX)
    return ContentSignal(
        signal_type="urgency",
        description=(
            "Urgency-inducing language detected: {} matching phrase(s) "
            "found (e.g. 'urgent', 'immediately', 'action required').".format(hits)
        ),
        points_contributed=points,
    )


# ---------------------------------------------------------------------------
# Credential harvest
# ---------------------------------------------------------------------------

_CRED_REQUEST_RE = re.compile(
    r"\b(password|ssn|social\s+security|card\s+number|cvv|otp|one[- ]time\s+(code|password)|"
    r"login\s+credentials?)\b",
    re.I,
)
_HTML_FORM_RE = re.compile(r"<form\b", re.I)
_HTML_PASSWORD_INPUT_RE = re.compile(
    r'<input[^>]+type\s*=\s*["\']?password["\']?',
    re.I,
)

# Brand roots for lookalike detection. Deliberately excludes generic words
# like "bank" (code-review C): a hyphen token such as "secure-bank.com" is too
# weak a signal and produced false positives. Brand-name impersonation in body
# text (incl. "bank", "chase", etc.) is still handled by _BRAND_IMPERSONATION_RE.
_BRAND_ROOTS: List[str] = [
    "paypal", "amazon", "google", "microsoft", "apple", "netflix",
    "facebook",
]

_DIGIT_TO_LETTERS = {
    "0": ["o"], "1": ["i", "l"], "2": ["z"], "3": ["e"], "4": ["a"],
    "5": ["s"], "6": ["g", "b"], "7": ["t"], "8": ["b", "g"], "9": ["g", "q"],
}


def _digit_substitution_candidates(text):
    """Return every string reachable by replacing digits with look-alike letters."""
    candidates = {text}
    for digit, letters in _DIGIT_TO_LETTERS.items():
        if digit not in text:
            continue
        expanded = set()
        for candidate in candidates:
            if digit in candidate:
                for letter in letters:
                    expanded.add(candidate.replace(digit, letter))
            expanded.add(candidate)
        candidates = expanded
    return list(candidates)


def _is_lookalike_domain(domain):
    """Return True when *domain* impersonates a known brand.

    Uses the registrable domain (eTLD+1) so a brand's own subdomains
    (www.paypal.com, accounts.google.com, id.apple.com) are never flagged
    as typosquats -- the root cause of code-review finding #1. A domain is a
    lookalike when the brand does NOT own the registrable domain AND the brand
    appears via homoglyph substitution, hyphenation inside the registered
    label, or as a subdomain label of a non-brand registrable domain.
    """
    if not domain:
        return False

    host = domain.split(":")[0].strip().lower().strip(".")
    if not host:
        return False

    reg = registrable_domain(host)
    reg_sld = reg.split(".")[0] if reg else ""
    host_labels = host.split(".")
    reg_label_count = len(reg.split(".")) if reg else 0
    sub_labels = host_labels[:-reg_label_count] if len(host_labels) > reg_label_count else []

    for brand in _BRAND_ROOTS:
        if reg_sld == brand:
            continue
        sld_tokens = reg_sld.split("-")
        if brand in sld_tokens:
            return True
        for token in sld_tokens:
            if brand in _digit_substitution_candidates(token):
                return True
        for label in sub_labels:
            if label == brand or brand in _digit_substitution_candidates(label):
                return True

    return False


def _extract_domain_from_url(url):
    """Pull the host portion from a URL string (shared parser)."""
    return _domain_from_url(url)


def _check_credential_harvest(combined_text, body_html, all_urls):
    """Detect credential-harvesting patterns; return zero or more signals."""
    out = []

    if _CRED_REQUEST_RE.search(combined_text):
        out.append(
            ContentSignal(
                signal_type="credential_harvest",
                description=(
                    "Body contains language requesting sensitive credentials "
                    "(password, SSN, card number, OTP, or similar)."
                ),
                points_contributed=30,
            )
        )

    if body_html:
        has_form = bool(_HTML_FORM_RE.search(body_html))
        has_pw_input = bool(_HTML_PASSWORD_INPUT_RE.search(body_html))
        if has_form or has_pw_input:
            out.append(
                ContentSignal(
                    signal_type="credential_harvest",
                    description=(
                        "HTML body contains a form with a password input field, "
                        "consistent with an inline credential-harvesting page."
                    ),
                    points_contributed=40,
                )
            )

    lookalike_found = any(
        _is_lookalike_domain(_extract_domain_from_url(u)) for u in all_urls
    )
    if lookalike_found:
        out.append(
            ContentSignal(
                signal_type="credential_harvest",
                description=(
                    "One or more URLs contain a domain that closely resembles "
                    "a known brand via homoglyph substitution, hyphenation, or "
                    "subdomain spoofing (typosquat / lookalike domain)."
                ),
                points_contributed=35,
            )
        )

    return out


# ---------------------------------------------------------------------------
# Impersonation
# ---------------------------------------------------------------------------

_BRAND_IMPERSONATION_RE = re.compile(
    r"\b(microsoft|paypal|apple|amazon|netflix|google|"
    r"bank|chase|barclays|hsbc|wells\s+fargo)\b",
    re.I,
)
_BRAND_CONTEXT_RE = re.compile(
    r"\b(account|security|verify|verification|password|login|sign[- ]in|"
    r"suspend|alert|notice|confirm|update|access)\b",
    re.I,
)
_AUTHORITY_RE = re.compile(
    r"\b(ceo|chief\s+executive|it\s+department|it\s+support|hmrc|irs|"
    r"head\s+office|administrator|admin\s+team|helpdesk)\b",
    re.I,
)
_PRIZE_RE = re.compile(
    r"\b(you\s+have\s+won|prize|reward|gift\s+card|claim\s+your|"
    r"congratulations.{0,40}won|lucky\s+winner)\b",
    re.I,
)
_FEAR_RE = re.compile(
    r"\b(legal\s+action|account\s+closure|suspended|terminated|arrest|"
    r"penalty|prosecut|enforcement)\b",
    re.I,
)


def _check_impersonation(text):
    """Detect brand and authority impersonation signals."""
    out = []

    if _BRAND_IMPERSONATION_RE.search(text) and _BRAND_CONTEXT_RE.search(text):
        out.append(
            ContentSignal(
                signal_type="impersonation",
                description=(
                    "Email references a well-known brand alongside "
                    "account/security language, consistent with brand "
                    "impersonation phishing."
                ),
                points_contributed=30,
            )
        )

    if _AUTHORITY_RE.search(text):
        out.append(
            ContentSignal(
                signal_type="impersonation",
                description=(
                    "Email claims to originate from an authority figure or "
                    "department (CEO, IT, HMRC, IRS, head office, or "
                    "administrator)."
                ),
                points_contributed=25,
            )
        )

    if _PRIZE_RE.search(text):
        out.append(
            ContentSignal(
                signal_type="impersonation",
                description=(
                    "Email contains prize, reward, or gift-card lure language "
                    "designed to entice the recipient into clicking or responding."
                ),
                points_contributed=20,
            )
        )

    if _FEAR_RE.search(text):
        out.append(
            ContentSignal(
                signal_type="impersonation",
                description=(
                    "Email uses fear or threat language (legal action, account "
                    "closure, suspension, termination, or arrest) to coerce "
                    "the recipient."
                ),
                points_contributed=25,
            )
        )

    return out


# ---------------------------------------------------------------------------
# Evasion
# ---------------------------------------------------------------------------

_ZERO_WIDTH_RE = re.compile(
    "[​‌‍﻿]"
    "|&#x200b;|&#x200c;|&#x200d;|&#xfeff;|&zwnj;|&zwj;",
    re.I,
)
_LONG_SPACE_RE = re.compile(r" {31,}")

# Base64 detection -- tightened to cut false positives (code-review #2).
# A bare alphanumeric run is NOT enough; legitimate HTML/marketing mail is
# full of long tokens. We flag base64 only when a data-URI marker is present,
# or a word-boundaried blob that actually looks like base64 appears in PLAIN
# TEXT (not HTML).
_DATA_URI_B64_RE = re.compile(r";base64,", re.I)
_BASE64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")


def _looks_like_base64(blob: str) -> bool:
    """Heuristic: does *blob* plausibly carry encoded content (not a plain word)?"""
    if len(blob) < 40:
        return False
    if "+" in blob or "/" in blob or blob.endswith("="):
        return True
    has_upper = any(c.isupper() for c in blob)
    has_lower = any(c.islower() for c in blob)
    has_digit = any(c.isdigit() for c in blob)
    return has_upper and has_lower and has_digit


_REDIRECT_URL_IN_URL_RE = re.compile(r"https?://[^\s]*https?://", re.I)
_REDIRECT_PARAM_RE = re.compile(
    r"[?&](url|redirect|r|redir|return|returnurl|dest|destination)=https?",
    re.I,
)


def _check_evasion(body_text, body_html, all_urls):
    """Detect evasion techniques; return zero or more signals."""
    out = []

    if body_html and body_html.strip() and not (body_text and body_text.strip()):
        out.append(
            ContentSignal(
                signal_type="evasion",
                description=(
                    "Email has an HTML body but no plain-text alternative, "
                    "a common technique to obstruct text-based analysis."
                ),
                points_contributed=15,
            )
        )

    combined = body_text + " " + body_html
    if _ZERO_WIDTH_RE.search(combined) or _LONG_SPACE_RE.search(combined):
        out.append(
            ContentSignal(
                signal_type="evasion",
                description=(
                    "Email body contains zero-width Unicode characters or "
                    "abnormally long whitespace runs, used to disrupt keyword "
                    "scanning."
                ),
                points_contributed=20,
            )
        )

    has_data_uri = bool(_DATA_URI_B64_RE.search(body_text + " " + body_html))
    has_text_blob = any(
        _looks_like_base64(b) for b in _BASE64_BLOB_RE.findall(body_text or "")
    )
    if has_data_uri or has_text_blob:
        out.append(
            ContentSignal(
                signal_type="evasion",
                description=(
                    "Email contains base64-encoded content (a data-URI payload "
                    "or an encoded blob in the plain-text body), potentially "
                    "used to conceal content from scanners."
                ),
                points_contributed=25,
            )
        )

    redirect_found = False
    for url in all_urls:
        if _REDIRECT_URL_IN_URL_RE.search(url) or _REDIRECT_PARAM_RE.search(url):
            redirect_found = True
            break
    if redirect_found:
        out.append(
            ContentSignal(
                signal_type="evasion",
                description=(
                    "One or more URLs contain embedded redirect parameters "
                    "(url=, redirect=, r=http, etc.) or a nested URL, "
                    "indicating a redirect chain to obscure the final destination."
                ),
                points_contributed=20,
            )
        )

    return out


# ---------------------------------------------------------------------------
# URL extraction helper
# ---------------------------------------------------------------------------

def _collect_urls(urls_extracted, body_text, body_html):
    """Merge structured URLs with any found inline -- via the shared parser
    so Stage 2 and Stage 3 always agree on the URL list (code-review #3)."""
    return _extract_urls([body_text, body_html], seed=urls_extracted)
