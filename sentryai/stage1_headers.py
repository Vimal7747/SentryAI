"""Stage 1 — Email header authentication analysis.

Examines SPF, DKIM, DMARC results and the From/Reply-To relationship to
produce a HeaderAuthSignals dataclass and a list of IP addresses queued for
Stage 3 (threat-intelligence enrichment).

All email content is UNTRUSTED DATA; this module reads only structured header
fields that have already been normalised by models.Headers.from_dict().
"""

from __future__ import annotations

from typing import List, Tuple

from sentryai.models import EmailInput, HeaderAuthSignals
from sentryai.textutils import domain_from_email


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_headers(
    email: EmailInput,
    trust_missing_auth: bool = False,
) -> Tuple[HeaderAuthSignals, List[str]]:
    """Analyse email authentication headers and return scored signals.

    Scoring (additive, per the SentryAI specification):
        - SPF result that is not 'pass'                        -> +15
        - DKIM result that is not 'pass'                       -> +15
        - DMARC result that is not 'pass'                      -> +20
        - From domain differs from Reply-To domain (mismatch)  -> +20

    Args:
        email: A fully parsed EmailInput instance.

    Returns:
        A 2-tuple of:
            HeaderAuthSignals — scored authentication signals.
            list[str]         — IP addresses queued for Stage 3 enrichment
                                (the x_originating_ip value when present,
                                otherwise an empty list).
    """
    h = email.headers
    points = 0

    # --- SPF -----------------------------------------------------------------
    spf = h.received_spf  # already lowercased or None
    if not (trust_missing_auth and spf is None) and spf != "pass":
        points += 15

    # --- DKIM ----------------------------------------------------------------
    dkim = h.dkim_result  # already lowercased or None
    if not (trust_missing_auth and dkim is None) and dkim != "pass":
        points += 15

    # --- DMARC ---------------------------------------------------------------
    dmarc = h.dmarc_result  # already lowercased or None
    if not (trust_missing_auth and dmarc is None) and dmarc != "pass":
        points += 20

    # --- From vs Reply-To domain mismatch ------------------------------------
    mismatch = _check_reply_to_mismatch(h.from_, h.reply_to)
    if mismatch:
        points += 20

    # --- IPs to enrich -------------------------------------------------------
    ips_to_enrich: List[str] = []
    if h.x_originating_ip:
        ip = h.x_originating_ip.strip()
        if ip:
            ips_to_enrich.append(ip)

    signals = HeaderAuthSignals(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        from_reply_to_mismatch=mismatch,
        points_contributed=points,
    )
    return signals, ips_to_enrich


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_reply_to_mismatch(from_: str | None, reply_to: str | None) -> bool:
    """Return True when Reply-To is present and its domain differs from From.

    A None or empty Reply-To is not considered a mismatch (legitimate emails
    often omit it entirely).
    """
    if not reply_to or not reply_to.strip():
        return False
    from_domain = domain_from_email(from_ or "")
    reply_domain = domain_from_email(reply_to or "")
    if not from_domain or not reply_domain:
        # Malformed addresses; treat the presence of any reply-to with an
        # unresolvable from-domain as a mismatch only if reply_domain exists.
        return bool(reply_domain and not from_domain)
    return from_domain != reply_domain
