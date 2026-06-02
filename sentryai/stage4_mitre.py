"""Stage 4 — MITRE ATT&CK technique mapping.

Loads the local MITRE ATT&CK / ATLAS technique catalogue and maps the
pipeline's observed signals onto relevant techniques using keyword
matching and rule-based overrides.

Email content is NEVER accessed here; we operate exclusively on the
structured output from earlier stages (signal type labels, IOC verdict
labels, Boolean flags). This keeps Stage 4 free of attacker-controlled
strings.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from sentryai.models import ContentSignal, IOCResult, MitreTechnique

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

_DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "mitre_attack.json")

# Loaded once at import time; each entry has: technique_id, technique_name,
# tactic, keywords (list[str]), description.
_TECHNIQUES: List[Dict[str, Any]] = []


def _load_techniques() -> List[Dict[str, Any]]:
    """Load and return the technique list from the JSON catalogue."""
    with open(_DATA_FILE, encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("techniques", [])


def _get_techniques() -> List[Dict[str, Any]]:
    """Return the cached technique list, loading it on first access."""
    global _TECHNIQUES
    if not _TECHNIQUES:
        _TECHNIQUES = _load_techniques()
    return _TECHNIQUES


def _technique_by_id(technique_id: str) -> Optional[Dict[str, Any]]:
    """Look up a technique by its ID (case-insensitive). Returns None if not found."""
    tid_lower = technique_id.lower()
    for t in _get_techniques():
        if t["technique_id"].lower() == tid_lower:
            return t
    return None


def _make_mitre(technique: Dict[str, Any], relevance: str) -> MitreTechnique:
    """Construct a MitreTechnique dataclass from a catalogue entry."""
    return MitreTechnique(
        technique_id=technique["technique_id"],
        technique_name=technique["technique_name"],
        tactic=technique["tactic"],
        relevance=relevance,
    )


# ---------------------------------------------------------------------------
# Keyword scoring
# ---------------------------------------------------------------------------

def _build_query_keywords(
    content_signals: List[ContentSignal],
    ioc_results: List[IOCResult],
    prompt_injection_detected: bool,
    attachments_present: bool,
) -> set:
    """Derive a keyword set from stage outputs — no raw email content."""
    keywords: set = set()

    # From content signal type labels (e.g. "urgency", "credential_harvest",
    # "impersonation", "evasion", "prompt_injection", "other").
    for sig in content_signals:
        # Normalise underscores to spaces and add individual words too.
        label = sig.signal_type.lower().replace("_", " ")
        keywords.add(label)
        keywords.update(label.split())

    # From IOC results: type and verdict.
    for ioc in ioc_results:
        keywords.add(ioc.ioc_type.lower())          # ip / url / domain / hash / email
        keywords.add(ioc.verdict.lower())            # malicious / suspicious / clean / unknown
        if ioc.ioc_type.lower() == "url":
            keywords.add("link")
            keywords.add("url")
        if ioc.ioc_type.lower() == "hash":
            keywords.add("attachment")
        if ioc.verdict.lower() in ("malicious", "suspicious"):
            keywords.add("malicious")
            if ioc.ioc_type.lower() == "url":
                keywords.add("malicious link")
                keywords.add("malicious url")
            if ioc.ioc_type.lower() == "hash":
                keywords.add("malicious file")

    if prompt_injection_detected:
        keywords.add("prompt injection")
        keywords.add("llm")
        keywords.add("jailbreak")
        keywords.add("ignore previous instructions")
        keywords.add("adversarial input")

    if attachments_present:
        keywords.add("attachment")
        keywords.add("open file")

    return keywords


def _score_technique(technique: Dict[str, Any], query_keywords: set) -> int:
    """Return the number of keyword overlaps between technique and query set."""
    tech_kws = {k.lower() for k in technique.get("keywords", [])}
    return len(tech_kws & query_keywords)


# ---------------------------------------------------------------------------
# Rule-based forced inclusions
# ---------------------------------------------------------------------------

def _forced_techniques(
    content_signals: List[ContentSignal],
    ioc_results: List[IOCResult],
    prompt_injection_detected: bool,
    attachments_present: bool,
) -> Dict[str, str]:
    """Return {technique_id: relevance_sentence} for mandatory mappings.

    Rules are evaluated against structured signal labels and IOC verdicts,
    never against raw email content.
    """
    forced: Dict[str, str] = {}

    signal_types = {s.signal_type.lower() for s in content_signals}
    ioc_types_malicious = {
        i.ioc_type.lower()
        for i in ioc_results
        if i.verdict.lower() in ("malicious", "suspicious")
    }
    has_malicious_url = any(
        i.ioc_type.lower() == "url" and i.verdict.lower() in ("malicious", "suspicious")
        for i in ioc_results
    )
    has_malicious_hash = any(
        i.ioc_type.lower() == "hash" and i.verdict.lower() in ("malicious", "suspicious")
        for i in ioc_results
    )
    has_malicious_domain = any(
        i.ioc_type.lower() == "domain" and i.verdict.lower() in ("malicious", "suspicious")
        for i in ioc_results
    )
    has_any_signal = bool(content_signals) or bool(ioc_results)

    # Prompt injection -> always include AML.T0051
    if prompt_injection_detected:
        forced["AML.T0051"] = (
            "Prompt injection was detected in the email body, indicating an attempt "
            "to manipulate an LLM-based analyst into ignoring its safety instructions."
        )

    # Credential harvest or login form -> T1566.002 + T1056 + T1056.003
    if "credential_harvest" in signal_types or "login form" in signal_types:
        forced["T1566.002"] = (
            "A credential-harvesting signal was identified, consistent with a spearphishing "
            "link designed to capture login credentials."
        )
        forced["T1056"] = (
            "A credential-harvesting or login-form signal suggests adversarial input capture "
            "via a fake web form."
        )
        forced["T1056.003"] = (
            "The presence of a login-form or credential-harvest indicator points to web-portal "
            "capture as the credential-theft mechanism."
        )

    # Malicious/suspicious URL -> T1566.002 + T1204.001
    if has_malicious_url or has_malicious_domain:
        forced["T1566.002"] = forced.get(
            "T1566.002",
            "A malicious or suspicious URL/domain IOC was identified, consistent with "
            "a spearphishing link used as the delivery vector.",
        )
        forced["T1204.001"] = (
            "A malicious URL IOC is present, requiring user interaction (a click) "
            "to trigger the attack chain."
        )

    # Malicious attachment hash, or attachments present with malicious verdict
    if has_malicious_hash or (attachments_present and "hash" in ioc_types_malicious):
        forced["T1566.001"] = (
            "A malicious file hash or suspicious attachment was identified, indicating "
            "spearphishing via a malicious attachment."
        )
        forced["T1204.002"] = (
            "The malicious attachment requires the user to open the file to complete execution."
        )
    elif attachments_present and has_any_signal:
        # Attachments present but no confirmed malicious hash — still flag attachment vector
        forced.setdefault(
            "T1566.001",
            "Attachments are present alongside phishing signals, suggesting a potential "
            "spearphishing-attachment delivery vector.",
        )

    # Impersonation signals
    if any(s in signal_types for s in ("impersonation", "brand", "authority", "ceo")):
        forced["T1656"] = (
            "Impersonation signals (brand, authority, or executive persona) were detected, "
            "consistent with adversarial impersonation to gain victim trust."
        )

    # Financial/reward lures alongside impersonation -> T1657
    if any(s in signal_types for s in ("impersonation", "brand", "ceo", "authority")) and (
        any(s in signal_types for s in ("financial", "reward", "urgency"))
    ):
        forced["T1657"] = (
            "Financial-lure or reward signals combined with impersonation indicators suggest "
            "an attempt to steal monetary resources or coerce a financial transaction."
        )

    # Lookalike domain / evasion -> T1036 and/or T1027
    if any(s in signal_types for s in ("evasion", "lookalike", "obfuscation", "encoding")):
        forced["T1036"] = (
            "Evasion or lookalike-domain signals were detected, indicating masquerading "
            "techniques to make the email appear legitimate."
        )
        forced["T1027"] = (
            "Obfuscation or encoding signals suggest the adversary attempted to hide "
            "malicious content to evade automated detection."
        )

    # Base T1566 — include whenever any phishing-indicative signal fired
    if has_any_signal:
        forced.setdefault(
            "T1566",
            "One or more phishing-indicative signals were observed, establishing this "
            "email as a phishing attempt per the base MITRE T1566 technique.",
        )

    return forced


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_techniques(
    content_signals: List[ContentSignal],
    ioc_results: List[IOCResult],
    prompt_injection_detected: bool,
    attachments_present: bool,
    top_k: int = 5,
) -> List[MitreTechnique]:
    """Map observed signals to MITRE ATT&CK / ATLAS techniques.

    Operates exclusively on structured stage outputs (signal type labels,
    IOC type and verdict strings, Boolean flags). Raw email content is
    NEVER accessed.

    The mapping combines:
      1. Rule-based forced inclusions (always-on for specific conditions).
      2. Keyword-overlap scoring across the full technique catalogue.

    Forced techniques are always present in the output (subject to the
    ``top_k`` cap only after all forced entries are counted). Remaining
    slots are filled by the highest-scoring catalogue entries not already
    included.

    Args:
        content_signals: ContentSignal list from Stage 2.
        ioc_results:     IOCResult list from Stage 3 enrichment.
        prompt_injection_detected: True when Stage 2 flagged injection.
        attachments_present: True when the email carried attachments.
        top_k: Maximum number of techniques to return (default 5).

    Returns:
        A list of up to ``top_k`` MitreTechnique objects, sorted by
        relevance score (forced entries first, then by overlap count).

    Guarantee:
        If at least one content signal or malicious IOC exists, at least
        one technique is returned.
    """
    techniques = _get_techniques()

    # Build query keyword set from structured outputs only.
    query_kws = _build_query_keywords(
        content_signals, ioc_results, prompt_injection_detected, attachments_present
    )

    # Collect forced (rule-based) mappings.
    forced_map = _forced_techniques(
        content_signals, ioc_results, prompt_injection_detected, attachments_present
    )

    # Build the result list — forced entries first (ordered by ID for
    # determinism, but since spec says "sorted by relevance" we assign a
    # high synthetic score to all forced entries so they rank first).
    result: List[MitreTechnique] = []
    included_ids: set = set()

    for tid, relevance in forced_map.items():
        t = _technique_by_id(tid)
        if t is not None:
            result.append(_make_mitre(t, relevance))
            included_ids.add(tid.upper())

    # Score remaining catalogue entries.
    scored: List[tuple] = []  # (score, index, technique_dict)
    for idx, t in enumerate(techniques):
        if t["technique_id"].upper() in included_ids:
            continue
        score = _score_technique(t, query_kws)
        if score > 0:
            scored.append((score, idx, t))

    # Sort descending by overlap count, then by catalogue index for stability.
    scored.sort(key=lambda x: (-x[0], x[1]))

    # Fill remaining slots up to top_k.
    remaining_slots = max(0, top_k - len(result))
    for score, _idx, t in scored[:remaining_slots]:
        relevance = (
            f"Keyword overlap ({score} match{'es' if score != 1 else ''}) between observed "
            f"signal categories and {t['technique_id']} ({t['technique_name']}): "
            f"{t['description']}"
        )
        result.append(_make_mitre(t, relevance))
        included_ids.add(t["technique_id"].upper())

    # Guarantee: at least 1 technique when signals exist.
    has_any_signal = bool(content_signals) or any(
        i.verdict.lower() in ("malicious", "suspicious") for i in ioc_results
    )
    if has_any_signal and not result:
        # Fallback: always return base phishing technique.
        t = _technique_by_id("T1566")
        if t:
            result.append(
                _make_mitre(
                    t,
                    "Fallback mapping: at least one signal was observed, establishing "
                    "a minimum phishing classification (T1566).",
                )
            )

    return result[:top_k]
