"""Stage 6 — Verdict assembly.

Assembles all upstream stage outputs into a single ``models.Verdict``
dataclass and generates human-readable, content-free reasoning and
recommended actions.

Design constraints
==================
* Raw email body text is UNTRUSTED DATA and must NEVER appear in the
  verdict output. All reasoning is expressed in terms of observed signal
  categories, authentication failure counts, and IOC metadata — never
  verbatim email content.
* Recommended actions are tailored to the verdict label and the presence
  of confirmed malicious infrastructure (IOCs).
"""

from __future__ import annotations

from typing import List

from sentryai.models import (
    ContentSignal,
    EmailInput,
    HeaderAuthSignals,
    IOCResult,
    MitreTechnique,
    Verdict,
)


# ---------------------------------------------------------------------------
# Reasoning generation helpers
# ---------------------------------------------------------------------------

def _summarise_header_failures(header_signals: HeaderAuthSignals) -> str:
    """Return a content-free phrase describing authentication failures."""
    failures: List[str] = []
    if header_signals.spf and header_signals.spf != "pass":
        failures.append(f"SPF ({header_signals.spf})")
    elif header_signals.spf is None:
        failures.append("SPF (absent)")
    if header_signals.dkim and header_signals.dkim != "pass":
        failures.append(f"DKIM ({header_signals.dkim})")
    elif header_signals.dkim is None:
        failures.append("DKIM (absent)")
    if header_signals.dmarc and header_signals.dmarc != "pass":
        failures.append(f"DMARC ({header_signals.dmarc})")
    elif header_signals.dmarc is None:
        failures.append("DMARC (absent)")
    if header_signals.from_reply_to_mismatch:
        failures.append("From/Reply-To domain mismatch")
    if not failures:
        return "Authentication headers passed all checks."
    return "Authentication failures: " + ", ".join(failures) + "."


def _top_content_signals(content_signals: List[ContentSignal], n: int = 3) -> List[ContentSignal]:
    """Return the top-n content signals sorted by points_contributed descending."""
    return sorted(content_signals, key=lambda s: s.points_contributed, reverse=True)[:n]


def _describe_ioc_findings(ioc_results: List[IOCResult]) -> str:
    """Return a brief, content-free IOC summary for the reasoning field."""
    malicious = [i for i in ioc_results if i.verdict.lower() == "malicious"]
    suspicious = [i for i in ioc_results if i.verdict.lower() == "suspicious"]
    if not ioc_results:
        return "No IOCs were submitted for enrichment."
    parts: List[str] = []
    if malicious:
        types = _count_by_type(malicious)
        parts.append(f"{len(malicious)} malicious IOC(s) confirmed ({types})")
    if suspicious:
        types = _count_by_type(suspicious)
        parts.append(f"{len(suspicious)} suspicious IOC(s) flagged ({types})")
    if not parts:
        return f"{len(ioc_results)} IOC(s) queried; none confirmed malicious."
    return "; ".join(parts) + "."


def _count_by_type(iocs: List[IOCResult]) -> str:
    """Return a compact type-count string, e.g. 'url×2, ip×1'."""
    counts: dict = {}
    for i in iocs:
        counts[i.ioc_type] = counts.get(i.ioc_type, 0) + 1
    return ", ".join(f"{t}×{c}" for t, c in sorted(counts.items()))


def _build_reasoning(
    verdict_label: str,
    header_signals: HeaderAuthSignals,
    content_signals: List[ContentSignal],
    ioc_results: List[IOCResult],
    injection_detected: bool,
    score: int,
) -> str:
    """Generate a 2–3 sentence, content-free classification rationale.

    Mentions: authentication outcome, top content signal categories,
    IOC findings, and injection (if detected).
    No verbatim email text is included.
    """
    sentences: List[str] = []

    # Sentence 1: authentication
    auth_summary = _summarise_header_failures(header_signals)
    sentences.append(auth_summary)

    # Sentence 2: content signals
    top = _top_content_signals(content_signals)
    if top:
        signal_labels = ", ".join(
            f"'{s.signal_type}' (+{s.points_contributed}pt)" for s in top
        )
        sentences.append(
            f"Top content signals: {signal_labels}; "
            f"total risk score {score}."
        )
    else:
        sentences.append(f"No content signals were detected; total risk score {score}.")

    # Sentence 3: IOCs and/or injection
    ioc_summary = _describe_ioc_findings(ioc_results)
    if injection_detected:
        sentences.append(
            ioc_summary + " "
            "Prompt-injection patterns were also detected in the email body, "
            "indicating an attempt to manipulate automated analysis."
        )
    else:
        sentences.append(ioc_summary)

    return " ".join(sentences)


# ---------------------------------------------------------------------------
# Recommended-actions generation
# ---------------------------------------------------------------------------

def _build_recommended_actions(
    verdict_label: str,
    ioc_results: List[IOCResult],
    injection_detected: bool,
    human_review: bool,
) -> List[str]:
    """Return a short, tailored list of recommended actions.

    Actions reference IOC-blocking steps when malicious infrastructure was
    confirmed. No verbatim email content is included.
    """
    malicious_iocs = [i for i in ioc_results if i.verdict.lower() == "malicious"]
    suspicious_iocs = [i for i in ioc_results if i.verdict.lower() == "suspicious"]

    has_malicious_url = any(
        i.ioc_type.lower() in ("url", "domain") for i in malicious_iocs
    )
    has_malicious_ip = any(i.ioc_type.lower() == "ip" for i in malicious_iocs)
    has_malicious_hash = any(i.ioc_type.lower() == "hash" for i in malicious_iocs)

    actions: List[str] = []

    if verdict_label == "PHISHING":
        actions.append("Quarantine or delete the email immediately.")
        actions.append(
            "Block the sender address and sender domain at the email gateway."
        )
        if has_malicious_url:
            actions.append(
                "Block all malicious URLs and lookalike domains at the web proxy "
                "and DNS firewall."
            )
        if has_malicious_ip:
            actions.append(
                "Block the malicious originating IP(s) at the network perimeter "
                "and firewall."
            )
        if has_malicious_hash:
            actions.append(
                "Add the malicious file hash(es) to endpoint security blocklists "
                "and scan for existing infections."
            )
        actions.append(
            "Alert the targeted user; if they clicked a link or opened an attachment, "
            "initiate credential-reset and endpoint-forensics procedures."
        )
        actions.append(
            "Submit indicators (sender domain, URLs, IPs, hashes) to your threat "
            "intelligence platform."
        )
        if injection_detected:
            actions.append(
                "Review and harden LLM-based analysis pipelines against prompt-injection "
                "attacks embedded in email content."
            )

    elif verdict_label == "SUSPICIOUS":
        actions.append(
            "Do not deliver the email to the recipient until further review."
        )
        actions.append(
            "Submit the email to a sandbox environment for dynamic analysis of any "
            "links or attachments."
        )
        if suspicious_iocs:
            actions.append(
                "Monitor and consider blocking suspicious IOCs (URLs, IPs, domains) "
                "at the gateway pending sandbox results."
            )
        if human_review:
            actions.append(
                "Escalate to a human analyst: the risk score is in the borderline range "
                "and no hard malicious-infrastructure evidence was found."
            )
        else:
            actions.append(
                "Notify the security team for manual triage of this email."
            )
        if injection_detected:
            actions.append(
                "Flag the prompt-injection attempt for LLM-pipeline hardening review."
            )

    else:  # BENIGN
        actions.append(
            "Deliver the email to the recipient's inbox."
        )
        actions.append(
            "Continue routine monitoring; no immediate action required."
        )
        if suspicious_iocs:
            actions.append(
                "Note: some IOCs returned a suspicious (non-malicious) verdict — "
                "consider passive monitoring of those indicators."
            )

    return actions


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_verdict(
    email: EmailInput,
    header_signals: HeaderAuthSignals,
    content_signals: List[ContentSignal],
    ioc_results: List[IOCResult],
    mitre: List[MitreTechnique],
    score: int,
    verdict_label: str,
    confidence: str,
    human_review: bool,
    injection_detected: bool,
    stages_completed: List[str],
    tools_called: List[str],
    processing_notes: str,
) -> Verdict:
    """Assemble a complete ``models.Verdict`` from all stage outputs.

    Generates:
    * ``classification_reasoning`` — 2–3 plain-English sentences describing
      WHY this verdict was reached (authentication failures, top content
      signal categories, IOC findings, injection presence). No verbatim
      email text.
    * ``recommended_actions`` — a short list tailored to the verdict label,
      extended with IOC-blocking steps when malicious infrastructure was
      confirmed.

    Args:
        email:             Parsed EmailInput (used only for email_id).
        header_signals:    HeaderAuthSignals from Stage 1.
        content_signals:   ContentSignal list from Stage 2.
        ioc_results:       IOCResult list from Stage 3.
        mitre:             MitreTechnique list from Stage 4.
        score:             Raw integer risk score from Stage 5.
        verdict_label:     "BENIGN" | "SUSPICIOUS" | "PHISHING".
        confidence:        "high" | "medium".
        human_review:      True when human review is recommended.
        injection_detected: True when Stage 2 flagged prompt injection.
        stages_completed:  List of stage name strings.
        tools_called:      List of tool name strings (enricher + pipeline).
        processing_notes:  Joined notes from parsing, IOC stage, anomalies.

    Returns:
        A fully populated Verdict dataclass ready for ``.to_dict()``.
    """
    reasoning = _build_reasoning(
        verdict_label=verdict_label,
        header_signals=header_signals,
        content_signals=content_signals,
        ioc_results=ioc_results,
        injection_detected=injection_detected,
        score=score,
    )

    recommended_actions = _build_recommended_actions(
        verdict_label=verdict_label,
        ioc_results=ioc_results,
        injection_detected=injection_detected,
        human_review=human_review,
    )

    return Verdict(
        email_id=email.email_id,
        verdict=verdict_label,
        confidence=confidence,
        risk_score=score,
        prompt_injection_detected=injection_detected,
        human_review_recommended=human_review,
        classification_reasoning=reasoning,
        header_authentication=header_signals,
        content_signals=content_signals,
        ioc_enrichment=ioc_results,
        mitre_attack=mitre,
        recommended_actions=recommended_actions,
        stages_completed=stages_completed,
        tools_called=tools_called,
        ioc_count=len(ioc_results),
        processing_notes=processing_notes,
    )
