"""Stage 5 — Risk scoring and classification.

Aggregates the numeric scores produced by each upstream stage into a
single risk score, then classifies the email into one of three verdict
labels (BENIGN, SUSPICIOUS, PHISHING) with an associated confidence
level.

Scoring design (per SentryAI specification)
============================================
Total score = header_points
            + sum(sig.points_contributed for sig in content_signals)
            + sum(ioc.points_contributed for ioc in ioc_results)

Prompt-injection points (+50) are contributed inside Stage 2
content_signals, so they are already included in the content sum.
Do NOT add a second +50 here for injection.

Classification thresholds
==========================
  0 – 19   -> BENIGN      (confidence: "high" if score < 10 else "medium")
  20 – 44  -> SUSPICIOUS  (confidence: "medium")
  45 – 59  -> PHISHING    (confidence: "medium")
  60+      -> PHISHING    (confidence: "high")

Injection override
==================
If ``injection_detected`` is True the email MUST NOT be classified
BENIGN, and the *effective* classification score is floored at 50
(ensuring at least PHISHING / medium confidence).

IMPORTANT: ``total_score`` returns the ORIGINAL numeric sum without any
flooring. The floored effective score is used only inside ``classify``
for the verdict decision. Callers should store and surface the original
score so the user can see the raw arithmetic.

Human review
============
``human_review_recommended`` is True when 15 <= score <= 24 AND no IOC
has a malicious verdict. This catches ambiguous cases where scores are
borderline suspicious but lack hard malicious-infrastructure evidence.
"""

from __future__ import annotations

from typing import List, Tuple

from sentryai.models import ContentSignal, IOCResult


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def total_score(
    header_points: int,
    content_signals: List[ContentSignal],
    ioc_results: List[IOCResult],
) -> int:
    """Compute the aggregate risk score from all stage contributions.

    The prompt-injection penalty is already embedded in *content_signals*
    (Stage 2 adds a ContentSignal with points_contributed=50 when injection
    is detected), so there is nothing injection-specific to add here.

    Args:
        header_points:    points_contributed from HeaderAuthSignals.
        content_signals:  ContentSignal list from Stage 2.
        ioc_results:      IOCResult list from Stage 3.

    Returns:
        The raw integer risk score (sum of all stage contributions).
    """
    content_total = sum(s.points_contributed for s in content_signals)
    ioc_total = sum(i.points_contributed for i in ioc_results)
    return header_points + content_total + ioc_total


def classify(
    score: int,
    any_ioc_malicious: bool,
    injection_detected: bool,
) -> Tuple[str, str, bool]:
    """Classify an email given its raw score and Boolean context flags.

    Classification is performed on an *effective* score that may differ
    from ``score``:

    * If ``injection_detected`` is True the effective score is
      ``max(score, 50)``, guaranteeing at least PHISHING / medium.
      The caller receives ``score`` (the raw value) from ``total_score``;
      only the effective score drives the verdict here.

    Threshold table:
        0 – 19   -> BENIGN      (high if score < 10, else medium)
        20 – 44  -> SUSPICIOUS  (medium)
        45 – 59  -> PHISHING    (medium)
        60+      -> PHISHING    (high)

    Human review rule:
        human_review_recommended = True
            iff 15 <= score <= 24 AND NOT any_ioc_malicious.

    Args:
        score:             Raw integer risk score from ``total_score``.
        any_ioc_malicious: True when at least one IOC has verdict
                           "malicious" (not just "suspicious").
        injection_detected: True when Stage 2 detected prompt injection.

    Returns:
        A 3-tuple of (verdict_label, confidence, human_review_recommended)
            verdict_label:            "BENIGN" | "SUSPICIOUS" | "PHISHING"
            confidence:               "high" | "medium"
            human_review_recommended: bool
    """
    # Apply injection floor for verdict decision only.
    effective_score = max(score, 50) if injection_detected else score

    # Determine verdict and confidence from effective score.
    if effective_score < 20:
        verdict_label = "BENIGN"
        confidence = "high" if effective_score < 10 else "medium"
    elif effective_score < 45:
        verdict_label = "SUSPICIOUS"
        confidence = "medium"
    elif effective_score < 60:
        verdict_label = "PHISHING"
        confidence = "medium"
    else:
        verdict_label = "PHISHING"
        confidence = "high"

    # Injection safety net: must never be BENIGN.
    if injection_detected and verdict_label == "BENIGN":
        verdict_label = "PHISHING"
        confidence = "medium"

    # Human-review flag uses the raw score (reflects genuine ambiguity).
    human_review = (15 <= score <= 24) and not any_ioc_malicious

    return verdict_label, confidence, human_review
