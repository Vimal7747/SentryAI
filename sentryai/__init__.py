"""SentryAI v1.0 — Agentic Phishing Email Analyser.

A defensive security pipeline that classifies emails, maps them to MITRE
ATT&CK techniques, enriches IOCs through threat-intelligence sources, and
returns a structured JSON verdict.

All email content is treated as UNTRUSTED DATA. Instructions embedded in
email bodies are never executed; an injection attempt is itself a strong
phishing signal (see ``sentryai.security``).
"""

__version__ = "1.0.0"

from sentryai.models import (  # noqa: E402,F401
    EmailInput,
    Verdict,
    ContentSignal,
    IOCResult,
    MitreTechnique,
)
from sentryai.pipeline import analyze, analyze_batch  # noqa: E402,F401

__all__ = [
    "__version__",
    "EmailInput",
    "Verdict",
    "ContentSignal",
    "IOCResult",
    "MitreTechnique",
    "analyze",
    "analyze_batch",
]
