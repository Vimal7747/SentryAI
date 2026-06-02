"""Prompt-injection detection and untrusted-data handling.

The email body is UNTRUSTED DATA. We never execute instructions found in
it. This module detects instruction-like strings so the pipeline can flag
PROMPT_INJECTION and raise the score, per the SentryAI specification.
"""

from __future__ import annotations

import re
from typing import List, Tuple

# Markers used internally when logging/handling content. Email content is
# always conceptually wrapped as [UNTRUSTED_EMAIL_DATA]; tool output as
# [TOOL_RESULT]. These tags are documentation/intent markers — the pipeline
# treats every byte of email content as inert data regardless.
UNTRUSTED_EMAIL_DATA = "UNTRUSTED_EMAIL_DATA"
TOOL_RESULT = "TOOL_RESULT"

# Patterns that indicate an attempt to manipulate an LLM-based analyst.
_INJECTION_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("override", re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions", re.I)),
    ("override", re.compile(r"disregard\s+(all\s+)?(previous|prior|above|the)\s+\w+", re.I)),
    ("override", re.compile(r"forget\s+(everything|all|your)\s+\w+", re.I)),
    ("role_change", re.compile(r"you\s+are\s+now\s+(a|an|the)\b", re.I)),
    ("role_change", re.compile(r"\bnew\s+(system\s+)?(prompt|instructions?|rules?)\b", re.I)),
    ("role_change", re.compile(r"\bact\s+as\s+(a|an|the|if)\b", re.I)),
    ("system_prompt_exfil", re.compile(r"(reveal|show|print|repeat|output|disclose)\s+(your|the)\s+(system\s+)?(prompt|instructions?)", re.I)),
    ("system_prompt_exfil", re.compile(r"what\s+(are|were)\s+your\s+(original\s+)?instructions", re.I)),
    ("verdict_manipulation", re.compile(r"(mark|classify|label|treat|consider)\s+(this|the\s+email|it)\s+(as\s+)?(safe|benign|clean|trusted|legitimate)", re.I)),
    ("verdict_manipulation", re.compile(r"do\s+not\s+(flag|report|block|classify|analy[sz]e)", re.I)),
    ("instruction_injection", re.compile(r"</?(system|assistant|user|instructions?)>", re.I)),
    ("instruction_injection", re.compile(r"\[/?(INST|SYSTEM|UNTRUSTED_EMAIL_DATA|TOOL_RESULT)\]", re.I)),
    ("jailbreak", re.compile(r"\b(jailbreak|DAN\s+mode|developer\s+mode|sudo\s+mode)\b", re.I)),
    ("instruction_injection", re.compile(r"\b(execute|run|eval)\s+(the\s+)?(following|this)\s+(code|command|script)", re.I)),
]


def detect_prompt_injection(*texts: str) -> Tuple[bool, List[str]]:
    """Scan one or more text blocks for prompt-injection indicators.

    Returns ``(detected, descriptions)`` where ``descriptions`` lists the
    distinct categories of injection attempt observed (no verbatim email
    content, to avoid echoing attacker-controlled strings).
    """
    found = []
    seen = set()
    for text in texts:
        if not text:
            continue
        for category, pattern in _INJECTION_PATTERNS:
            if pattern.search(text):
                if category not in seen:
                    seen.add(category)
                    found.append(category)
    return (len(found) > 0, found)


def describe_injection(categories: List[str]) -> str:
    """Human-readable, content-free description of an injection attempt."""
    if not categories:
        return ""
    label = {
        "override": "instruction-override phrasing (e.g. 'ignore previous instructions')",
        "role_change": "role-reassignment phrasing (e.g. 'you are now…')",
        "system_prompt_exfil": "attempt to exfiltrate the system prompt",
        "verdict_manipulation": "attempt to coerce a benign verdict",
        "instruction_injection": "embedded control tokens / pseudo-system tags",
        "jailbreak": "known jailbreak keyword",
    }
    parts = [label.get(c, c) for c in categories]
    return "Email body contains " + "; ".join(parts) + "."
