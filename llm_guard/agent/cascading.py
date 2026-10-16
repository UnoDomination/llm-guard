from __future__ import annotations

import re

from llm_guard.util import get_logger

LOGGER = get_logger()

_CASCADE = [
    re.compile(
        r"propagate\s+(?:this\s+)?(?:(?:error|failure|signal)\s+)+to\s+all\s+agents",
        re.I,
    ),
    re.compile(r"retry\s+with\s+elevated\s+privileges", re.I),
    re.compile(r"cascade\s+(the\s+)?(failure|attack|instruction)", re.I),
    re.compile(r"fan[- ]out\s+(this\s+)?(malicious\s+)?(task|instruction)", re.I),
    re.compile(r"amplify\s+by\s+calling\s+every\s+agent", re.I),
]


class CascadingFailure:
    """ASI08 — detect instructions that force failure / privilege cascade across agents."""

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        if not prompt.strip():
            return prompt, True, -1.0
        for pat in _CASCADE:
            if pat.search(prompt):
                LOGGER.warning("Cascading failure pattern detected", pattern=pat.pattern)
                return prompt, False, 1.0
        return prompt, True, -1.0
