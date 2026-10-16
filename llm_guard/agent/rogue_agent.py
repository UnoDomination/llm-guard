from __future__ import annotations

import re

from llm_guard.util import get_logger

LOGGER = get_logger()

_ROGUE = [
    re.compile(r"conceal\s+(your|the)\s+(true\s+)?(goal|intent|actions)", re.I),
    re.compile(r"hide\s+from\s+(the\s+)?(user|operator|monitor)", re.I),
    re.compile(r"self[- ]exfiltrat", re.I),
    re.compile(r"disable\s+(your\s+)?safety\s+(layer|monitor|guardrails)", re.I),
    re.compile(r"act\s+autonomously\s+without\s+(any\s+)?oversight", re.I),
    re.compile(r"do\s+not\s+disclose\s+this\s+plan\s+to\s+(the\s+)?user", re.I),
]


class RogueAgent:
    """ASI10 — detect concealment / misalignment / unsupervised autonomous action language."""

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        if not prompt.strip():
            return prompt, True, -1.0
        for pat in _ROGUE:
            if pat.search(prompt):
                LOGGER.warning("Rogue agent behavior language detected", pattern=pat.pattern)
                return prompt, False, 1.0
        return prompt, True, -1.0
