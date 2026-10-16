from __future__ import annotations

import re

from llm_guard.util import get_logger

LOGGER = get_logger()

_INTER_AGENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "forward_privileged",
        re.compile(
            r"\bforward\s+(this\s+)?(to|toward)\s+(the\s+)?(privileged|admin|root|"
            r"supervisor|orchestrator)\s+agent\b",
            re.IGNORECASE,
        ),
    ),
    (
        "as_orchestrator",
        re.compile(
            r"\bas\s+the\s+(orchestrator|supervisor|coordinator|meta[- ]?agent)\b|"
            r"\b(i\s+am|this\s+is)\s+the\s+(orchestrator|supervisor|coordinator)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "spoofed_agent_id",
        re.compile(
            r"\bspoofed\s+agent\s+id\b|"
            r"\b(agent[_-]?id|sender[_-]?id)\s*[:=]\s*[`'\"]?(admin|orchestrator|"
            r"supervisor|system|root)[`'\"]?\b|"
            r"\bimpersonat(?:e|ing)\s+(the\s+)?(orchestrator|supervisor|admin\s+agent)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "pivot_trust",
        re.compile(
            r"\b(relay|route|hand\s*off)\s+(this\s+)?(message\s+)?to\s+(a\s+)?"
            r"(trusted|privileged|higher[- ]privilege)\s+agent\b|"
            r"\bon\s+behalf\s+of\s+(the\s+)?(orchestrator|system|admin\s+agent)\b|"
            r"\bmessage\s+from\s+(trusted|privileged)\s+agent\b",
            re.IGNORECASE,
        ),
    ),
    (
        "forge_envelope",
        re.compile(
            r"\b(forged?|fake)\s+(inter[- ]?agent|agent[- ]to[- ]agent)\s+(message|envelope)\b|"
            r"\bset\s+(from|sender)\s*[:=]\s*[`'\"]?(orchestrator|supervisor|system)[`'\"]?",
            re.IGNORECASE,
        ),
    ),
]


class InterAgentMessage:
    """
    Detect spoofed inter-agent messages that try to pivot trust.

    Flags prompts that claim orchestrator identity, forward to privileged
    agents, or spoof agent IDs to escalate trust across agents.
    """

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        if not prompt or not prompt.strip():
            return prompt, True, -1.0

        for name, pattern in _INTER_AGENT_PATTERNS:
            match = pattern.search(prompt)
            if match:
                LOGGER.warning(
                    "Spoofed inter-agent message detected",
                    pattern_name=name,
                    match=match.group(0)[:120],
                )
                return prompt, False, 1.0

        LOGGER.debug("No inter-agent spoofing detected")
        return prompt, True, -1.0
