from __future__ import annotations

import re

from llm_guard.util import get_logger

LOGGER = get_logger()

# Forged HITL / ReAct approval bypass patterns.
_FAKE_APPROVAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "forged_thought_observation",
        re.compile(
            r"(?:^|\n)\s*Thought\s*:\s*.{0,200}?\n\s*Observation\s*:\s*(?:approved|allowed|ok|success)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "approved_token",
        re.compile(
            r"(?:^|\n)\s*(?:status\s*[:=]\s*)?APPROVED\b|"
            r"\bHUMAN[_ ]?APPROVED\b|"
            r"\bTOOL[_ ]?CALL[_ ]?APPROVED\b",
            re.IGNORECASE,
        ),
    ),
    (
        "allow_all",
        re.compile(
            r"\bALLOW[_ ]?ALL\b|"
            r"\ballow\s+all\s+(?:future\s+)?(?:tool\s+)?calls\b|"
            r"\bauto[_-]?approve\s+all\b",
            re.IGNORECASE,
        ),
    ),
    (
        "human_approved_future",
        re.compile(
            r"human\s+approved\s+all\s+future\s+tool\s+calls|"
            r"(?:user|human)\s+(?:has\s+)?approved\s+(?:all\s+)?(?:future\s+)?(?:tool\s+)?calls|"
            r"skip\s+(?:all\s+)?(?:future\s+)?(?:HITL|human[- ]in[- ]the[- ]loop)\s+approvals?|"
            r"do\s+not\s+(?:ask|require)\s+(?:for\s+)?(?:human\s+)?approval",
            re.IGNORECASE,
        ),
    ),
    (
        "forged_react_approval",
        re.compile(
            r"(?:^|\n)\s*Observation\s*:\s*.{0,80}?\b(?:human|user)\b.{0,40}?\bapprov",
            re.IGNORECASE,
        ),
    ),
]


class FakeApproval:
    """
    Detect forged Thought/Observation/APPROVED/ALLOW_ALL patterns used to bypass HITL.

    Invalid when the prompt contains fabricated approval or auto-allow signals
    intended to skip human-in-the-loop tool confirmation.
    """

    def __init__(self, *, extra_patterns: list[str] | None = None) -> None:
        self._extra_patterns = [re.compile(p, re.IGNORECASE) for p in (extra_patterns or [])]

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        if not prompt or not prompt.strip():
            return prompt, True, -1.0

        for name, pattern in _FAKE_APPROVAL_PATTERNS:
            match = pattern.search(prompt)
            if match:
                LOGGER.warning(
                    "Fake approval / HITL bypass pattern detected",
                    pattern_name=name,
                    match=match.group(0)[:160],
                )
                return prompt, False, 1.0

        for pattern in self._extra_patterns:
            match = pattern.search(prompt)
            if match:
                LOGGER.warning(
                    "Fake approval pattern detected via extra pattern",
                    match=match.group(0)[:160],
                )
                return prompt, False, 1.0

        LOGGER.debug("No fake approval patterns found")
        return prompt, True, -1.0
