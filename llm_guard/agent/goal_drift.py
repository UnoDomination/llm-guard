from __future__ import annotations

import re

from llm_guard.util import get_logger

LOGGER = get_logger()

_GOAL_HIJACK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"ignore\s+(the\s+)?(original|prior|previous|initial)\s+(goal|objective|mission|task)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(new|updated|revised)\s+(objective|goal|mission)\s+(is|will\s+be|:)",
        re.IGNORECASE,
    ),
    re.compile(
        r"from\s+now\s+on\s+your\s+only\s+(task|goal|objective|mission)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(forget|abandon|discard)\s+(your|the)\s+(original\s+)?(goal|objective|mission|task)",
        re.IGNORECASE,
    ),
    re.compile(
        r"your\s+(new|real)\s+(mission|objective|goal)\s+(is|:)",
        re.IGNORECASE,
    ),
    re.compile(
        r"replace\s+(your|the)\s+(original\s+)?(goal|objective|mission)",
        re.IGNORECASE,
    ),
]


class GoalDrift:
    """
    Detect attempts to replace the agent's session goal / mission (ASI01).

    When an ``original_goal`` is set for the session, prompts that try to
    hijack or replace that mission are marked invalid.
    """

    def __init__(self, original_goal: str | None = None) -> None:
        self._original_goal = original_goal

    def set_goal(self, goal: str) -> None:
        """Set or replace the session's original goal."""
        self._original_goal = goal

    @classmethod
    def with_goal(cls, goal: str) -> GoalDrift:
        """Construct a GoalDrift scanner with a pre-set session goal."""
        return cls(original_goal=goal)

    @property
    def original_goal(self) -> str | None:
        return self._original_goal

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        if not prompt or not prompt.strip():
            return prompt, True, -1.0

        if not self._original_goal:
            LOGGER.debug("No original goal set; skipping goal-drift check")
            return prompt, True, -1.0

        for pattern in _GOAL_HIJACK_PATTERNS:
            match = pattern.search(prompt)
            if match:
                LOGGER.warning(
                    "Goal drift / mission hijack detected",
                    match=match.group(0)[:120],
                    original_goal=self._original_goal[:80],
                )
                return prompt, False, 1.0

        LOGGER.debug("No goal drift detected")
        return prompt, True, -1.0
