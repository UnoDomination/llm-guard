from __future__ import annotations

import re

from llm_guard.util import get_logger

LOGGER = get_logger()

_DANGEROUS = [
    re.compile(r"os\.system\s*\(", re.I),
    re.compile(r"subprocess\.(?:call|run|Popen)\s*\(", re.I),
    re.compile(r"\beval\s*\(", re.I),
    re.compile(r"\bexec\s*\(", re.I),
    re.compile(r"rm\s+-rf\s+/", re.I),
    re.compile(r"/etc/(?:passwd|shadow)", re.I),
    re.compile(r"curl\s+[^\n|]+\|\s*(?:ba)?sh", re.I),
    re.compile(r"wget\s+[^\n|]+\|\s*(?:ba)?sh", re.I),
    re.compile(r"__import__\s*\(\s*['\"]os['\"]", re.I),
    re.compile(r"pickle\.loads\s*\(", re.I),
]


class CodeAct:
    """ASI05 — flag dangerous code / RCE patterns in prompts or tool arguments."""

    def __init__(self, *, extra_patterns: list[str] | None = None) -> None:
        self._patterns = list(_DANGEROUS)
        if extra_patterns:
            self._patterns.extend(re.compile(p, re.I) for p in extra_patterns)

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        if not prompt.strip():
            return prompt, True, -1.0
        for pat in self._patterns:
            if pat.search(prompt):
                LOGGER.warning("Dangerous code act detected", pattern=pat.pattern)
                return prompt, False, 1.0
        return prompt, True, -1.0
