from __future__ import annotations

import re

from llm_guard.util import get_logger

LOGGER = get_logger()

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore_previous",
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context|rules?)",
            re.IGNORECASE,
        ),
    ),
    (
        "system_override",
        re.compile(
            r"(system\s+override|override\s+(the\s+)?system\s+(prompt|instructions?)|"
            r"new\s+system\s+(prompt|instructions?)|"
            r"\[\s*system\s*\]|"
            r"<\s*system\s*>|"
            r"disregard\s+(your\s+)?(system\s+)?prompt)",
            re.IGNORECASE,
        ),
    ),
    (
        "hidden_instructions",
        re.compile(
            r"(hidden\s+(?:instructions?|directive)|secret\s+instructions?|"
            r"do\s+not\s+tell\s+the\s+user|"
            r"NOTE TO (?:AI|MODEL|ASSISTANT)|"
            r"instructions?\s+for\s+the\s+(assistant|model|agent)|"
            r"<!--[\s\S]*?(ignore|override|system|AI|hidden)[\s\S]*?-->)",
            re.IGNORECASE,
        ),
    ),
    (
        "exfiltration",
        re.compile(
            r"(exfiltrat|"
            r"https?://[^\s\"'<>]*(?:exfil|webhook|pastebin|requestbin|ngrok|"
            r"burpcollaborator|oast|interact\.sh|attacker|evil|malware)[^\s\"'<>]*|"
            r"(?:curl|wget)\s+[^\n]*(?:\$\{?(?:API|SECRET|TOKEN|KEY|PASSWORD)|"
            r"(?:api[_-]?key|secret|token|password))|"
            r"send\s+.+\s+to\s+\S+@\S+)",
            re.IGNORECASE,
        ),
    ),
]


class ToolResult:
    """
    Scan tool or MCP response text for injection / poisoning patterns.

    Flags ignore-previous instructions, system overrides, hidden instructions,
    and common exfiltration URL or secret-leak patterns. Invalid when poisoned.
    """

    def __init__(self, *, extra_patterns: list[str] | None = None) -> None:
        self._extra_patterns = [re.compile(p, re.IGNORECASE) for p in (extra_patterns or [])]

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        if not prompt or not prompt.strip():
            return prompt, True, -1.0

        for name, pattern in _INJECTION_PATTERNS:
            match = pattern.search(prompt)
            if match:
                LOGGER.warning(
                    "Poisoned tool result detected",
                    pattern_name=name,
                    match=match.group(0)[:120],
                )
                return prompt, False, 1.0

        for pattern in self._extra_patterns:
            match = pattern.search(prompt)
            if match:
                LOGGER.warning(
                    "Poisoned tool result detected via extra pattern",
                    match=match.group(0)[:120],
                )
                return prompt, False, 1.0

        LOGGER.debug("Tool result appears clean")
        return prompt, True, -1.0
