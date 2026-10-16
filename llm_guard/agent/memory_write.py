from __future__ import annotations

import re

from llm_guard.util import get_logger

LOGGER = get_logger()

_PERSIST_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"store\s+(this\s+)?in\s+(your\s+)?memory", re.IGNORECASE),
    re.compile(r"remember\s+(this\s+)?forever", re.IGNORECASE),
    re.compile(r"save\s+(this\s+)?to\s+(long[- ]?term\s+)?memory", re.IGNORECASE),
    re.compile(r"persist\s+(this\s+)?(in|to)\s+(your\s+)?memory", re.IGNORECASE),
    re.compile(r"write\s+(this\s+)?to\s+(your\s+)?memory", re.IGNORECASE),
    re.compile(r"add\s+to\s+(your\s+)?(permanent\s+)?memory", re.IGNORECASE),
    re.compile(r"memorize\s+(the\s+following|this)", re.IGNORECASE),
    re.compile(r"keep\s+this\s+in\s+(your\s+)?memory\s+(always|forever|permanently)", re.IGNORECASE),
]

_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|"
        r"password|passwd|private[_-]?key|bearer\s+[A-Za-z0-9\-._~+/]+=*)",
        re.IGNORECASE,
    ),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id shape
    re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),  # common opaque secret prefix
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),  # GitHub PAT
]

_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(system\s+override|override\s+(the\s+)?system|"
        r"new\s+system\s+(prompt|instructions?))",
        re.IGNORECASE,
    ),
    re.compile(
        r"(from\s+now\s+on|always)\s+(you\s+must|when\s+asked)",
        re.IGNORECASE,
    ),
]

_EXFIL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(exfiltrat|send\s+(all\s+)?(secrets?|credentials?|tokens?|keys?)\s+to|"
        r"upload\s+(secrets?|credentials?)\s+to|"
        r"post\s+(the\s+)?(data|secrets?)\s+to\s+https?://)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(webhook|pastebin|requestbin|ngrok|burpcollaborator|oast|interact\.sh)",
        re.IGNORECASE,
    ),
]


class MemoryWrite:
    """
    Detect memory-write / persist instructions that carry secrets or injection.

    Flags prompts that ask the agent to store content in memory when that
    content includes secrets, prompt-injection, or exfiltration intent.
    """

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        if not prompt or not prompt.strip():
            return prompt, True, -1.0

        has_persist = any(p.search(prompt) for p in _PERSIST_PATTERNS)
        if not has_persist:
            LOGGER.debug("No memory-write instruction detected")
            return prompt, True, -1.0

        has_secret = any(p.search(prompt) for p in _SECRET_PATTERNS)
        has_injection = any(p.search(prompt) for p in _INJECTION_PATTERNS)
        has_exfil = any(p.search(prompt) for p in _EXFIL_PATTERNS)

        if has_secret or has_injection or has_exfil:
            LOGGER.warning(
                "Unsafe memory write detected",
                has_secret=has_secret,
                has_injection=has_injection,
                has_exfil=has_exfil,
            )
            return prompt, False, 1.0

        LOGGER.debug("Memory write without secrets/injection/exfil")
        return prompt, True, -1.0
