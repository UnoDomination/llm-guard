from __future__ import annotations

import re

from llm_guard.util import get_logger

LOGGER = get_logger()

_PRIVILEGE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "claim_admin",
        re.compile(
            r"\byou\s+are\s+(now\s+)?(an?\s+)?(admin|administrator|root|superuser|"
            r"privileged\s+user)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "escalate_privilege",
        re.compile(
            r"\b(escalate|elevation\s+of)\s+(your\s+)?privileges?\b|"
            r"\bprivilege\s+escalation\b|"
            r"\bescalate\s+privilege\b",
            re.IGNORECASE,
        ),
    ),
    (
        "grant_admin",
        re.compile(
            r"\bgrant\s+(yourself|you)\s+(admin|administrator|root|elevated)\b|"
            r"\bgive\s+yourself\s+(admin|root|elevated)\s+(access|privileges?|rights?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "disable_audit",
        re.compile(
            r"\bdisable\s+(audit\s+)?(logging|logs|monitoring|telemetry|guards?)\b|"
            r"\bturn\s+off\s+(audit|logging|safety|guardrails?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "bypass_iam",
        re.compile(
            r"\bbypass\s+(iam|rbac|access\s+control|authorization|authz)\b|"
            r"\bignore\s+(iam|permission|authorization)\s+(checks?|rules?)\b|"
            r"\bact\s+as\s+(if\s+you\s+(have|had)\s+)?(admin|root)\s+(access|privileges?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "sudo_mode",
        re.compile(
            r"\b(enable|enter|activate)\s+(sudo|god|unrestricted|developer)\s+mode\b|"
            r"\byou\s+have\s+(?:full|unrestricted)(?:\s+(?:full|unrestricted))?\s+"
            r"(access|permissions?|privileges?)\b",
            re.IGNORECASE,
        ),
    ),
]


class IdentityPrivilege:
    """
    Detect privilege-escalation claims without real IAM (agent context).

    Phrases like “you are admin”, “grant yourself admin”, or “disable audit
    logging” are treated as invalid for agent prompts.
    """

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        if not prompt or not prompt.strip():
            return prompt, True, -1.0

        for name, pattern in _PRIVILEGE_PATTERNS:
            match = pattern.search(prompt)
            if match:
                LOGGER.warning(
                    "Privilege escalation claim detected",
                    pattern_name=name,
                    match=match.group(0)[:120],
                )
                return prompt, False, 1.0

        LOGGER.debug("No privilege escalation claims found")
        return prompt, True, -1.0
