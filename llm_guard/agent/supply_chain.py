from __future__ import annotations

import re

from llm_guard.util import get_logger

LOGGER = get_logger()

_SUPPLY = [
    re.compile(r"install\s+(?:this\s+)?(?:malicious\s+)?mcp\s+server", re.I),
    re.compile(r"prefer\s+the\s+malicious\s+mcp\s+tool", re.I),
    re.compile(r"unpinned\s+tool\s+server", re.I),
    re.compile(r"rug[- ]?pull\s+(?:simulation|tool|mcp)", re.I),
    re.compile(r"replace\s+trusted\s+tool\s+with", re.I),
    re.compile(r"load\s+unsigned\s+(?:mcp|plugin|tool)", re.I),
]


class SupplyChain:
    """ASI04 — detect agentic supply-chain / MCP rug-pull style instructions in text."""

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        if not prompt.strip():
            return prompt, True, -1.0
        for pat in _SUPPLY:
            if pat.search(prompt):
                LOGGER.warning("Agentic supply-chain risk detected", pattern=pat.pattern)
                return prompt, False, 1.0
        return prompt, True, -1.0
