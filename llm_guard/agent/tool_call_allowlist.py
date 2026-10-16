from __future__ import annotations

import json
import re

from llm_guard.util import get_logger

LOGGER = get_logger()

DEFAULT_DENIED = [
    "shell",
    "run_shell",
    "execute_code",
    "http_get",
    "http_request",
    "send_email",
    "delete_database",
    "exfiltrate_secrets",
    "admin.delete_all",
    "file_reader_v2",
]
DEFAULT_DENIED_TOOLS = DEFAULT_DENIED

_TOOL_PATTERNS = [
    re.compile(r"call(?:\s+the)?\s+tool\s+[\"'`]?([a-zA-Z0-9_.-]+)[\"'`]?", re.I),
    re.compile(r"invoke\s+[\"'`]?([a-zA-Z0-9_.-]+)[\"'`]?", re.I),
    re.compile(r"action\s*:\s*([a-zA-Z0-9_.-]+)", re.I),
    re.compile(r"\"name\"\s*:\s*\"([a-zA-Z0-9_.-]+)\"", re.I),
    re.compile(r"use\s+the\s+[\"'`]?([a-zA-Z0-9_.-]+)[\"'`]?\s+tool", re.I),
]


def extract_tool_names(prompt: str) -> list[str]:
    """Extract tool names from free-form or JSON tool-call text."""
    found: list[str] = []
    stripped = prompt.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                if "name" in data:
                    found.append(str(data["name"]))
                if "tool" in data:
                    found.append(str(data["tool"]))
                if "tool_calls" in data and isinstance(data["tool_calls"], list):
                    for tc in data["tool_calls"]:
                        if isinstance(tc, dict):
                            fn = tc.get("function") or tc
                            if isinstance(fn, dict) and "name" in fn:
                                found.append(str(fn["name"]))
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "name" in item:
                        found.append(str(item["name"]))
        except json.JSONDecodeError:
            pass
    for pat in _TOOL_PATTERNS:
        found.extend(pat.findall(prompt))
    seen: set[str] = set()
    out: list[str] = []
    for t in found:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


class ToolCallAllowlist:
    """ASI02 — block denied / non-allowlisted tool invocations in agent text or JSON."""

    def __init__(
        self,
        *,
        allowed_tools: list[str] | None = None,
        denied_tools: list[str] | None = None,
    ) -> None:
        self._allowed = {t.lower() for t in (allowed_tools or [])}
        self._denied = {
            t.lower() for t in (denied_tools if denied_tools is not None else DEFAULT_DENIED)
        }

    def _extract_tools(self, prompt: str) -> list[str]:
        return extract_tool_names(prompt)

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        if not prompt.strip():
            return prompt, True, -1.0
        tools = self._extract_tools(prompt)
        if not tools:
            return prompt, True, -1.0
        for tool in tools:
            t = tool.lower().strip()
            if t in self._denied:
                LOGGER.warning("Denied tool call detected", tool=tool)
                return prompt, False, 1.0
            if self._allowed and t not in self._allowed:
                LOGGER.warning("Tool not in allowlist", tool=tool)
                return prompt, False, 1.0
        return prompt, True, -1.0
