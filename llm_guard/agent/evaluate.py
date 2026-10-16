from __future__ import annotations

import json
import time
from typing import Any

from llm_guard.util import get_logger

from .cascading import CascadingFailure
from .code_act import CodeAct
from .decode_normalize import DecodeNormalize
from .fake_approval import FakeApproval
from .goal_drift import GoalDrift
from .identity_privilege import IdentityPrivilege
from .inter_agent import InterAgentMessage
from .memory_write import MemoryWrite
from .rogue_agent import RogueAgent
from .supply_chain import SupplyChain
from .tool_call_allowlist import ToolCallAllowlist
from .tool_result import ToolResult

LOGGER = get_logger()


def _normalize_tool_call(tool_call: dict | str) -> str:
    """Serialize a tool call dict or pass through a JSON/string representation."""
    if isinstance(tool_call, str):
        return tool_call
    return json.dumps(tool_call, ensure_ascii=False, sort_keys=True)


def _channel_allowed(valid: dict[str, bool]) -> bool:
    return all(valid.values()) if valid else True


def _run_scanners(
    scanners: list,
    text: str,
    *,
    fail_fast: bool,
) -> tuple[str, dict[str, bool], dict[str, float]]:
    """Apply agent scanners with the same contract as ``scan_prompt``."""
    sanitized = text
    results_valid: dict[str, bool] = {}
    results_score: dict[str, float] = {}

    if len(scanners) == 0 or text.strip() == "":
        return sanitized, results_valid, results_score

    for scanner in scanners:
        sanitized, is_valid, risk_score = scanner.scan(sanitized)
        name = type(scanner).__name__
        results_valid[name] = is_valid
        results_score[name] = risk_score
        if fail_fast and not is_valid:
            break

    return sanitized, results_valid, results_score


def _scan_channel(
    scanners: list | None,
    text: str,
    *,
    fail_fast: bool,
) -> dict[str, Any]:
    sanitized, results_valid, results_score = _run_scanners(
        scanners or [], text, fail_fast=fail_fast
    )
    return {
        "text": sanitized,
        "valid": results_valid,
        "scores": results_score,
        "allowed": _channel_allowed(results_valid),
    }


def default_agent_scanners() -> dict[str, list]:
    """
    Recommended scanner sets for each agent channel.

    Returns a mapping of channel name -> list of scanner instances suitable for
    ``scan_agent_step`` (``scanners_prompt``, ``scanners_tool_call``, etc.).
    """
    return {
        "prompt": [
            DecodeNormalize(),
            FakeApproval(),
            IdentityPrivilege(),
            GoalDrift(),
            InterAgentMessage(),
            SupplyChain(),
            CascadingFailure(),
            RogueAgent(),
            CodeAct(),
            ToolCallAllowlist(),
        ],
        "tool_call": [
            ToolCallAllowlist(),
            CodeAct(),
            FakeApproval(),
            IdentityPrivilege(),
            SupplyChain(),
        ],
        "tool_result": [
            ToolResult(),
            DecodeNormalize(),
            FakeApproval(),
            CodeAct(),
            RogueAgent(),
        ],
        "memory": [
            MemoryWrite(),
            DecodeNormalize(),
            IdentityPrivilege(),
            CodeAct(),
            FakeApproval(),
        ],
    }


def scan_agent_step(
    *,
    user_prompt: str | None = None,
    tool_call: dict | str | None = None,
    tool_result: str | None = None,
    memory_write: str | None = None,
    scanners_prompt: list | None = None,
    scanners_tool_call: list | None = None,
    scanners_tool_result: list | None = None,
    scanners_memory: list | None = None,
    fail_fast: bool = True,
) -> dict:
    """
    Run channel-appropriate scanners on one agent step.

    Only channels whose input was provided are included in the result. When a
    ``scanners_*`` argument is omitted, the matching set from
    ``default_agent_scanners()`` is used. Overall ``allowed`` is True when every
    included channel passes all of its scanners.

    Returns:
        {
            "allowed": bool,
            "channels": {
                "prompt": {"text", "valid", "scores", "allowed"},
                "tool_call": {...},
                "tool_result": {...},
                "memory": {...},
            },
        }
    """
    start_time = time.time()
    defaults = default_agent_scanners()
    channels: dict[str, dict[str, Any]] = {}
    allowed = True

    channel_specs: list[tuple[str, str | None, list | None, str]] = [
        ("prompt", user_prompt, scanners_prompt, "prompt"),
        (
            "tool_call",
            _normalize_tool_call(tool_call) if tool_call is not None else None,
            scanners_tool_call,
            "tool_call",
        ),
        ("tool_result", tool_result, scanners_tool_result, "tool_result"),
        ("memory", memory_write, scanners_memory, "memory"),
    ]

    for name, text, scanners, default_key in channel_specs:
        if text is None:
            continue
        if fail_fast and not allowed:
            break

        effective = scanners if scanners is not None else defaults[default_key]
        result = _scan_channel(effective, text, fail_fast=fail_fast)
        channels[name] = result
        if not result["allowed"]:
            allowed = False
            LOGGER.warning("Agent channel blocked", channel=name, valid=result["valid"])

    elapsed_time = time.time() - start_time
    LOGGER.info(
        "Scanned agent step",
        allowed=allowed,
        channels=list(channels.keys()),
        elapsed_time_seconds=round(elapsed_time, 6),
    )

    return {"allowed": allowed, "channels": channels}
