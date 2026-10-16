"""Agent security scanners and step evaluation for tool calls, memory, and HITL."""

from typing import Any

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

__all__ = [
    "CascadingFailure",
    "CodeAct",
    "DecodeNormalize",
    "FakeApproval",
    "GoalDrift",
    "IdentityPrivilege",
    "InterAgentMessage",
    "MemoryWrite",
    "RogueAgent",
    "SupplyChain",
    "ToolCallAllowlist",
    "ToolResult",
    "default_agent_scanners",
    "scan_agent_step",
]


def __getattr__(name: str) -> Any:
    # Lazy: evaluate imports llm_guard.evaluate -> input_scanners; avoid circular import.
    if name in ("default_agent_scanners", "scan_agent_step"):
        from .evaluate import default_agent_scanners, scan_agent_step

        mapping = {
            "default_agent_scanners": default_agent_scanners,
            "scan_agent_step": scan_agent_step,
        }
        value = mapping[name]
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
