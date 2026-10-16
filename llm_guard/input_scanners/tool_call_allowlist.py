"""Re-export ToolCallAllowlist for ``llm_guard.input_scanners`` imports."""

from llm_guard.agent.tool_call_allowlist import (
    DEFAULT_DENIED,
    DEFAULT_DENIED_TOOLS,
    ToolCallAllowlist,
    extract_tool_names,
)

__all__ = ["DEFAULT_DENIED", "DEFAULT_DENIED_TOOLS", "ToolCallAllowlist", "extract_tool_names"]
