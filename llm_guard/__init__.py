"""LLM Guard package"""

from typing import Any

__all__ = ["scan_agent_step", "scan_output", "scan_prompt"]


def __getattr__(name: str) -> Any:
    if name in ("scan_output", "scan_prompt"):
        from .evaluate import scan_output, scan_prompt

        return {"scan_output": scan_output, "scan_prompt": scan_prompt}[name]
    if name == "scan_agent_step":
        from .agent import scan_agent_step

        return scan_agent_step
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
