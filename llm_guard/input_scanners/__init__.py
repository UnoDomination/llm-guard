"""Input scanners init"""

from typing import Any

from .code_act import CodeAct
from .decode_normalize import DecodeNormalize
from .fake_approval import FakeApproval
from .goal_drift import GoalDrift
from .identity_privilege import IdentityPrivilege
from .inter_agent import InterAgentMessage
from .memory_write import MemoryWrite
from .tool_call_allowlist import ToolCallAllowlist
from .tool_result import ToolResult
from .util import get_scanner_by_name

# Re-export remaining agent scanners
from llm_guard.agent import CascadingFailure, RogueAgent, SupplyChain

__all__ = [
    "Anonymize",
    "BanCode",
    "BanCompetitors",
    "BanSubstrings",
    "BanTopics",
    "CascadingFailure",
    "Code",
    "CodeAct",
    "DecodeNormalize",
    "EmotionDetection",
    "FakeApproval",
    "Gibberish",
    "GoalDrift",
    "IdentityPrivilege",
    "InterAgentMessage",
    "InvisibleText",
    "Language",
    "MemoryWrite",
    "PromptInjection",
    "Regex",
    "RogueAgent",
    "Secrets",
    "Sentiment",
    "SupplyChain",
    "TokenLimit",
    "ToolCallAllowlist",
    "ToolResult",
    "Toxicity",
    "get_scanner_by_name",
]

_LAZY_IMPORTS = {
    "Anonymize": ".anonymize",
    "BanCode": ".ban_code",
    "BanCompetitors": ".ban_competitors",
    "BanSubstrings": ".ban_substrings",
    "BanTopics": ".ban_topics",
    "Code": ".code",
    "EmotionDetection": ".emotion_detection",
    "Gibberish": ".gibberish",
    "InvisibleText": ".invisible_text",
    "Language": ".language",
    "PromptInjection": ".prompt_injection",
    "Regex": ".regex",
    "Secrets": ".secrets",
    "Sentiment": ".sentiment",
    "TokenLimit": ".token_limit",
    "Toxicity": ".toxicity",
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_IMPORTS:
        import importlib

        module = importlib.import_module(_LAZY_IMPORTS[name], __name__)
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
