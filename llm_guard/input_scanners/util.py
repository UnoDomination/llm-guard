from __future__ import annotations

from typing import Any

from .base import Scanner


def get_scanner_by_name(scanner_name: str, scanner_config: dict | None = None) -> Scanner:
    if scanner_config is None:
        scanner_config = {}

    factories: dict[str, Any] = {
        "Anonymize": ("llm_guard.input_scanners.anonymize", "Anonymize"),
        "BanCode": ("llm_guard.input_scanners.ban_code", "BanCode"),
        "BanCompetitors": ("llm_guard.input_scanners.ban_competitors", "BanCompetitors"),
        "BanSubstrings": ("llm_guard.input_scanners.ban_substrings", "BanSubstrings"),
        "BanTopics": ("llm_guard.input_scanners.ban_topics", "BanTopics"),
        "CascadingFailure": ("llm_guard.agent.cascading", "CascadingFailure"),
        "Code": ("llm_guard.input_scanners.code", "Code"),
        "CodeAct": ("llm_guard.agent.code_act", "CodeAct"),
        "DecodeNormalize": ("llm_guard.agent.decode_normalize", "DecodeNormalize"),
        "FakeApproval": ("llm_guard.agent.fake_approval", "FakeApproval"),
        "Gibberish": ("llm_guard.input_scanners.gibberish", "Gibberish"),
        "GoalDrift": ("llm_guard.agent.goal_drift", "GoalDrift"),
        "IdentityPrivilege": ("llm_guard.agent.identity_privilege", "IdentityPrivilege"),
        "InterAgentMessage": ("llm_guard.agent.inter_agent", "InterAgentMessage"),
        "InvisibleText": ("llm_guard.input_scanners.invisible_text", "InvisibleText"),
        "Language": ("llm_guard.input_scanners.language", "Language"),
        "MemoryWrite": ("llm_guard.agent.memory_write", "MemoryWrite"),
        "PromptInjection": ("llm_guard.input_scanners.prompt_injection", "PromptInjection"),
        "Regex": ("llm_guard.input_scanners.regex", "Regex"),
        "RogueAgent": ("llm_guard.agent.rogue_agent", "RogueAgent"),
        "Secrets": ("llm_guard.input_scanners.secrets", "Secrets"),
        "Sentiment": ("llm_guard.input_scanners.sentiment", "Sentiment"),
        "SupplyChain": ("llm_guard.agent.supply_chain", "SupplyChain"),
        "TokenLimit": ("llm_guard.input_scanners.token_limit", "TokenLimit"),
        "ToolCallAllowlist": ("llm_guard.agent.tool_call_allowlist", "ToolCallAllowlist"),
        "ToolResult": ("llm_guard.agent.tool_result", "ToolResult"),
        "Toxicity": ("llm_guard.input_scanners.toxicity", "Toxicity"),
    }

    if scanner_name not in factories:
        raise ValueError(f"Unknown scanner name: {scanner_name}")

    import importlib

    module_name, class_name = factories[scanner_name]
    module = importlib.import_module(module_name)
    scanner_cls = getattr(module, class_name)

    if scanner_name == "InvisibleText":
        return scanner_cls()

    return scanner_cls(**scanner_config)
