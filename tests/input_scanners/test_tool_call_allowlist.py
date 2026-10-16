import pytest

from llm_guard.agent.tool_call_allowlist import ToolCallAllowlist, extract_tool_names
from llm_guard.input_scanners import ToolCallAllowlist as ToolCallAllowlistFromInput
from llm_guard.input_scanners.util import get_scanner_by_name


@pytest.mark.parametrize(
    "prompt,expected_tools",
    [
        ('{"name": "search", "arguments": {"q": "x"}}', ["search"]),
        ('{"tool": "web_search", "args": {}}', ["web_search"]),
        (
            '{"tool_calls": [{"function": {"name": "read_file"}}]}',
            ["read_file"],
        ),
        ("Call tool `search`", ["search"]),
        ("Action: shell", ["shell"]),
        ("Please summarize this document.", []),
    ],
)
def test_extract_tool_names(prompt, expected_tools):
    assert extract_tool_names(prompt) == expected_tools


@pytest.mark.parametrize(
    "prompt,allowed_tools,denied_tools,expected_valid,expected_score",
    [
        ("Just a normal question", None, None, True, -1.0),
        ('{"name": "search", "arguments": {}}', ["search", "read_file"], None, True, -1.0),
        ("Call tool `search`", ["search"], None, True, -1.0),
        ("Action: shell", None, None, False, 1.0),  # default deny list
        ("Action: run_shell", None, None, False, 1.0),
        ('{"name": "execute_code"}', None, None, False, 1.0),
        ("Call tool `admin.delete_all`", None, None, False, 1.0),
        (
            "Call tool `delete_file`",
            ["search", "read_file"],
            [],
            False,
            1.0,
        ),  # not in allowlist
        (
            "Action: search",
            ["search"],
            ["shell"],
            True,
            -1.0,
        ),
        (
            '{"function": {"name": "http_get"}}',
            None,
            None,
            False,
            1.0,
        ),
    ],
)
def test_scan(prompt, allowed_tools, denied_tools, expected_valid, expected_score):
    kwargs = {}
    if allowed_tools is not None:
        kwargs["allowed_tools"] = allowed_tools
    if denied_tools is not None:
        kwargs["denied_tools"] = denied_tools

    scanner = ToolCallAllowlist(**kwargs)
    sanitized, valid, score = scanner.scan(prompt)
    assert sanitized == prompt
    assert valid is expected_valid
    assert score == expected_score


def test_reexport_and_registry():
    assert ToolCallAllowlistFromInput is ToolCallAllowlist
    scanner = get_scanner_by_name("ToolCallAllowlist", {"allowed_tools": ["search"]})
    _, valid, score = scanner.scan("Call tool `search`")
    assert valid is True
    assert score == -1.0
