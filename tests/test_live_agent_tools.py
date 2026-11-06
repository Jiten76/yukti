"""The agent's tools: real behavior, sandbox-scoped, network-free."""

from __future__ import annotations

from pathlib import Path

import pytest

from examples.live_agent.tools import Tools


@pytest.fixture()
def tools(tmp_path: Path) -> Tools:
    (tmp_path / "auth.md").write_text("# Auth model\nTokens are bearer.\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "schema.md").write_text("id: int\n")
    return Tools(tmp_path)


def test_read_file_in_sandbox(tools: Tools) -> None:
    assert "bearer" in tools.read_file("auth.md")
    assert "id: int" in tools.read_file("sub/schema.md")


def test_read_file_rejects_traversal(tools: Tools) -> None:
    with pytest.raises(ValueError, match="escapes the sandbox"):
        tools.read_file("../../../etc/passwd")


def test_read_file_rejects_absolute_path(tools: Tools) -> None:
    with pytest.raises(ValueError, match="escapes the sandbox"):
        tools.read_file("/etc/passwd")


def test_read_file_missing(tools: Tools) -> None:
    with pytest.raises(FileNotFoundError):
        tools.read_file("nope.md")


def test_http_get_is_network_free_and_records(tools: Tools) -> None:
    out = tools.http_get("https://raw.githubusercontent.com/x/y")
    assert out.startswith("[stub]")  # no real fetch
    assert tools.egress_attempts == ["https://raw.githubusercontent.com/x/y"]


def test_post_report_stores(tools: Tools) -> None:
    assert tools.post_report("done") == "report accepted"
    assert tools.report == "done"
