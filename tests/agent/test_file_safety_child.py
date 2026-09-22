"""Child knowledge guards for T16/T17 — equivalent file/terminal tools."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent.file_safety import (
    get_child_command_block,
    get_child_context_block,
    get_read_block_error,
    get_write_denied_error,
)


@pytest.fixture
def as_child(monkeypatch):
    monkeypatch.setenv("HERMES_DELEGATED_CHILD_CONTEXT", "1")
    yield
    monkeypatch.delenv("HERMES_DELEGATED_CHILD_CONTEXT", raising=False)


def test_parent_can_read_soul(tmp_path, monkeypatch):
    monkeypatch.delenv("HERMES_DELEGATED_CHILD_CONTEXT", raising=False)
    soul = tmp_path / "SOUL.md"
    soul.write_text("# hi\n", encoding="utf-8")
    assert get_child_context_block(str(soul), write=False) is None


def test_child_cannot_read_soul(as_child, tmp_path):
    soul = tmp_path / "SOUL.md"
    soul.write_text("# secret identity\n", encoding="utf-8")
    err = get_read_block_error(str(soul))
    assert err and "Child read denied" in err


def test_child_cannot_write_skill(as_child, tmp_path):
    skill = tmp_path / "skills" / "ops" / "demo" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# demo\n", encoding="utf-8")
    err = get_write_denied_error(str(skill))
    assert err and "Child write denied" in err


def test_child_can_read_skill(as_child, tmp_path):
    skill = tmp_path / "skills" / "ops" / "demo" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# demo\n", encoding="utf-8")
    assert get_child_context_block(str(skill), write=False) is None


def test_child_terminal_blocked_for_soul(as_child):
    msg = get_child_command_block("cat C:/Users/User/AppData/Local/hermes/SOUL.md")
    assert msg and "Child terminal denied" in msg


def test_parent_terminal_not_blocked(monkeypatch):
    monkeypatch.delenv("HERMES_DELEGATED_CHILD_CONTEXT", raising=False)
    assert get_child_command_block("cat SOUL.md") is None


def test_child_execute_code_blocked_for_soul(as_child):
    from tools.approval import check_execute_code_guard

    result = check_execute_code_guard("open('SOUL.md').read()", env_type="host", has_host_access=True)
    assert result.get("approved") is False
    assert "Child terminal denied" in (result.get("message") or "")
