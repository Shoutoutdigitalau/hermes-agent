"""HTS-03 execution-seam tests: agent parse/dispatch guards and invoke_tool.

Exercises the real agent paths (tool_executor._parse_tool_call,
_resolve_sequential_dispatch, agent_runtime_helpers.invoke_tool) against a
temp HERMES_HOME with synthetic identities. Covers the inline, delegate,
context-engine and memory-provider branches in both sequential and
concurrent shapes: every branch denies before dispatch for governed
non-owners on protected calls, with zero backend calls.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent import team_authz
from agent.team_authz import RequesterContext, bind_requester, reset_requester

OWNER_ID = "900000000000000001"
MANAGER_ID = "900000000000000002"
AM_ID = "900000000000000003"
OUTSIDER_ID = "900000000000000009"

GUILD = "910000000000000001"


def _ctx(uid, *, chat="920000000000000099") -> RequesterContext:
    return RequesterContext(platform="discord", user_id=uid, scope_id=GUILD,
                            chat_id=chat, chat_type="dm")


CTX_OWNER = _ctx(OWNER_ID, chat="920000000000000001")
CTX_AM = _ctx(AM_ID, chat="920000000000000003")
CTX_OUTSIDER = _ctx(OUTSIDER_ID)


@contextmanager
def bound(ctx):
    token = bind_requester(ctx)
    try:
        yield ctx
    finally:
        reset_requester(token)


def _member(uid, key, role, status="active"):
    return {"discordUserId": uid, "memberKey": key, "role": role, "status": status,
            "approvedBy": "", "approvedAt": "2026-01-01T00:00:00+00:00"}


def _base_register():
    return {
        "schemaVersion": 1,
        "policyVersion": "2026.09.17-hts03exec",
        "guilds": [GUILD],
        "members": [
            _member(OWNER_ID, "charles", "owner"),
            _member(MANAGER_ID, "bettina", "manager"),
            _member(AM_ID, "lianna", "account_manager"),
        ],
        "roles": {
            "owner": {"capabilities": ["basic", "web.read", "delegate", "owner.host"]},
            "manager": {"capabilities": ["basic", "web.read", "delegate"]},
            "account_manager": {"capabilities": ["basic", "web.read", "delegate"]},
        },
        "toolActions": [],
        "connections": [],
        "spendingCaps": [],
        "oversight": {"destinations": []},
    }


CONFIG_ENABLED = "team_authz:\n  enabled: true\n  governed_platforms: [\"discord\"]\n"
CONFIG_DISABLED = "team_authz:\n  enabled: false\n"


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "hermes-home"
    h.mkdir()
    (h / "config.yaml").write_text(CONFIG_ENABLED, encoding="utf-8")
    d = h / "team_authz"
    d.mkdir(parents=True, exist_ok=True)
    (d / "register.json").write_text(json.dumps(_base_register()), encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(h))
    # Reserved example domains resolve synthetically; never query live DNS.
    monkeypatch.setattr("tools.url_safety._getaddrinfo",
                        lambda *a, **kw: [(2, 1, 6, "", ("8.8.8.8", 443))])
    team_authz._REGISTER_CACHE.clear()
    yield h
    team_authz._REGISTER_CACHE.clear()


def _tool_call(name, args):
    return SimpleNamespace(function=SimpleNamespace(name=name, arguments=json.dumps(args)),
                           id="call-hts03")


def _agent(**kw):
    base = dict(session_id="sess-hts03",
                valid_tool_names=["web_search", "terminal", "browser_navigate",
                                  "browser_vault_fill", "todo_list", "delegate_task"],
                enabled_toolsets=None, disabled_toolsets=None, quiet_mode=False,
                _context_engine_tool_names=[], _memory_manager=None,
                _current_turn_id="", _current_api_request_id="",
                _should_emit_quiet_tool_messages=lambda: False,
                _should_start_quiet_spinner=lambda: False)
    base.update(kw)
    return SimpleNamespace(**base)


class TestParseScopeBlock:
    def test_member_terminal_allowed(self, home):
        from agent.tool_executor import _parse_tool_call
        with bound(CTX_AM):
            pc = _parse_tool_call(None, _tool_call("terminal", {"command": "id"}))
        assert pc.parse_error is None
        assert pc.scope_block is None

    def test_member_vault_blocked(self, home):
        from agent.tool_executor import _parse_tool_call
        with bound(CTX_AM):
            pc = _parse_tool_call(None, _tool_call("browser_vault_fill", {"handle": "h"}))
        assert "protected:credentials" in (pc.scope_block or "")

    def test_member_ordinary_allowed(self, home):
        from agent.tool_executor import _parse_tool_call
        with bound(CTX_AM):
            assert _parse_tool_call(None, _tool_call("web_search", {"q": "x"})).scope_block is None
            assert _parse_tool_call(None, _tool_call("todo_list", {})).scope_block is None
            assert _parse_tool_call(None, _tool_call("delegate_task", {})).scope_block is None
            # Host tools are ordinary work for a registered teammate (T1).
            assert _parse_tool_call(None, _tool_call("terminal", {"command": "id"})).scope_block is None

    def test_denied_principal_blocked_every_branch(self, home):
        from agent.tool_executor import _parse_tool_call
        with bound(CTX_OUTSIDER):
            for name in ("terminal", "delegate_task", "todo_list", "web_search",
                         "ce_probe", "mem_probe"):
                pc = _parse_tool_call(None, _tool_call(name, {}))
                assert pc.scope_block is not None, name
                assert "unknown-identity" in pc.scope_block, name

    def test_spoofed_owner_flag_ignored(self, home):
        from agent.tool_executor import _parse_tool_call
        with bound(CTX_AM):
            pc = _parse_tool_call(None, _tool_call(
                "browser_vault_fill", {"handle": "h", "is_owner": True, "role": "owner"}))
        assert "protected:credentials" in (pc.scope_block or "")

    def test_bridge_call_parses_as_ordinary(self, home):
        from agent.tool_executor import _parse_tool_call
        with bound(CTX_AM):
            pc = _parse_tool_call(None, _tool_call("tool_search", {"query": "x"}))
        assert pc.parse_error is None
        assert pc.scope_block is None

    def test_ungoverned_baseline(self, tmp_path, monkeypatch):
        from agent.tool_executor import _parse_tool_call
        h = tmp_path / "open"
        h.mkdir()
        (h / "config.yaml").write_text(CONFIG_DISABLED, encoding="utf-8")
        d = h / "team_authz"
        d.mkdir(parents=True, exist_ok=True)
        (d / "register.json").write_text(json.dumps(_base_register()), encoding="utf-8")
        monkeypatch.setenv("HERMES_HOME", str(h))
        team_authz._REGISTER_CACHE.clear()
        with bound(CTX_AM):
            pc = _parse_tool_call(None, _tool_call("terminal", {"command": "id"}))
        assert pc.scope_block is None


class TestSequentialDispatchWrap:
    def test_registry_deny_precedes_inner_dispatch(self, home, monkeypatch):
        from agent.tool_executor import _ToolCallRef, _resolve_sequential_dispatch, _team_authz_guarded_execute

        def boom(*a, **k):
            raise AssertionError("inner dispatch touched")

        monkeypatch.setattr("model_tools.handle_function_call", boom)
        agent = _agent()
        ref = _ToolCallRef("browser_vault_fill", {"handle": "h"}, "task1", "call1", [])
        with bound(CTX_AM):
            dispatch = _resolve_sequential_dispatch(agent, ref, [])
            dispatch.execute = _team_authz_guarded_execute(ref.name, dispatch.execute)
            body = json.loads(dispatch.execute({"handle": "h"}))
        assert "protected:credentials" in body["error"]

    def test_registry_allow_passes_through(self, home, monkeypatch):
        from agent.tool_executor import _ToolCallRef, _resolve_sequential_dispatch, _team_authz_guarded_execute
        monkeypatch.setattr("model_tools.handle_function_call",
                            lambda *a, **k: '{"ok": "ran"}')
        agent = _agent()
        ref = _ToolCallRef("web_search", {"q": "x"}, "task1", "call1", [])
        with bound(CTX_AM):
            dispatch = _resolve_sequential_dispatch(agent, ref, [])
            dispatch.execute = _team_authz_guarded_execute(ref.name, dispatch.execute)
            assert json.loads(dispatch.execute({"q": "x"})) == {"ok": "ran"}

    def test_context_engine_branch_preserved_for_allowed(self, home):
        from agent.tool_executor import _ToolCallRef, _resolve_sequential_dispatch, _parse_tool_call, _team_authz_guarded_execute
        agent = _agent(
            _context_engine_tool_names={"ce_probe"},
            context_compressor=SimpleNamespace(
                handle_tool_call=lambda name, args, messages=None: '{"ok": "ce"}'))
        with bound(CTX_AM):
            assert _parse_tool_call(None, _tool_call("ce_probe", {})).scope_block is None
            ref = _ToolCallRef("ce_probe", {}, "task1", "call1", [])
            dispatch = _resolve_sequential_dispatch(agent, ref, [])
            dispatch.execute = _team_authz_guarded_execute(ref.name, dispatch.execute)
            out = dispatch.execute({})
        assert json.loads(out) == {"ok": "ce"}

    def test_memory_branch_preserved_for_allowed(self, home):
        from agent.tool_executor import _ToolCallRef, _resolve_sequential_dispatch, _parse_tool_call, _team_authz_guarded_execute
        agent = _agent(_memory_manager=SimpleNamespace(
            has_tool=lambda name: True,
            handle_tool_call=lambda name, args: '{"ok": "mem"}'))
        with bound(CTX_AM):
            assert _parse_tool_call(None, _tool_call("mem_probe", {})).scope_block is None
            ref = _ToolCallRef("mem_probe", {}, "task1", "call1", [])
            dispatch = _resolve_sequential_dispatch(agent, ref, [])
            dispatch.execute = _team_authz_guarded_execute(ref.name, dispatch.execute)
            out = dispatch.execute({})
        assert json.loads(out) == {"ok": "mem"}

    def test_wrap_denies_transformed_args(self, home, monkeypatch):
        from agent.tool_executor import _ToolCallRef, _resolve_sequential_dispatch, _team_authz_guarded_execute

        def boom(*a, **k):
            raise AssertionError("inner dispatch touched")

        monkeypatch.setattr("model_tools.handle_function_call", boom)
        agent = _agent()
        ref = _ToolCallRef("browser_navigate", {"url": "https://c.example/"}, "t1", "c1", [])
        with bound(CTX_AM):
            dispatch = _resolve_sequential_dispatch(agent, ref, [])
            dispatch.execute = _team_authz_guarded_execute(ref.name, dispatch.execute)
            body = json.loads(dispatch.execute(
                {"url": "https://c.example/", "text": "password hunter2"}))
        assert "protected:browser-login" in body["error"]


class TestInvokeTool:
    def test_member_protected_tool_denied_zero_backend(self, home, monkeypatch):
        from agent.agent_runtime_helpers import invoke_tool

        def boom(*a, **k):
            raise AssertionError("backend touched")

        monkeypatch.setattr("model_tools.registry.dispatch", boom)
        with bound(CTX_AM):
            body = json.loads(invoke_tool(_agent(), "browser_vault_fill", {"handle": "h"}, "task1"))
        assert "protected:credentials" in body["error"]

    def test_member_ordinary_passes_through(self, home, monkeypatch):
        from agent.agent_runtime_helpers import invoke_tool
        monkeypatch.setattr("model_tools.handle_function_call",
                            lambda *a, **k: '{"ok": "ran"}')
        with bound(CTX_AM):
            out = invoke_tool(_agent(), "web_search", {"q": "x"}, "task1")
        assert json.loads(out) == {"ok": "ran"}

    def test_execution_middleware_launder_denied(self, home, monkeypatch):
        from agent.agent_runtime_helpers import invoke_tool

        def fake_run_middleware(name, args, dispatcher, original_args=None, **kw):
            laundered = dict(args)
            laundered["text"] = "type the password hunter2"
            return dispatcher(laundered)

        monkeypatch.setattr("hermes_cli.middleware.run_tool_execution_middleware",
                            fake_run_middleware)

        def boom(*a, **k):
            raise AssertionError("backend touched")

        monkeypatch.setattr("model_tools.handle_function_call", boom)
        with bound(CTX_AM):
            body = json.loads(invoke_tool(
                _agent(), "browser_navigate", {"url": "https://c.example/"}, "task1"))
        assert "protected:browser-login" in body["error"]

    def test_spoofed_owner_flag_ignored(self, home, monkeypatch):
        from agent.agent_runtime_helpers import invoke_tool

        def boom(*a, **k):
            raise AssertionError("backend touched")

        monkeypatch.setattr("model_tools.registry.dispatch", boom)
        with bound(CTX_AM):
            body = json.loads(invoke_tool(
                _agent(), "browser_vault_fill", {"handle": "h", "is_owner": True}, "task1"))
        assert "protected:credentials" in body["error"]

    def test_ungoverned_baseline(self, tmp_path, monkeypatch):
        from agent.agent_runtime_helpers import invoke_tool
        h = tmp_path / "open"
        h.mkdir()
        (h / "config.yaml").write_text(CONFIG_DISABLED, encoding="utf-8")
        d = h / "team_authz"
        d.mkdir(parents=True, exist_ok=True)
        (d / "register.json").write_text(json.dumps(_base_register()), encoding="utf-8")
        monkeypatch.setenv("HERMES_HOME", str(h))
        team_authz._REGISTER_CACHE.clear()
        monkeypatch.setattr("model_tools.handle_function_call",
                            lambda *a, **k: '{"ok": "ran"}')
        with bound(CTX_AM):
            out = invoke_tool(_agent(), "terminal", {"command": "id"}, "task1")
        assert json.loads(out) == {"ok": "ran"}
