"""HTS-03 tool-seam tests: discovery, handle_function_call, vault, approval, connectors.

Exercises the real dispatch seams (model_tools.handle_function_call,
get_tool_definitions, vault handlers, request_tool_approval,
dispatch_connector_call/batch) against a temp HERMES_HOME with synthetic
identities shaped like ``9000000000000000NN``. Backend sentinels prove
denials happen with zero backend calls. Behaviour contracts only.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent import team_authz
from agent.team_authz import (
    Decision,
    RequesterContext,
    bind_requester,
    classify_protected,
    filter_tool_names,
    reset_requester,
)
from agent.team_authz_sharing import record_sharing_consent

OWNER_ID = "900000000000000001"
MANAGER_ID = "900000000000000002"
AM_ID = "900000000000000003"
OUTSIDER_ID = "900000000000000009"

GUILD = "910000000000000001"
CHAT_AM = "920000000000000003"
CHAT_OWNER = "920000000000000001"


def _ctx(uid, *, chat="920000000000000099", scope=GUILD) -> RequesterContext:
    return RequesterContext(platform="discord", user_id=uid, scope_id=scope,
                            chat_id=chat, chat_type="dm")


CTX_OWNER = _ctx(OWNER_ID, chat=CHAT_OWNER)
CTX_MANAGER = _ctx(MANAGER_ID, chat="920000000000000002")
CTX_AM = _ctx(AM_ID, chat=CHAT_AM)
CTX_AM_SHARED = replace(CTX_AM, chat_type="channel")
CTX_OUTSIDER = _ctx(OUTSIDER_ID)


@contextmanager
def bound(ctx):
    """Bind a requester with transport provenance for the block."""
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
        "policyVersion": "2026.09.17-hts03",
        "guilds": [GUILD],
        "members": [
            _member(OWNER_ID, "charles", "owner"),
            _member(MANAGER_ID, "bettina", "manager"),
            _member(AM_ID, "lianna", "account_manager"),
        ],
        "roles": {
            "owner": {"capabilities": [
                "basic", "web.read", "ghl.manage", "history.read.own",
                "memory.own", "delegate", "register.change", "owner.host",
            ]},
            "manager": {"capabilities": [
                "basic", "web.read", "history.oversight", "register.change",
                "history.read.own", "memory.own", "delegate",
            ]},
            "account_manager": {"capabilities": [
                "basic", "web.read", "client.message.send", "ghl.manage",
                "history.read.own", "memory.own", "delegate",
            ]},
        },
        "toolActions": [
            {"pattern": "connectors__ghl__charge", "action": "ghl.manage",
             "connectionId": "conn-ghl-main", "accountArg": "account",
             "amountArg": "amount", "currencyArg": "currency"},
            {"pattern": "connectors__archive__lookup", "action": "basic",
             "connectionId": "conn-mail-personal"},
            {"pattern": "connectors__ghl__*", "action": "ghl.manage",
             "connectionId": "conn-ghl-main", "accountArg": "account"},
        ],
        "connections": [
            {"id": "conn-ghl-main", "connector": "ghl", "account": "shoutout",
             "ownerClass": "business", "actions": ["ghl.manage"]},
            {"id": "conn-mail-personal", "connector": "email",
             "account": "charles-personal", "ownerClass": "personal",
             "actions": ["basic"]},
        ],
        "spendingCaps": [
            {"memberKey": "lianna", "connectionId": "conn-ghl-main",
             "account": "shoutout", "currency": "USD", "period": "month",
             "amount": 100, "scope": "", "approvedBy": "charles"},
        ],
        "oversight": {"destinations": []},
    }


def _write_register(home: Path, register: dict) -> None:
    d = home / "team_authz"
    d.mkdir(parents=True, exist_ok=True)
    (d / "register.json").write_text(json.dumps(register), encoding="utf-8")


def _write_config(home: Path, text: str) -> None:
    (home / "config.yaml").write_text(text, encoding="utf-8")


CONFIG_ENABLED = "team_authz:\n  enabled: true\n  governed_platforms: [\"discord\"]\n"
CONFIG_DISABLED = "team_authz:\n  enabled: false\n"


def _audit_rows(home: Path) -> list:
    p = home / "team_authz" / "audit.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Temp HERMES_HOME: team_authz enabled, HTS-03 register, clean audit."""
    h = tmp_path / "hermes-home"
    h.mkdir()
    _write_config(h, CONFIG_ENABLED)
    _write_register(h, _base_register())
    monkeypatch.setenv("HERMES_HOME", str(h))
    # Reserved example domains resolve synthetically; never query live DNS.
    monkeypatch.setattr("tools.url_safety._getaddrinfo",
                        lambda *a, **kw: [(2, 1, 6, "", ("8.8.8.8", 443))])
    team_authz._REGISTER_CACHE.clear()
    yield h
    team_authz._REGISTER_CACHE.clear()


def _make_home(tmp_path, monkeypatch, name, config=CONFIG_ENABLED, register=None):
    h = tmp_path / name
    h.mkdir()
    _write_config(h, config)
    _write_register(h, register if register is not None else _base_register())
    monkeypatch.setenv("HERMES_HOME", str(h))
    team_authz._REGISTER_CACHE.clear()
    return h


def _patch_dispatch(monkeypatch, calls, result='{"ok": true}'):
    def fake_dispatch(name, args, **kw):
        calls.append((name, dict(args)))
        return result
    monkeypatch.setattr("model_tools.registry.dispatch", fake_dispatch)


def _patch_remote(monkeypatch, calls, entries=None):
    def fake_run_remote(plans, tool_call_id, availability=None, client_factory=None):
        calls.append(list(plans))
        if entries is not None:
            return entries
        return [{"index": p.position, "name": p.name, "response": {"ok": True}}
                for p in plans]
    monkeypatch.setattr("tools.connectors.gateway.bridge.run_remote", fake_run_remote)


def _deny_text(raw: str) -> str:
    body = json.loads(raw)
    assert "error" in body, body
    err = body["error"]
    return err if isinstance(err, str) else json.dumps(err)


_DISCOVERY_TOOLSETS = ["terminal", "browser", "web", "file", "todo"]


def _def_names(defs):
    return {d["function"]["name"] for d in defs}


class TestDiscovery:
    def test_member_hides_protected_keeps_ordinary(self, tmp_path, monkeypatch):
        from model_tools import get_tool_definitions
        open_home = _make_home(tmp_path, monkeypatch, "open", CONFIG_DISABLED)
        with bound(CTX_AM):
            open_defs = get_tool_definitions(enabled_toolsets=_DISCOVERY_TOOLSETS, quiet_mode=True)
        assert open_defs, "ungoverned baseline must be non-empty"
        team_home = _make_home(tmp_path, monkeypatch, "team")
        with bound(CTX_AM):
            member_defs = get_tool_definitions(enabled_toolsets=_DISCOVERY_TOOLSETS, quiet_mode=True)
        open_names, member_names = _def_names(open_defs), _def_names(member_defs)
        hidden = {n for n in open_names if classify_protected(n)}
        assert member_names <= open_names
        assert member_names & hidden == set()
        assert (open_names - hidden) <= member_names
        # The synthetic home may surface no protected tool at all (browser
        # vault tools need a configured browser), which would make the checks
        # above vacuous. Prove the hiding property against fixed names so it
        # cannot silently pass on an empty set.
        probe = ["browser_vault_get", "gmail_search", "web_search", "terminal"]
        with bound(CTX_AM):
            assert set(filter_tool_names(probe, CTX_AM)) == {"web_search", "terminal"}

    def test_owner_matches_ungoverned(self, tmp_path, monkeypatch):
        from model_tools import get_tool_definitions
        _make_home(tmp_path, monkeypatch, "open", CONFIG_DISABLED)
        with bound(CTX_AM):
            open_defs = get_tool_definitions(enabled_toolsets=_DISCOVERY_TOOLSETS, quiet_mode=True)
        _make_home(tmp_path, monkeypatch, "team")
        with bound(CTX_OWNER):
            owner_defs = get_tool_definitions(enabled_toolsets=_DISCOVERY_TOOLSETS, quiet_mode=True)
        assert _def_names(owner_defs) == _def_names(open_defs)

    def test_discovery_stable_across_principals(self, home):
        from model_tools import get_tool_definitions
        with bound(CTX_AM):
            first = _def_names(get_tool_definitions(
                enabled_toolsets=_DISCOVERY_TOOLSETS, quiet_mode=True))
        with bound(CTX_OWNER):
            owner = _def_names(get_tool_definitions(
                enabled_toolsets=_DISCOVERY_TOOLSETS, quiet_mode=True))
        with bound(CTX_AM):
            second = _def_names(get_tool_definitions(
                enabled_toolsets=_DISCOVERY_TOOLSETS, quiet_mode=True))
        assert first == second
        assert first <= owner


class TestHandleFunctionCall:
    def test_member_terminal_allowed(self, home, monkeypatch):
        from model_tools import handle_function_call
        calls = []
        _patch_dispatch(monkeypatch, calls, result='{"ok": "ran"}')
        with bound(CTX_AM):
            out = handle_function_call("terminal", {"command": "id"})
        assert json.loads(out) == {"ok": "ran"}
        assert [c[0] for c in calls] == ["terminal"]

    def test_member_vault_denied_zero_dispatch(self, home, monkeypatch):
        from model_tools import handle_function_call
        calls = []
        _patch_dispatch(monkeypatch, calls)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call("browser_vault_list", {}))
        assert "protected:credentials" in text
        assert calls == []

    def test_member_browser_credential_entry_denied(self, home, monkeypatch):
        from model_tools import handle_function_call
        calls = []
        _patch_dispatch(monkeypatch, calls)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call(
                "browser_navigate",
                {"url": "https://client.example/login", "text": "type the password hunter2"}))
        assert "protected:browser-login" in text
        assert calls == []

    def test_member_browser_view_allowed(self, home, monkeypatch):
        from model_tools import handle_function_call
        calls = []
        _patch_dispatch(monkeypatch, calls, result='{"ok": "view"}')
        with bound(CTX_AM):
            out = handle_function_call("browser_navigate", {"url": "https://client.example/"})
        assert json.loads(out) == {"ok": "view"}
        assert [c[0] for c in calls] == ["browser_navigate"]

    def test_owner_terminal_allowed(self, home, monkeypatch):
        from model_tools import handle_function_call
        calls = []
        _patch_dispatch(monkeypatch, calls, result='{"ok": "owner"}')
        with bound(CTX_OWNER):
            out = handle_function_call("terminal", {"command": "id"})
        assert json.loads(out) == {"ok": "owner"}
        assert [c[0] for c in calls] == ["terminal"]

    def test_approvals_mode_off_cannot_convert_deny(self, home, monkeypatch):
        from model_tools import handle_function_call
        monkeypatch.setattr("hermes_cli.config.load_config_readonly",
                            lambda: {"approvals": {"mode": "off"}})
        calls = []
        _patch_dispatch(monkeypatch, calls)
        with bound(CTX_AM):
            assert "protected:credentials" in _deny_text(
                handle_function_call("browser_vault_list", {}))
            assert "protected:personal-mailbox" in _deny_text(
                handle_function_call("email_send", {}))
        assert calls == []

    def test_spoofed_owner_flags_ignored(self, home, monkeypatch):
        from model_tools import handle_function_call
        calls = []
        _patch_dispatch(monkeypatch, calls)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call(
                "browser_vault_list", {"is_owner": True, "role": "owner",
                                       "approvedBy": OWNER_ID}))
        assert "protected:credentials" in text
        assert calls == []

    def test_middleware_launder_in_denied_at_final_recheck(self, home, monkeypatch):
        from model_tools import handle_function_call
        seen = []

        def fake_middleware(tool_name, args, **ctx):
            payload = dict(args)
            payload["text"] = "type the password hunter2"
            seen.append(tool_name)
            return SimpleNamespace(payload=payload, original_payload=dict(args), trace=[])

        monkeypatch.setattr("hermes_cli.middleware.apply_tool_request_middleware", fake_middleware)
        calls = []
        _patch_dispatch(monkeypatch, calls)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call(
                "browser_navigate", {"url": "https://client.example/"}))
        assert "protected:browser-login" in text
        assert seen == ["browser_navigate"]
        assert calls == []

    def test_middleware_launder_out_entry_denies_first(self, home, monkeypatch):
        from model_tools import handle_function_call
        seen = []

        def fake_middleware(tool_name, args, **ctx):
            seen.append(tool_name)
            payload = {k: v for k, v in args.items() if k != "text"}
            return SimpleNamespace(payload=payload, original_payload=dict(args), trace=[])

        monkeypatch.setattr("hermes_cli.middleware.apply_tool_request_middleware", fake_middleware)
        calls = []
        _patch_dispatch(monkeypatch, calls)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call(
                "browser_navigate",
                {"url": "https://x.example/", "text": "password hunter2"}))
        assert "protected:browser-login" in text
        assert seen == []
        assert calls == []

    def test_unwrapped_tool_call_reguarded(self, home, monkeypatch):
        from model_tools import handle_function_call
        monkeypatch.setattr("tools.tool_search.resolve_underlying_call",
                            lambda args: ("browser_vault_fill", {"handle": "h"}, None))
        monkeypatch.setattr("tools.tool_search.scoped_deferrable_names",
                            lambda defs: {"browser_vault_fill"})
        monkeypatch.setattr("tools.tool_search.validate_deferred_call_args",
                            lambda name, args: None)
        calls = []
        _patch_dispatch(monkeypatch, calls)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call(
                "tool_call", {"name": "browser_vault_fill", "arguments": {"handle": "h"}}))
        assert "protected:credentials" in text
        assert calls == []

    def test_in_cap_spend_allowed(self, home, monkeypatch):
        from model_tools import handle_function_call
        remote = []
        _patch_remote(monkeypatch, remote)
        with bound(CTX_AM_SHARED):
            out = handle_function_call("connectors__ghl__charge", {
                "account": "shoutout", "amount": 10, "currency": "USD"})
        assert json.loads(out) == {"response": {"ok": True}}
        assert len(remote) == 1

    def test_over_cap_spend_denied_zero_remote(self, home, monkeypatch):
        from model_tools import handle_function_call
        remote = []
        _patch_remote(monkeypatch, remote)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call("connectors__ghl__charge", {
                "account": "shoutout", "amount": 1000, "currency": "USD"}))
        assert "cap-exceeded" in text
        assert remote == []

    def test_personal_connection_denied_zero_remote(self, home, monkeypatch):
        from model_tools import handle_function_call
        remote = []
        _patch_remote(monkeypatch, remote)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call("connectors__archive__lookup", {}))
        assert "connection-class-denied" in text
        assert remote == []


def _secure_owner_ctx() -> RequesterContext:
    return RequesterContext(platform="secure-owner", user_id=OWNER_ID, scope_id=None,
                            chat_id="920000000000000001", chat_type="secure-owner")


def _record_owner_approval_for(home, monkeypatch, operation, resource):
    """Mint one exact owner approval on a configured secure owner surface."""
    from agent.team_authz_owner import record_owner_approval
    ctx = _secure_owner_ctx()
    _write_config(home, json.dumps({"team_authz": {
        "enabled": True, "governed_platforms": ["discord"],
        "secure_owner_surfaces": [{"platform": ctx.platform,
                                   "chatId": ctx.chat_id,
                                   "chatType": ctx.chat_type}],
    }}))
    team_authz._REGISTER_CACHE.clear()
    with bound(ctx):
        decision = record_owner_approval({"operation": operation, "resource": resource})
    assert decision.allowed, decision.reason
    return decision.action


class TestApprovalHookAndOwnerApprovalLanes:
    """Approval-hook removal control plus owner-approval non-transfer lanes.

    T1 removed the approval hook (``tools/approval.py`` is back to base bytes)
    while the tool seam still refuses the same call, and an owner approval never
    transfers the owner's private resources to a teammate.
    """

    def test_approval_gate_no_longer_enforces_team_policy(self, home, monkeypatch):
        from tools.approval import request_tool_approval
        monkeypatch.setattr("hermes_cli.config.load_config_readonly",
                            lambda: {"approvals": {"mode": "off"}})
        with bound(CTX_AM):
            verdict = request_tool_approval("browser_vault_fill", "plugin wants a vault fill")
        rendered = json.dumps(verdict)
        assert "Team authorization" not in rendered
        assert "I can't" not in (verdict.get("message") or "")

    def test_execution_still_denies_the_same_tool(self, home, monkeypatch):
        from model_tools import handle_function_call
        calls = []
        _patch_dispatch(monkeypatch, calls)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call("browser_vault_fill", {"handle": "h"}))
        assert "protected:credentials" in text
        assert calls == []

    def test_exact_approval_cannot_transfer_private_browser_access(self, home, monkeypatch):
        from model_tools import handle_function_call
        approval_id = _record_owner_approval_for(
            home, monkeypatch, "owner.browser.use", "browser_navigate")
        snapshots = []
        calls = []

        def fake_dispatch(name, args, **kw):
            snapshots.append(_audit_rows(home))
            calls.append(name)
            return '{"ok": "browsed"}'

        monkeypatch.setattr("model_tools.registry.dispatch", fake_dispatch)
        with bound(CTX_AM):
            out = handle_function_call("browser_navigate", {
                "url": "https://client.example/login",
                "text": "type the password hunter2",
                "ownerApprovalId": approval_id})
        assert "protected:browser-login" in json.loads(out)["error"]
        assert calls == []
        assert snapshots == []
        assert any(r.get("decision") == "denied" for r in _audit_rows(home))
        with bound(CTX_OWNER):
            out = handle_function_call("browser_navigate", {"url": "https://client.example/login"})
        assert json.loads(out) == {"ok": "browsed"}
        assert calls == ["browser_navigate"]
        assert any(r.get("event") == "authorize" and r.get("decision") == "allowed" for r in snapshots[0])

    def test_audit_failure_denies_zero_dispatch(self, home, monkeypatch):
        from model_tools import handle_function_call
        monkeypatch.setattr("agent.team_authz.audit", lambda event: False)
        monkeypatch.setattr("agent.team_authz_owner.audit", lambda event: False)
        monkeypatch.setattr("agent.team_authz_sharing.audit", lambda event: False)
        calls = []
        _patch_dispatch(monkeypatch, calls)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call("web_search", {"query": "x"}))
        assert "audit-failure" in text
        assert calls == []

    def test_approval_audit_failure_denies_zero_dispatch(self, home, monkeypatch):
        from model_tools import handle_function_call
        approval_id = _record_owner_approval_for(
            home, monkeypatch, "owner.browser.use", "browser_navigate")
        monkeypatch.setattr("agent.team_authz.audit", lambda event: False)
        monkeypatch.setattr("agent.team_authz_owner.audit", lambda event: False)
        monkeypatch.setattr("agent.team_authz_sharing.audit", lambda event: False)
        calls = []
        _patch_dispatch(monkeypatch, calls)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call("browser_navigate", {
                "url": "https://client.example/login",
                "text": "type the password hunter2",
                "ownerApprovalId": approval_id}))
        assert "audit-failure" in text or "protected:" in text
        assert calls == []


class TestVaultHandlers:
    def test_vault_list_denied_zero_backend(self, home, monkeypatch):
        from tools.browser_vault_tool import browser_vault_list
        backends = []
        monkeypatch.setattr("agent.vault_backends.enabled_backends",
                            lambda: backends.append(1) or [])
        with bound(CTX_AM):
            body = json.loads(browser_vault_list())
        assert body["success"] is False
        assert body["error_type"] == "team_authz_denied"
        assert "protected:credentials" in body["error"]
        assert backends == []

    def test_vault_unlock_denied_zero_backend(self, home, monkeypatch):
        from tools.browser_vault_tool import browser_vault_unlock
        backends = []
        monkeypatch.setattr("agent.vault_backends.enabled_backends",
                            lambda: backends.append(1) or [])
        with bound(CTX_AM):
            body = json.loads(browser_vault_unlock("some-backend"))
        assert body["success"] is False
        assert "protected:credentials" in body["error"]
        assert backends == []

    def test_vault_save_login_denied_before_prompt(self, home, monkeypatch):
        from tools.browser_vault_tool import browser_vault_save_login

        def boom(*a, **k):
            raise AssertionError("backend touched")

        monkeypatch.setattr("tools.browser_vault_tool._focus_bound_origin", boom)
        with bound(CTX_AM):
            body = json.loads(browser_vault_save_login("Example"))
        assert body["success"] is False
        assert "protected:credentials" in body["error"]

    def test_vault_enter_code_denied_before_page(self, home, monkeypatch):
        from tools.browser_vault_tool import browser_vault_enter_code

        def boom(*a, **k):
            raise AssertionError("backend touched")

        monkeypatch.setattr("tools.browser_vault_tool._focus_bound_origin", boom)
        with bound(CTX_AM):
            body = json.loads(browser_vault_enter_code("h1"))
        assert body["success"] is False
        assert "protected:credentials" in body["error"]

    def test_vault_fill_denied_zero_backend(self, home, monkeypatch):
        from tools.browser_vault_tool import browser_vault_fill
        lookups = []
        monkeypatch.setattr("agent.vault_backends.backend_for_handle",
                            lambda handle: lookups.append(handle) or None)
        with bound(CTX_AM):
            body = json.loads(browser_vault_fill("h1"))
        assert body["success"] is False
        assert "protected:credentials" in body["error"]
        assert lookups == []

    def test_owner_vault_list_positive(self, home, monkeypatch):
        from tools.browser_vault_tool import browser_vault_list
        monkeypatch.setattr("agent.vault_backends.enabled_backends", lambda: [])
        with bound(CTX_OWNER):
            body = json.loads(browser_vault_list())
        assert body["success"] is True
        assert body["items"] == []

    def test_vault_deny_with_approvals_off(self, home, monkeypatch):
        from tools.browser_vault_tool import browser_vault_fill
        monkeypatch.setattr("hermes_cli.config.load_config_readonly",
                            lambda: {"approvals": {"mode": "off"}})
        lookups = []
        monkeypatch.setattr("agent.vault_backends.backend_for_handle",
                            lambda handle: lookups.append(handle) or None)
        with bound(CTX_AM):
            body = json.loads(browser_vault_fill("h1"))
        assert body["success"] is False
        assert "protected:credentials" in body["error"]
        assert lookups == []


class TestApprovalFloor:
    def test_ordinary_tool_passes_floor(self, home):
        from tools.approval import request_tool_approval
        with bound(CTX_AM):
            verdict = request_tool_approval("web_search", "plugin check")
        assert "Team authorization" not in json.dumps(verdict)

    def test_ungoverned_terminal_passes_floor(self, tmp_path, monkeypatch):
        from tools.approval import request_tool_approval
        _make_home(tmp_path, monkeypatch, "open", CONFIG_DISABLED)
        with bound(CTX_AM):
            verdict = request_tool_approval("terminal", "plugin wants a shell")
        assert "Team authorization" not in json.dumps(verdict)


SINK_TOOL = "connectors__ghl__publish_note"
SINK_DEST = {"shape": "connector", "connector": "ghl", "connectionId": "conn-ghl-main",
             "account": "shoutout", "resource": "notes"}
SINK_SUMMARY = "Client Acme approved the rollout summary."
SINK_SOURCE = "dm:920000000000000003:msg-1"


def _record_consent(status="approved"):
    # The human author approves the complete canonical provider payload. Build
    # the expected binding independently of the production binding helper.
    payload = json.dumps({"tool": SINK_TOOL, "arguments": _sink_args(None)},
                         ensure_ascii=False, sort_keys=True)
    destination = {"shape": "connector", "connector": "ghl",
                   "connectionId": "conn-ghl-main", "account": "shoutout",
                   "resource": SINK_TOOL}
    with bound(CTX_AM):
        decision = record_sharing_consent({
            "sourceRef": f"dm:discord:{AM_ID}:{CHAT_AM}", "authorDiscordUserId": AM_ID,
            "summary": payload, "destination": destination, "status": status})
    assert decision.allowed, decision.reason
    return decision.action


def _sink_args(consent_id, **kw):
    args = {"source": SINK_SOURCE, "summary": SINK_SUMMARY,
            "destination": dict(SINK_DEST), "account": "shoutout"}
    if consent_id is not None:
        args["sharingConsentId"] = consent_id
    args.update(kw)
    return args


class TestSharingConsentAtSink:
    def test_exact_consent_allowed(self, home, monkeypatch):
        from model_tools import handle_function_call
        cid = _record_consent()
        remote = []
        _patch_remote(monkeypatch, remote)
        with bound(CTX_AM):
            out = handle_function_call(SINK_TOOL, _sink_args(cid))
        assert json.loads(out) == {"response": {"ok": True}}
        assert len(remote) == 1
        rows = _audit_rows(home)
        assert any(r.get("event") == "sharing-check" and r.get("decision") == "allowed"
                   for r in rows)

    def test_missing_consent_denied_zero_remote(self, home, monkeypatch):
        from model_tools import handle_function_call
        _record_consent()
        remote = []
        _patch_remote(monkeypatch, remote)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call(SINK_TOOL, _sink_args(None)))
        assert "consent-required" in text
        assert remote == []

    def test_wrong_destination_denied_zero_remote(self, home, monkeypatch):
        from model_tools import handle_function_call
        cid = _record_consent()
        remote = []
        _patch_remote(monkeypatch, remote)
        other = dict(SINK_DEST, resource="other-board")
        with bound(CTX_AM):
            text = _deny_text(handle_function_call(SINK_TOOL, _sink_args(cid, destination=other)))
        # Destination is inside the canonical payload: changing it changes
        # the exact author-approved bytes before the connector is reached.
        assert "consent-summary-mismatch" in text
        assert remote == []

    def test_altered_summary_denied_zero_remote(self, home, monkeypatch):
        from model_tools import handle_function_call
        cid = _record_consent()
        remote = []
        _patch_remote(monkeypatch, remote)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call(
                SINK_TOOL, _sink_args(cid, summary=SINK_SUMMARY + " edited")))
        assert "consent-summary-mismatch" in text
        assert remote == []

    def test_extra_field_denied_zero_remote(self, home, monkeypatch):
        from model_tools import handle_function_call
        cid = _record_consent()
        remote = []
        _patch_remote(monkeypatch, remote)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call(
                SINK_TOOL, _sink_args(cid, priority="high")))
        assert "consent-extra-fields" in text
        assert remote == []

    @pytest.mark.parametrize("attachment,reason", [
        ("screenshot.png", "consent-attachments-denied"),
        ("https://client.example/screenshot.png", "consent-attachments-denied"),
    ])
    def test_attachments_denied_zero_remote(self, home, monkeypatch, attachment, reason):
        from model_tools import handle_function_call
        cid = _record_consent()
        remote = []
        _patch_remote(monkeypatch, remote)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call(
                SINK_TOOL, _sink_args(cid, attachments=[attachment])))
        assert reason in text
        assert remote == []

    def test_extra_destination_field_denied_zero_remote(self, home, monkeypatch):
        from model_tools import handle_function_call
        cid = _record_consent()
        remote = []
        _patch_remote(monkeypatch, remote)
        wild = dict(SINK_DEST, zone="unconsented")
        with bound(CTX_AM):
            text = _deny_text(handle_function_call(SINK_TOOL, _sink_args(cid, destination=wild)))
        assert "consent-extra-destination-fields" in text
        assert remote == []

    def test_revoked_consent_denied_zero_remote(self, home, monkeypatch):
        from model_tools import handle_function_call
        cid = _record_consent(status="revoked")
        remote = []
        _patch_remote(monkeypatch, remote)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call(SINK_TOOL, _sink_args(cid)))
        assert "consent-revoked" in text
        assert remote == []


class TestConnectorDispatch:
    def test_mapped_business_call_allowed(self, home, monkeypatch):
        from tools.connectors.dispatch import dispatch_connector_call
        remote = []
        _patch_remote(monkeypatch, remote)
        with bound(CTX_AM_SHARED):
            out = dispatch_connector_call("connectors__ghl__charge", {
                "account": "shoutout", "amount": 10, "currency": "USD"}, "tc-1")
        assert json.loads(out) == {"response": {"ok": True}}
        assert len(remote) == 1

    def test_unmapped_connector_allowed(self, home, monkeypatch):
        from tools.connectors.dispatch import dispatch_connector_call
        remote = []
        _patch_remote(monkeypatch, remote)
        with bound(CTX_AM):
            out = dispatch_connector_call("connectors__nope__tool", {}, "tc-1")
        assert json.loads(out) == {"response": {"ok": True}}
        assert len(remote) == 1

    def test_malformed_connector_blocked_zero_remote(self, home, monkeypatch):
        from tools.connectors.dispatch import dispatch_connector_call
        remote = []
        _patch_remote(monkeypatch, remote)
        with bound(CTX_AM):
            text = _deny_text(dispatch_connector_call("connectors__bogus", {}, "tc-1"))
        assert "malformed connector target" in text
        assert remote == []

    def test_inventoried_unmapped_allowed(self, home, monkeypatch):
        from tools.connectors.dispatch import dispatch_connector_call
        remote = []
        _patch_remote(monkeypatch, remote)
        with bound(CTX_AM):
            out = dispatch_connector_call("connectors__email__read", {}, "tc-1")
        assert json.loads(out) == {"response": {"ok": True}}
        assert len(remote) == 1

    def test_gateway_failure_is_terminal_no_retry(self, home, monkeypatch):
        from tools.connectors.dispatch import dispatch_connector_call
        remote = []
        _patch_remote(monkeypatch, remote, entries=[{
            "index": 0, "name": "connectors__ghl__read",
            "error": {"code": "PROVIDER_ERROR", "message": "gateway down"}}])
        with bound(CTX_AM_SHARED):
            out = dispatch_connector_call("connectors__ghl__read", {"account": "shoutout"}, "tc-1")
        body = json.loads(out)
        assert "error" in body
        assert "gateway down" in json.dumps(body)
        assert "browser" not in json.dumps(body).lower()
        assert len(remote) == 1

    def test_batch_per_item_policy(self, home, monkeypatch):
        from model_tools import _CallIds
        from tools.connectors.dispatch import dispatch_connector_batch
        remote = []
        _patch_remote(monkeypatch, remote)
        ids = _CallIds(task_id="t", session_id="s", tool_call_id="c",
                       turn_id="", api_request_id="")
        calls = [
            {"name": "connectors__ghl__charge",
             "arguments": {"account": "shoutout", "amount": 5, "currency": "USD"}},
            {"name": "connectors__ghl__proxy_fetch", "arguments": {}},
            {"name": "connectors__nope__tool2", "arguments": {}},
        ]
        with bound(CTX_AM_SHARED):
            body = json.loads(dispatch_connector_batch(
                calls, ids, user_task=None, enabled_tools=None,
                middleware_trace=[], enabled_toolsets=None, disabled_toolsets=None))
        assert body["total_count"] == 3
        assert body["success_count"] == 2
        assert body["error_count"] == 1
        by_name = {e["name"]: e for e in body["results"]}
        assert "response" in by_name["connectors__ghl__charge"]
        # Mapped tool missing its mapped account still denies (retained policy).
        assert "connection-account-mismatch" in json.dumps(by_name["connectors__ghl__proxy_fetch"])
        assert "response" in by_name["connectors__nope__tool2"]
        assert len(remote) == 2

    def test_ungoverned_connector_baseline(self, tmp_path, monkeypatch):
        from tools.connectors.dispatch import dispatch_connector_call
        _make_home(tmp_path, monkeypatch, "open", CONFIG_DISABLED)
        remote = []
        _patch_remote(monkeypatch, remote)
        with bound(CTX_AM):
            out = dispatch_connector_call("connectors__nope__tool", {}, "tc-1")
        assert json.loads(out) == {"response": {"ok": True}}
        assert len(remote) == 1


class TestMalformedSinkDestination:
    def test_string_destination_denied_zero_remote(self, home, monkeypatch):
        from model_tools import handle_function_call
        cid = _record_consent()
        remote = []
        _patch_remote(monkeypatch, remote)
        with bound(CTX_AM):
            text = _deny_text(handle_function_call(
                SINK_TOOL, _sink_args(cid, destination="team-channel")))
        assert "consent-destination-invalid" in text
        assert remote == []


def _loopback_or_public_addrinfo(hostname, port=None):
    ip = "127.0.0.1" if hostname in {"127.0.0.1", "localhost", "::1"} else "8.8.8.8"
    return [(2, 1, 6, "", (ip, port or 80))]


class TestMemberUrlFetchToggle:
    """B12-R: non-browser URL tools must not inherit the owner private-URL toggle."""

    PRIVATE = "http://127.0.0.1:9119/dashboard"
    PUBLIC = "https://example.com/page"

    def _toggle_home(self, tmp_path, monkeypatch, name="toggle"):
        import tools.url_safety as url_safety
        h = _make_home(tmp_path, monkeypatch, name)
        monkeypatch.setenv("HERMES_ALLOW_PRIVATE_URLS", "true")
        url_safety._allow_private_resolved = False
        monkeypatch.setattr("tools.url_safety._getaddrinfo", _loopback_or_public_addrinfo)
        return h

    def test_member_web_extract_private_denied_with_toggle(self, tmp_path, monkeypatch):
        from model_tools import handle_function_call
        from tools.url_safety import is_safe_url
        self._toggle_home(tmp_path, monkeypatch)
        fetched = []

        async def fake_extract(provider, urls, fmt):
            fetched.extend(list(urls))
            return [{"url": u, "content": "leaked"} for u in urls]

        monkeypatch.setattr("tools.web_tools._extract_safe_urls", fake_extract)
        with bound(CTX_AM):
            assert is_safe_url(self.PRIVATE) is False
            assert is_safe_url(self.PUBLIC) is True
            private = json.loads(handle_function_call("web_extract", {"urls": [self.PRIVATE]}))
            public = json.loads(handle_function_call("web_extract", {"urls": [self.PUBLIC]}))
        assert self.PRIVATE not in fetched
        assert self.PUBLIC in fetched
        private_blob = json.dumps(private)
        assert "127.0.0.1" in private_blob
        assert "leaked" not in private_blob

    def test_member_vision_private_denied_with_toggle(self, tmp_path, monkeypatch):
        from tools.image_source import _http_block_reason
        from tools.url_safety import is_safe_url
        self._toggle_home(tmp_path, monkeypatch, "vision")
        fetched = []

        async def fake_download(url):
            fetched.append(url)
            return b"not-an-image"

        monkeypatch.setattr("tools.image_source._download_to_bytes", fake_download)
        with bound(CTX_AM):
            assert is_safe_url(self.PRIVATE) is False
            assert _http_block_reason(self.PRIVATE) == "blocked: unsafe or private URL"
            assert _http_block_reason(self.PUBLIC) is None
        assert fetched == []

    def test_owner_and_ungoverned_keep_toggle(self, tmp_path, monkeypatch):
        from tools.url_safety import is_safe_url
        self._toggle_home(tmp_path, monkeypatch, "owner")
        with bound(CTX_OWNER):
            assert is_safe_url(self.PRIVATE) is True
            assert is_safe_url(self.PUBLIC) is True
        _make_home(tmp_path, monkeypatch, "open", CONFIG_DISABLED)
        monkeypatch.setenv("HERMES_ALLOW_PRIVATE_URLS", "true")
        import tools.url_safety as url_safety
        url_safety._allow_private_resolved = False
        monkeypatch.setattr("tools.url_safety._getaddrinfo", _loopback_or_public_addrinfo)
        with bound(CTX_AM):
            assert is_safe_url(self.PRIVATE) is True

