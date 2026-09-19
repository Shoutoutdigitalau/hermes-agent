"""Integrated HTS acceptance: real transport, dispatch and isolated persistence.

The component test_team_authz_* suites remain part of the acceptance gate, not
replaced by these cross-component tests. No real provider, identity or home is
used. Gate 9 exercises fresh processes AND A-B-A in one long-lived process.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

from agent import team_authz as authz
from gateway.authz_mixin import TEAM_AUTHZ_DENY_REPLY
from gateway.config import Platform
from gateway.session import SessionSource


def _run(coro):
    """Drive one coroutine; this venv has no pytest-asyncio plugin installed."""
    import asyncio
    return asyncio.run(coro)

GUILD = "910000000000000001"
IDS = {role: f"90000000000000000{i}" for i, role in enumerate((
    "owner", "manager", "account_manager", "meta_ads_operator",
    "content_publisher", "asset_creator", "web_builder"), 1)}
CAPS = {
    "owner": ["owner.host", "register.change", "history.oversight"],
    "manager": ["history.oversight", "register.change"],
    "account_manager": ["ghl.manage"],
    "meta_ads_operator": ["ads.meta.write"],
    "content_publisher": ["content.publish"],
    "asset_creator": ["asset.create"],
    "web_builder": ["site.publish"],
}


def source(role="account_manager", **overrides):
    fields = dict(platform=Platform.DISCORD, user_id=IDS[role], scope_id=GUILD,
                  chat_id="920000000000000003", chat_type="dm",
                  user_name="Charles (Owner)", role_authorized=True)
    fields.update(overrides)
    return SessionSource(**fields)


@contextmanager
def bound(src):
    token = authz.bind_requester(src)
    try:
        yield authz.current_requester()
    finally:
        authz.reset_requester(token)


def register():
    return {
        "schemaVersion": 1, "policyVersion": "acceptance", "guilds": [GUILD],
        "members": [{"discordUserId": uid, "memberKey": role, "role": role,
                     "status": "active", "approvedBy": "synthetic-owner",
                     "approvedAt": "2026-01-01T00:00:00+00:00"}
                    for role, uid in IDS.items()],
        "roles": {role: {"capabilities": caps + ["basic", "web.read", "delegate",
                                                 "history.read.own", "memory.own"]}
                  for role, caps in CAPS.items()},
        "toolActions": [
            {"pattern": "synthetic_" + role, "action": caps[0]}
            for role, caps in CAPS.items()
        ] + [{"pattern": "connectors__ghl__charge", "action": "ghl.manage",
              "connectionId": "synthetic-business", "accountArg": "account",
              "amountArg": "amount", "currencyArg": "currency"}],
        "connections": [{"id": "synthetic-business", "connector": "ghl",
                         "account": "synthetic-account", "ownerClass": "business",
                         "actions": ["ghl.manage"]}],
        "spendingCaps": [{"memberKey": "account_manager", "connectionId": "synthetic-business",
                          "account": "synthetic-account", "currency": "USD",
                          "period": "month", "amount": 100, "scope": "",
                          "approvedBy": "synthetic-owner"}],
        "oversight": {"destinations": [{"chatId": "930000000000000001"}]},
    }


def write_home(home, reg=None):
    (home / "team_authz").mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(json.dumps({"team_authz": {
        "enabled": True, "governed_platforms": ["discord"]}}), encoding="utf-8")
    write_register(home, reg if reg is not None else register())


def write_register(home, reg):
    (home / "team_authz/register.json").write_text(json.dumps(reg), encoding="utf-8")


def rows(home):
    return [json.loads(line) for line in (home / "team_authz/audit.jsonl")
            .read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "isolated"
    write_home(h)
    monkeypatch.setenv("HERMES_HOME", str(h))
    monkeypatch.delenv("HERMES_SESSION_PLATFORM", raising=False)
    authz._REGISTER_CACHE.clear()
    yield h
    authz._REGISTER_CACHE.clear()


@pytest.fixture
def backend(monkeypatch):
    from model_tools import registry
    calls = []

    def dispatch(name, args, **kwargs):
        calls.append(name)
        return json.dumps({"ok": True})

    monkeypatch.setattr(registry, "dispatch", dispatch)
    return calls


MEMBER_HOST_TOOLS = [
    ("computer_use", {"action": "capture"}),
    ("computer", {"code": "print('synthetic')"}),
    ("desktop_preview", {"action": "read"}),
    ("drive_preview", {"action": "evaluate", "code": "document.cookie"}),
    ("read_terminal", {}), ("read_window_below", {}),
    ("skill_manage", {"action": "create"}), ("git_status", {}),
    ("api_client", {"method": "GET", "url": "http://localhost"}),
    ("browser_evaluate", {"expression": "window.location.href"}),
    ("browser_interact", {"action": "evaluate", "code": "1+1"}),
]

MEMBER_LOCAL_MEDIA = [
    ("vision_analyze", {"image_url": "C:/synthetic-private/owner.png"}),
    ("vision_analyze", {"image_url": "file:///synthetic-private/owner.png"}),
    ("image_generate", {"reference_images": ["/synthetic-private/owner.png"]}),
    ("image_generate", {"reference_image_urls": ["/synthetic-private/owner.png"]}),
    ("text_to_speech", {"text": "synthetic", "output_path": "/synthetic-private/owner.wav"}),
]


@pytest.mark.parametrize("tool,args", MEMBER_HOST_TOOLS)
def test_review_member_host_surface_allowed(home, tool, args):
    with bound(source()):
        assert authz.authorize_tool(tool, args, reserve=False).allowed, tool


@pytest.mark.parametrize("tool,args", MEMBER_LOCAL_MEDIA)
def test_review_member_local_media_allowed(home, tool, args):
    from agent.team_authz_perimeter import media_payload_denial
    with bound(source()):
        assert media_payload_denial(args) is None, tool
        assert authz.authorize_tool(tool, args, reserve=False).allowed, tool


def test_review_member_terminal_executes(home, backend):
    from model_tools import handle_function_call
    with bound(source()):
        assert json.loads(handle_function_call("terminal", {"command": "id"}))["ok"]
    assert backend == ["terminal"]


@pytest.mark.parametrize("tool,args,reason", [
    ("browser_vault_list", {}, "protected:credentials"),
    ("browser_vault_fill", {"handle": "synthetic"}, "protected:credentials"),
    ("mcp__gmail__list_messages", {}, "protected:personal-mailbox"),
    ("browser_type", {"fields": [{"selector": "password", "value": "synthetic"}]},
     "protected:browser-login"),
    ("browser_console", {"expression": "document.cookie"}, "protected:browser-machine-info"),
])
def test_review_protected_perimeter_denied_zero_backend(home, backend, tool, args, reason):
    from model_tools import handle_function_call
    with bound(source()):
        assert reason in json.loads(handle_function_call(tool, args))["error"]
    assert backend == []


def test_review_known_connector_unmapped_action_allowed(home, monkeypatch):
    from tools.connectors.dispatch import dispatch_connector_call
    reached = []
    monkeypatch.setattr("tools.connectors.gateway.bridge.run_remote",
                        lambda *a, **k: reached.append(True) or [{"response": {"ok": True}}])
    with bound(source()):
        result = json.loads(dispatch_connector_call("connectors__ghl__unknown_write", {}, "synthetic"))
        assert "response" in result, result
    assert reached


def test_review_empty_mapping_connector_allowed(home, monkeypatch):
    """Mandatory T1 positive control: no register mappings, connector still works."""
    from tools.connectors.dispatch import dispatch_connector_call
    reg = register()
    reg["toolActions"] = []
    reg["connections"] = []
    reg["spendingCaps"] = []
    write_register(home, reg)
    authz._REGISTER_CACHE.clear()
    reached = []
    monkeypatch.setattr("tools.connectors.gateway.bridge.run_remote",
                        lambda *a, **k: reached.append(True) or [{"response": {"ok": True}}])
    with bound(source()):
        result = json.loads(dispatch_connector_call("connectors__ghl__read", {}, "synthetic"))
        assert "response" in result, result
    assert reached


def test_review_in_cap_spend_executes_once_at_full_seam(home, monkeypatch):
    import model_tools
    reached = []
    monkeypatch.setattr(model_tools, "_select_tool_names", lambda *a, **k: {"manage_connections"})
    def remote(plans, *args, **kwargs):
        reached.extend(plans)
        return [{"response": {"ok": True}} for _ in plans]
    monkeypatch.setattr("tools.connectors.gateway.bridge.run_remote", remote)
    args = {"account": "synthetic-account", "amount": 60, "currency": "USD"}
    with bound(source(chat_type="channel")):
        first = json.loads(model_tools.handle_function_call("connectors__ghl__charge", args))
        assert "response" in first, first
        assert "error" in json.loads(model_tools.handle_function_call("connectors__ghl__charge", args))
    assert len(reached) == 1
    spend = [r for r in rows(home) if r.get("decision") == "allowed" and r.get("amount")]
    assert sum(r["amount"] for r in spend) == 60


@pytest.mark.parametrize("damage", ["tail", "edit"])
def test_review_audit_damage_blocks_next_backend(home, backend, damage):
    from model_tools import handle_function_call
    with bound(source()):
        assert authz.log_inbound(summary="first")
        assert authz.log_inbound(summary="second")
        path = home / "team_authz/audit.jsonl"
        lines = path.read_text().splitlines()
        if damage == "tail":
            lines.pop()
        else:
            row = json.loads(lines[0]); row["decision"] = "modified"
            lines[0] = json.dumps(row)
        path.write_text("\n".join(lines) + "\n")
        assert not authz.audit_verify()[0]
        assert "error" in json.loads(handle_function_call("web_search", {}))
    assert backend == []


def test_review_actual_gateway_intake_audits_before_prepare(home, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, MagicMock
    from gateway.run import GatewayRunner
    from contextlib import nullcontext
    runner = object.__new__(GatewayRunner)
    runner._profile_scope_for_source = lambda source: nullcontext()
    runner._hmwa_prepare_turn = AsyncMock(return_value=("prepared-stop", None))
    src = source()
    with bound(src):
        result = _run(runner._handle_message_with_agent_authorized(
            SimpleNamespace(text="synthetic password=do-not-log"), src, MagicMock(), "session", "quick", 1))
    assert result == "prepared-stop"
    assert (home / "team_authz/audit.jsonl").is_file(), "ingress did not write its audit event"
    assert rows(home)[0]["event"] == "message"
    assert rows(home)[0]["discordUserId"] == IDS["account_manager"]
    assert "do-not-log" not in json.dumps(rows(home))
    monkeypatch.setattr(authz, "log_inbound", lambda *a, **k: False)
    runner._hmwa_prepare_turn.reset_mock()
    with bound(src):
        result = _run(runner._handle_message_with_agent_authorized(
            SimpleNamespace(text="synthetic"), src, MagicMock(), "session", "quick", 1))
    runner._hmwa_prepare_turn.assert_not_awaited()
    assert result == TEAM_AUTHZ_DENY_REPLY == "I can't take requests from this account."


def test_review_shadow_records_decision_without_backend(home, backend):
    from model_tools import handle_function_call
    (home / "config.yaml").write_text(json.dumps({"team_authz": {
        "enabled": False, "mode": "shadow", "governed_platforms": ["discord"]}}))
    with bound(source()):
        result = json.loads(handle_function_call("web_search", {"query": "synthetic"}))
        assert "error" in result
    assert not backend
    assert any(r["event"] == "shadow" for r in rows(home))


@pytest.mark.parametrize("field", ["content", "body", "text", "summary", "arbitrary_nested_field"])
def test_review_dm_publication_cannot_omit_or_rename_consent(home, monkeypatch, field):
    import model_tools
    reached = []
    monkeypatch.setattr(model_tools, "_select_tool_names", lambda *a, **k: {"manage_connections"})
    monkeypatch.setattr("tools.connectors.gateway.bridge.run_remote",
                        lambda *a, **k: reached.append(True) or [{"response": {"ok": True}}])
    args = {"account": "synthetic-account", "amount": 60, "currency": "USD",
            field: {"nested": "private synthetic DM"}, "private_source_owners": []}
    with bound(source()):
        result = json.loads(model_tools.handle_function_call("connectors__ghl__charge", args))
        assert "error" in result
    assert not reached


def test_review_mapped_nonconnector_sink_requires_dm_consent(home, backend):
    from model_tools import handle_function_call
    reg = register()
    reg["toolActions"].append({"pattern": "synthetic_notes_publish", "action": "ghl.manage",
                               "connectionId": "synthetic-business", "accountArg": "account"})
    write_register(home, reg)
    with bound(source()):
        result = json.loads(handle_function_call("synthetic_notes_publish", {
            "account": "synthetic-account", "target": "shared-board",
            "body": "synthetic private DM", "private_source_owners": []}))
    assert "consent-required" in result.get("error", ""), result
    assert backend == []


def test_review_direct_media_resolver_allows_member_own_file(home, tmp_path):
    import base64
    from tools import image_source
    raw = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
    path = tmp_path / "synthetic-owner.png"
    path.write_bytes(raw)
    with bound(source()):
        resolved = _run(image_source.resolve_image_source(str(path), image_source.ResolveContext()))
    assert resolved.origin == "file"
    assert resolved.data == raw


def test_review_gateway_media_scope_binds_transport_and_delivers_own_file(home):
    from types import SimpleNamespace
    from gateway.platforms.base import BasePlatformAdapter, validate_media_delivery_path
    private = home / "cache/owner-private.png"
    private.parent.mkdir()
    private.write_bytes(b"synthetic-owner-image")
    adapter = SimpleNamespace(gateway_runner=None, name="synthetic")
    assert authz.current_requester() is None
    with BasePlatformAdapter._media_delivery_scope(adapter, source()):
        assert authz.current_requester().user_id == IDS["account_manager"]
        assert validate_media_delivery_path(str(private)) == str(private.resolve())
    assert authz.current_requester() is None
    with BasePlatformAdapter._media_delivery_scope(adapter, source("owner")):
        assert validate_media_delivery_path(str(private)) == str(private.resolve())


def test_review_gateway_media_delivery_allows_member_local_file(home, monkeypatch):
    from gateway.platforms.base import _validated_delivery_path
    private = home / "cache/owner-private.png"
    private.parent.mkdir()
    private.write_bytes(b"synthetic-owner-image")
    monkeypatch.setattr("gateway.media_fetch.fetch_remote_media",
                        lambda *a, **k: pytest.fail("existing local file reached remote fetch"))
    with bound(source()):
        assert _validated_delivery_path(str(private), "synthetic", "test") == str(private.resolve())


def test_review_produced_media_is_deliverable_by_a_teammate(home):
    from gateway.platforms.base import _write_cache_file, validate_media_delivery_path
    cache_dir = home / "cache-out"
    cache_dir.mkdir()
    with bound(source()):
        path = _write_cache_file(cache_dir, "synthetic", ".png", b"synthetic image")
        assert validate_media_delivery_path(path) == path
    with bound(source("asset_creator")):
        assert validate_media_delivery_path(path) == path


def test_review_registry_visible_except_protected(home):
    from model_tools import registry
    installed = set(registry.get_all_tool_names())
    assert installed
    with bound(source()):
        visible = set(authz.filter_tool_names(installed))
    hidden = {n for n in installed if authz.classify_protected(n)}
    assert hidden, "baseline must expose a protected tool or this proves nothing"
    assert visible == installed - hidden


@pytest.mark.parametrize("role,allowed", [("account_manager", False), ("meta_ads_operator", True)])
def test_review_meta_role_at_direct_and_real_child_dispatch(home, monkeypatch, role, allowed):
    import threading
    from unittest.mock import MagicMock
    import model_tools
    from tools.delegate_tool import _run_single_child
    reg = register()
    reg["connections"].append({"id": "synthetic-meta", "connector": "metaads", "account": "act-synthetic",
                               "ownerClass": "business", "actions": ["ads.meta.write"]})
    reg["toolActions"].append({"pattern": "connectors__metaads__set_budget", "action": "ads.meta.write",
                              "connectionId": "synthetic-meta", "accountArg": "account",
                              "amountArg": "amount", "currencyArg": "currency"})
    reg["spendingCaps"].append({"memberKey": "meta_ads_operator", "connectionId": "synthetic-meta",
                               "account": "act-synthetic", "currency": "USD", "period": "month",
                               "amount": 100, "scope": "", "approvedBy": "synthetic-owner"})
    write_register(home, reg)
    reached = []
    monkeypatch.setattr(model_tools, "_select_tool_names", lambda *a, **k: {"manage_connections"})
    def remote(plans, *a, **k):
        reached.extend(plans)
        return [{"response": {"ok": True}} for _ in plans]
    monkeypatch.setattr("tools.connectors.gateway.bridge.run_remote", remote)
    def invoke(*a, **k):
        response = model_tools.handle_function_call("connectors__metaads__set_budget", {
            "account": "act-synthetic", "amount": 10, "currency": "USD"})
        return {"final_response": response, "completed": True, "interrupted": False,
                "api_calls": 1, "messages": []}
    parent, child = MagicMock(), MagicMock()
    parent._active_children = []
    parent._active_children_lock = threading.Lock()
    parent._print_fn = parent.tool_progress_callback = parent.thinking_callback = None
    child.run_conversation.side_effect = invoke
    with bound(source(role, chat_type="channel")):
        direct = invoke()["final_response"]
        entry = _run_single_child(task_index=0, goal="synthetic", child=child, parent_agent=parent)
    assert entry["status"] == "completed", entry
    child.run_conversation.assert_called_once()
    assert ("response" in json.loads(direct)) is allowed
    assert len(reached) == (2 if allowed else 0)
    if not allowed:
        assert "role-missing-action" in direct


def test_review_real_child_resolution_filters_inherited_mcp(home, monkeypatch):
    from types import SimpleNamespace
    from tools import delegate_tool_toolsets as toolsets
    monkeypatch.setitem(toolsets.TOOLSETS, "mcp-synthetic-host", {"tools": ["terminal"], "includes": []})
    monkeypatch.setitem(toolsets.TOOLSETS, "mcp-synthetic-private", {"tools": ["browser_vault_list"], "includes": []})
    monkeypatch.setitem(toolsets.TOOLSETS, "mcp-synthetic-public", {"tools": ["web_search"], "includes": []})
    monkeypatch.setattr(toolsets, "_get_inherit_mcp_toolsets", lambda: True)
    parent = SimpleNamespace(enabled_toolsets=["web", "mcp-synthetic-host", "mcp-synthetic-private",
                                              "mcp-synthetic-public"],
                             disabled_toolsets=[])
    with bound(source()):
        enabled, disabled = toolsets._resolve_child_toolsets(parent, ["web"], "leaf")
    assert "mcp-synthetic-host" in enabled           # terminal work stays open (T1)
    assert "mcp-synthetic-private" not in enabled    # credentials toolset still filtered
    assert "mcp-synthetic-private" in disabled
    assert "mcp-synthetic-public" in enabled
    assert "web" in enabled


def test_gate1_transport_to_dispatch_identity(home, backend):
    from model_tools import handle_function_call
    from gateway.run import GatewayRunner
    runner = object.__new__(GatewayRunner)
    with bound(source()) as ctx:
        assert ctx.platform == "discord"
        assert ctx.user_id == IDS["account_manager"]
        assert runner._team_authz_turn_deny_reply(source()) is None
        assert authz.log_inbound(summary="synthetic request")
        assert json.loads(handle_function_call("web_search", {"query": "synthetic"}))["ok"]
    assert backend == ["web_search"]
    with bound(source(user_id="900000000000000099")):
        assert runner._team_authz_turn_deny_reply(source(user_id="900000000000000099")) == TEAM_AUTHZ_DENY_REPLY
        assert "error" in json.loads(handle_function_call("web_search", {}))
    assert backend == ["web_search"]


@pytest.mark.parametrize("role", list(IDS))
def test_gate2_recorded_roles_reach_only_authorized_dispatch(home, backend, role):
    from model_tools import handle_function_call
    with bound(source(role)):
        assert json.loads(handle_function_call("synthetic_" + role, {}))["ok"]
        # Ordinary host work is open to every registered teammate (T1).
        assert json.loads(handle_function_call("terminal", {"command": "id"}))["ok"]
    # Owner is intentionally unrestricted by role; an unlisted transport scope
    # must still fail. Do not invent an owner outside-role permission restriction.
    with bound(source(role, scope_id="910000000000000099")):
        assert "error" in json.loads(handle_function_call("synthetic_" + role, {}))
    assert backend == ["synthetic_" + role, "terminal"]


@pytest.mark.parametrize("tool", ["terminal", "read_file", "execute_code", "browser_exec"])
def test_gate3_host_surface_open_to_every_registered_member(home, backend, tool):
    from model_tools import handle_function_call
    with bound(source()):
        assert json.loads(handle_function_call(tool, {}))["ok"]
    assert backend == [tool]
    with bound(source("owner")):
        assert json.loads(handle_function_call(tool, {}))["ok"]
    assert backend == [tool, tool]


@pytest.mark.parametrize("tool", ["browser_vault_list", "browser_vault_unlock", "browser_vault_fill"])
def test_gate3_owner_perimeter_denied_before_backend(home, backend, tool):
    from model_tools import handle_function_call
    with bound(source()):
        assert "error" in json.loads(handle_function_call(tool, {}))
    assert backend == []


def test_gate4_5_real_history_ownership_and_oversight(home, tmp_path):
    from hermes_state import SessionDB
    from tools.session_search_tool import session_search
    db = SessionDB(tmp_path / "synthetic-state.db")
    try:
        for role in ("account_manager", "owner", "content_publisher"):
            db.create_session(role, source="discord", user_id=IDS[role],
                              chat_id="920000000000000003" if role == "account_manager"
                              else "920000000000000088", chat_type="dm")
            db.append_message(role, role="user", content=role + " private sentinel")
        with bound(source()):
            assert json.loads(session_search(db=db, session_id="account_manager"))["success"]
            assert not json.loads(session_search(db=db, session_id="content_publisher"))["success"]
            assert not json.loads(session_search(db=db, session_id="owner"))["success"]
        with bound(source("manager", chat_id="930000000000000001", chat_type="channel")):
            assert json.loads(session_search(db=db, session_id="account_manager"))["success"]
            assert not json.loads(session_search(db=db, session_id="owner"))["success"]
        assert any(r.get("event") == "oversight" for r in rows(home))
        with bound(source("manager", chat_id="930000000000000099", chat_type="channel")):
            assert not json.loads(session_search(db=db, session_id="account_manager"))["success"]
    finally:
        db.close()


def test_gate6_7_connector_cap_denies_before_remote(home, monkeypatch):
    from tools.connectors.dispatch import dispatch_connector_call
    calls = []

    def remote(plans, *args, **kwargs):
        calls.extend(plans)
        return [{"index": p.position, "name": p.name, "response": {"ok": True}} for p in plans]

    monkeypatch.setattr("tools.connectors.gateway.bridge.run_remote", remote)
    args = {"account": "synthetic-account", "amount": 60, "currency": "USD"}
    # Spend-cap proof uses a shared-channel origin; DM publication consent has
    # its own negative and positive seam tests below.
    with bound(source(chat_type="channel")):
        assert "response" in json.loads(dispatch_connector_call("connectors__ghl__charge", args, "first"))
        for denied in (args, dict(args, currency="EUR"), dict(args, account="unapproved")):
            assert "error" in json.loads(dispatch_connector_call("connectors__ghl__charge", denied, "denied"))
        # Unmapped connectors are ordinary team work (T1): no inventory denial.
        assert "response" in json.loads(dispatch_connector_call("connectors__ghl__proxy_fetch", {}, "unmapped"))
    assert len(calls) == 2


def test_gate8_revocation_crosses_live_dispatch_and_cron(home, backend, monkeypatch):
    from model_tools import handle_function_call
    from cron.jobs import create_job
    from cron.scheduler import _gate_job_requester, run_job
    with bound(source()):
        assert json.loads(handle_function_call("web_search", {}))["ok"]
        job = create_job(prompt="synthetic", schedule="2030-01-02T03:04:05Z", name="acceptance")
        assert _gate_job_requester(job, job["id"], job["name"]) is None
        before = authz.grant_digest()
        reg = register()
        reg["members"][2]["status"] = "revoked"
        write_register(home, reg)
        assert authz.grant_digest() != before
        assert "error" in json.loads(handle_function_call("web_search", {}))
    assert backend == ["web_search"]
    monkeypatch.setattr("run_agent.AIAgent", lambda **kw: pytest.fail("revoked job reached agent"))
    success, _, _, error = run_job(job)
    assert not success and "member-revoked" in error


def test_inbound_audit_is_redacted_and_ordered(home, backend):
    from model_tools import handle_function_call
    secret = "synthetic-secret-not-a-real-credential"
    with bound(source()):
        assert authz.log_inbound(summary="password=" + secret)
        assert json.loads(handle_function_call("web_search", {}))["ok"]
    trail = rows(home)
    assert trail[0]["event"] == "message"
    assert trail[-1]["event"] == "authorize"
    assert trail[-1]["tool"] == "web_search"
    assert trail[-1]["discordUserId"] == IDS["account_manager"]
    assert trail[0]["summaryBytes"] == len(("password=" + secret).encode("utf-8"))
    assert len(trail[0]["summaryHash"]) == 64
    assert trail[0]["chatId"] == source().chat_id
    assert secret not in json.dumps(trail)
    assert authz.audit_verify() == (True, None)


def test_rejected_amount_is_not_copied_to_audit(home):
    marker = "synthetic-secret-in-invalid-amount"
    with bound(source()):
        decision = authz.authorize_tool("connectors__ghl__charge", {
            "account": "synthetic-account", "currency": "USD", "amount": marker})
    assert not decision.allowed and decision.reason == "cap-amount-unparsable"
    assert marker not in json.dumps(rows(home))


def test_gate9_two_homes_aba_in_fresh_processes(home, tmp_path):
    other = tmp_path / "other"
    reg = register()
    reg["members"][2]["status"] = "revoked"
    write_home(other, reg)
    script = '''
import asyncio, json, os, sys
from types import SimpleNamespace
from contextlib import nullcontext
from unittest.mock import AsyncMock
from model_tools import handle_function_call, registry
from gateway.run import GatewayRunner
from agent import team_authz as a
from gateway.config import Platform
from gateway.session import SessionSource
from hermes_constants import set_hermes_home_override, reset_hermes_home_override
from agent.secret_scope import set_multiplex_active, set_secret_scope, reset_secret_scope
set_multiplex_active(True)
# The process home deliberately points at B: context-local A must override it.
os.environ["HERMES_HOME"] = sys.argv[2]
out = []
registry.dispatch = lambda *args, **kwargs: json.dumps({"ok": True})
runner = object.__new__(GatewayRunner)
runner._profile_scope_for_source = lambda source: nullcontext()
async def prepare(*args, **kwargs):
    return handle_function_call("web_search", {"query": "synthetic"}), None
runner._hmwa_prepare_turn = AsyncMock(side_effect=prepare)
for h in sys.argv[1:]:
    home_token = set_hermes_home_override(h)
    secret_token = set_secret_scope({})
    src = SessionSource(platform=Platform.DISCORD, user_id="900000000000000003",
                        scope_id="910000000000000001", chat_id="920000000000000003", chat_type="dm")
    token = a.bind_requester(src)
    try:
        response = asyncio.run(runner._handle_message_with_agent_authorized(
            SimpleNamespace(text="synthetic turn"), src, None, "synthetic", "quick", 1))
        out.append(response == json.dumps({"ok": True}))
    finally:
        a.reset_requester(token)
        reset_secret_scope(secret_token)
        reset_hermes_home_override(home_token)
print(json.dumps(out))
'''
    env = dict(os.environ)
    root = str(Path(__file__).resolve().parents[2])
    env["PYTHONPATH"] = root
    for _ in range(2):
        result = subprocess.run([sys.executable, "-c", script, str(home), str(other), str(home)],
                                cwd=root, env=env, capture_output=True, text=True, timeout=45)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == [True, False, True]
    observed = rows(home)
    assert {r["decision"] for r in observed} <= {"received", "checked", "allowed"}
    # Each fresh process runs A twice; preflights must not masquerade as executions.
    assert sum(r["event"] == "message" for r in observed) == 2 * 2
    assert sum(r["decision"] == "allowed" for r in observed) == 2 * 2
    assert all(r["tool"] == "web_search" for r in observed if r["event"] == "authorize")
    denied = [r for r in rows(other) if r["event"] != "message"]
    assert denied and all(r["decision"] == "denied" for r in denied)
    assert any(r["event"] == "message" for r in rows(home))
    assert any(r["event"] == "message" for r in rows(other))


@pytest.mark.parametrize("path", ["/synthetic-private/owner.png", "C:/synthetic-private/owner.png", "file:///synthetic-private/owner.png"])
def test_review_b11_nested_delegate_images_allowed(home, backend, path):
    with bound(source()):
        payload = {"tasks": [{"goal": "inspect", "images": [path]}]}
        assert authz.authorize_tool("delegate_task", payload, reserve=False).allowed
        assert authz.authorize_tool("delegate_task", payload, reserve=True).allowed
    assert backend == []


@pytest.mark.parametrize("mode", ["native", "text"])
def test_review_b11_child_image_boundary_reaches_reader(home, monkeypatch, mode):
    from types import SimpleNamespace
    from agent import image_routing
    from tools.delegate_tool_child_run import _build_child_goal_message
    reads = []
    monkeypatch.setattr(image_routing, "decide_image_input_mode", lambda *a, **kw: mode)
    monkeypatch.setattr(image_routing, "build_native_content_parts", lambda *a: (
        reads.append(a) or [{"type": "image_url", "image_url": {"url": "data:image/png;base64,U0VOVElORUw="}}], []))
    with bound(source()):
        result = _build_child_goal_message("inspect", ["/synthetic-private/owner.png"], SimpleNamespace())
    if mode == "native":
        assert reads, "reader must be reached once the provenance gate is gone"
        assert any(p.get("type") == "image_url" for p in result)
    else:
        assert result == "inspect"


@pytest.fixture
def synthetic_browser_dns(monkeypatch):
    import socket
    from tools import url_safety
    def resolve(host, *args, **kwargs):
        if host == "unresolved.example":
            raise socket.gaierror("synthetic DNS failure")
        import ipaddress
        try:
            ip = str(ipaddress.ip_address(host))
        except ValueError:
            ip = "8.8.8.8" if host == "public.example" else "127.0.0.1"
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443))]
    monkeypatch.setattr(url_safety, "_getaddrinfo", resolve)
    monkeypatch.setattr(url_safety, "_global_allow_private_urls", lambda: True)
    monkeypatch.setattr(url_safety, "_proxy_is_configured", lambda: True)


@pytest.mark.parametrize("url", [
    "http://localhost:9119/", "http://127.0.0.1/", "http://127.1/", "http://2130706433/",
    "http://10.1.2.3/", "http://192.168.1.1/", "http://[::1]/", "http://[::ffff:127.0.0.1]/",
    "http://private.example/", "http://unresolved.example/",
])
def test_review_b12_navigation_denied_before_dispatch(home, backend, synthetic_browser_dns, url):
    from model_tools import handle_function_call
    with bound(source()):
        result = json.loads(handle_function_call("browser_navigate", {"url": url}))
    assert "error" in result
    assert backend == []


def test_review_b12_public_navigation_retains_member_access(home, backend, synthetic_browser_dns):
    from model_tools import handle_function_call
    with bound(source()):
        assert json.loads(handle_function_call("browser_navigate", {"url": "https://public.example/"}))["ok"]
    assert backend == ["browser_navigate"]


def test_review_b12_local_backend_and_redirect_are_guarded(home, monkeypatch, synthetic_browser_dns):
    from tools import browser_tool as bt
    calls = []
    monkeypatch.setattr(bt._cloud, "_is_local_backend", lambda: True)
    monkeypatch.setattr(bt._cloud, "_allow_private_urls", lambda: True)
    monkeypatch.setattr(bt, "_is_always_blocked_url", lambda url: False)
    monkeypatch.setattr(bt._session, "_run_browser_command", lambda *a, **kw: calls.append(a) or {"success": True})
    with bound(source()):
        assert bt._url_policy_error("http://127.0.0.1/", auto_local=True) is not None
        assert bt._post_redirect_block("synthetic", "https://public.example/", "http://127.0.0.1/", True) is not None
    assert calls == [("synthetic", "open", ["about:blank"])]


def test_review_b12_unverified_page_probe_fails_closed(home, monkeypatch, synthetic_browser_dns):
    from tools import browser_tool as bt
    monkeypatch.setattr(bt._cloud, "_is_local_backend", lambda: True)
    monkeypatch.setattr(bt._session, "_run_browser_command", lambda *a, **kw: {"success": False})
    with bound(source()):
        assert bt._blocked_private_page_content("synthetic") is not None


@pytest.mark.parametrize("mode", ["native", "text"])
def test_review_b11_public_inline_and_local_images_work(home, tmp_path, monkeypatch, mode):
    import base64
    from types import SimpleNamespace
    from tools.delegate_tool_child_run import _build_child_goal_message
    raw = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
    local = tmp_path / "synthetic-owner.png"
    local.write_bytes(raw)
    monkeypatch.setattr("agent.image_routing.decide_image_input_mode", lambda *a, **kw: mode)
    url = "https://public.example/image.png"
    inline = "data:image/png;base64," + base64.b64encode(raw).decode()
    refs = [str(local), url, inline]
    with bound(source()):
        assert authz.authorize_tool(
            "delegate_task", {"tasks": [{"goal": "inspect", "images": refs}]}, reserve=False).allowed
        result = _build_child_goal_message("inspect", refs, SimpleNamespace())
        if mode == "native":
            assert sum(part.get("type") == "image_url" for part in result) == 3
        else:
            assert str(local) in result and url in result
            assert "base64," not in result


def test_review_b11_common_image_reader_allows_member_path(home, tmp_path):
    import base64
    from agent.image_routing import _file_to_data_url
    path = tmp_path / "synthetic-owner.png"
    path.write_bytes(base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="))
    with bound(source()):
        assert _file_to_data_url(path).startswith("data:image/png;base64,")
    with bound(source("owner")):
        assert _file_to_data_url(path).startswith("data:image/png;base64,")


def test_review_b12_camofox_direct_navigation_and_redirect(home, monkeypatch, synthetic_browser_dns):
    from tools import browser_camofox as cf
    calls = []
    session = {"tab_id": "synthetic", "user_id": "synthetic"}
    monkeypatch.setattr(cf, "_rewrite_loopback_url_for_camofox", lambda url: (url, None))
    monkeypatch.setattr(cf, "_navigate_tab", lambda *a: (calls.append(a) or session, {"url": "http://127.0.0.1/", "title": "PRIVATE-SENTINEL"}))
    monkeypatch.setattr(cf, "_post", lambda *a, **kw: {"result": "http://127.0.0.1/"})
    monkeypatch.setattr(cf, "_fetch_snapshot", lambda *a: ("PRIVATE-SENTINEL", 1))
    monkeypatch.setattr(cf, "get_vnc_url", lambda: "http://127.0.0.1:9999/")
    with bound(source()):
        assert "error" in json.loads(cf.camofox_navigate("http://127.0.0.1/"))
        assert calls == []
        result = cf.camofox_navigate("https://public.example/")
        assert "error" in json.loads(result)
        assert "PRIVATE-SENTINEL" not in result
        assert "vnc_url" not in result


@pytest.mark.parametrize("failure", ["empty", "exception"])
def test_review_b12_camofox_unknown_page_fails_closed(home, monkeypatch, synthetic_browser_dns, failure):
    from tools import browser_camofox as cf
    from tools.browser_tool_eval_policy import _camofox_current_page_private_url
    def probe(*args, **kwargs):
        if failure == "exception":
            raise RuntimeError("synthetic probe unavailable")
        return {}
    monkeypatch.setattr(cf, "_post", probe)
    with bound(source()):
        assert _camofox_current_page_private_url("synthetic", "synthetic") is not None


@pytest.mark.parametrize("role", [role for role in IDS if role != "owner"])
def test_review_b10_every_member_denies_outside_role_action(home, role):
    target = next(other for other in IDS if other != "owner" and CAPS[other][0] not in CAPS[role])
    with bound(source(role)):
        assert authz.authorize_tool("synthetic_" + role, {}).allowed
        assert not authz.authorize_tool("synthetic_" + target, {}).allowed


def test_review_b12_explicit_context_cannot_bypass_browser_guard(home, synthetic_browser_dns):
    with bound(source()) as ctx:
        saved = ctx
    assert not authz.authorize_tool("browser_navigate", {"url": "http://127.0.0.1/"}, saved).allowed

