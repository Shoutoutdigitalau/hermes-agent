"""HTS-04 delegation tests: child toolset intersection, the child-run gate, and
async requester stamps re-resolved at worker start, completion and replay.

Synthetic identities only (``9000000000000000NN``), temp HERMES_HOME written by
the test, synthetic async records only. Behaviour contracts per
INITIAL_SPEC.md section 4 (gates 1, 2, 7, 8): no change-detectors, no
source-text reads, real imports and real seam functions.
"""

from __future__ import annotations

import contextlib
import json
import queue
import sqlite3
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent import team_authz
from agent.team_authz import (
    RequesterContext,
    bind_requester,
    grant_digest,
    reset_requester,
)
from tools import async_delegation as ad
from tools.delegate_tool_child_run import _team_authz_gate_child_run
from tools.delegate_tool_toolsets import _resolve_child_toolsets
from tools.process_registry import process_registry

AM_ID = "900000000000000003"
META_ID = "900000000000000004"
OUTSIDER_ID = "900000000000000009"
OWNER_ID = "900000000000000001"
GUILD = "910000000000000001"

CTX_AM = RequesterContext(platform="discord", user_id=AM_ID, scope_id=GUILD,
                          chat_id="920000000000000003", chat_type="dm")
CTX_META = RequesterContext(platform="discord", user_id=META_ID, scope_id=GUILD,
                            chat_id="920000000000000004", chat_type="dm")
CTX_OUTSIDER = RequesterContext(platform="discord", user_id=OUTSIDER_ID,
                                scope_id=GUILD, chat_id="920000000000000009")

IDENTITY_FIELDS = {"platform", "user_id", "scope_id", "chat_id", "chat_type",
                   "thread_id", "session_key"}

CONFIG_ENABLED = "team_authz:\n  enabled: true\n  governed_platforms: [\"discord\"]\n"


def _member(uid, key, role, status="active"):
    return {"discordUserId": uid, "memberKey": key, "role": role, "status": status,
            "approvedBy": "", "approvedAt": "2026-01-01T00:00:00+00:00"}


def _base_register():
    return {
        "schemaVersion": 1,
        "policyVersion": "2026.09.17-r1",
        "guilds": [GUILD],
        "members": [
            _member(OWNER_ID, "charles", "owner"),
            _member(AM_ID, "lianna", "account_manager"),
            _member(META_ID, "dianne", "meta_ads_operator"),
        ],
        "roles": {
            "owner": {"capabilities": ["basic", "web.read", "ads.meta.write",
                                       "delegate", "owner.host"]},
            "account_manager": {"capabilities": ["basic", "web.read", "ads.brief",
                                                 "ads.read", "delegate"]},
            "meta_ads_operator": {"capabilities": ["basic", "web.read", "ads.read",
                                                   "ads.meta.write", "delegate"]},
        },
        "toolActions": [
            {"pattern": "todo_*", "action": "ads.meta.write"},
            {"pattern": "synth_meta_*", "action": "ads.meta.write"},
        ],
        "connections": [],
        "spendingCaps": [],
        "oversight": {"destinations": []},
    }


def _write_config(home: Path, text: str) -> None:
    (home / "config.yaml").write_text(text, encoding="utf-8")


def _write_register(home: Path, register: dict) -> None:
    d = home / "team_authz"
    d.mkdir(parents=True, exist_ok=True)
    (d / "register.json").write_text(json.dumps(register), encoding="utf-8")
    team_authz._REGISTER_CACHE.clear()


def _audit_rows(home: Path) -> list:
    p = home / "team_authz" / "audit.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()
            if line.strip()]


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "hermes-home"
    h.mkdir()
    _write_config(h, CONFIG_ENABLED)
    _write_register(h, _base_register())
    monkeypatch.setenv("HERMES_HOME", str(h))
    team_authz._REGISTER_CACHE.clear()
    yield h
    team_authz._REGISTER_CACHE.clear()
    monkeypatch.delenv("HERMES_HOME", raising=False)


@pytest.fixture
def home_plain(tmp_path, monkeypatch):
    """Temp home with no team_authz config: ungoverned base behaviour."""
    h = tmp_path / "hermes-home-plain"
    h.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(h))
    team_authz._REGISTER_CACHE.clear()
    yield h
    team_authz._REGISTER_CACHE.clear()
    monkeypatch.delenv("HERMES_HOME", raising=False)


@contextlib.contextmanager
def bound(ctx):
    token = bind_requester(ctx)
    try:
        yield ctx
    finally:
        reset_requester(token)


def _revoke(home: Path, uid: str) -> None:
    reg = json.loads((home / "team_authz" / "register.json").read_text(encoding="utf-8"))
    reg["members"] = [dict(m, status="revoked") if m["discordUserId"] == uid else m
                      for m in reg["members"]]
    _write_register(home, reg)


def _reassign_role(home: Path, uid: str, role: str) -> None:
    reg = json.loads((home / "team_authz" / "register.json").read_text(encoding="utf-8"))
    reg["members"] = [dict(m, role=role) if m["discordUserId"] == uid else m
                      for m in reg["members"]]
    _write_register(home, reg)


@pytest.fixture(autouse=True)
def _clean_async_state():
    ad._reset_for_tests()
    while not process_registry.completion_queue.empty():
        process_registry.completion_queue.get_nowait()
    yield
    deadline = time.monotonic() + 2.0
    while ad.active_count() and time.monotonic() < deadline:
        time.sleep(0.02)
    ad._reset_for_tests()
    while not process_registry.completion_queue.empty():
        process_registry.completion_queue.get_nowait()


@pytest.fixture(autouse=True)
def _clear_toolset_memo():
    import toolsets
    toolsets._resolve_toolset_memo.clear()
    yield
    toolsets._resolve_toolset_memo.clear()


def _drain_for(delegation_id, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not process_registry.completion_queue.empty():
            evt = process_registry.completion_queue.get_nowait()
            if evt.get("delegation_id") == delegation_id:
                return evt
        time.sleep(0.02)
    return None


def _wait_status(delegation_id, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rec = ad._records.get(delegation_id)
        if rec is not None and rec.get("status") not in ("running", "stalling", "finalizing"):
            return rec.get("status")
        time.sleep(0.02)
    return None


def _task_json(home: Path, delegation_id: str) -> dict:
    conn = sqlite3.connect(home / "state.db")
    try:
        row = conn.execute("SELECT task_json FROM async_delegations WHERE delegation_id=?",
                           (delegation_id,)).fetchone()
    finally:
        conn.close()
    assert row is not None
    return json.loads(row[0] or "{}")


def _mock_parent(enabled, disabled=None):
    parent = MagicMock()
    parent.enabled_toolsets = list(enabled)
    parent.disabled_toolsets = list(disabled or [])
    parent._delegate_depth = 0
    parent._active_children = []
    parent._active_children_lock = threading.Lock()
    parent._print_fn = None
    parent.tool_progress_callback = None
    parent.thinking_callback = None
    parent.provider = "openrouter"
    parent.model = "synthetic/test-model"
    parent.api_mode = "chat_completions"
    parent.base_url = "https://example.invalid/v1"
    parent.api_key = "test-key-not-a-secret"
    parent.platform = "cli"
    parent.providers_allowed = None
    parent.providers_ignored = None
    parent.providers_order = None
    parent.provider_sort = None
    parent._session_db = None
    parent.request_overrides = {}
    parent.prefill_messages = None
    return parent


# ---------------------------------------------------------------------------
# Child toolset intersection (gates 2, 7)
# ---------------------------------------------------------------------------


class TestChildToolsetIntersection:
    def test_am_child_loses_meta_toolset(self, home):
        with bound(CTX_AM):
            enabled, disabled = _resolve_child_toolsets(
                _mock_parent(["web", "todo"]), None, "leaf")
        assert "web" in enabled
        assert "todo" not in enabled
        assert "todo" in disabled

    def test_meta_operator_child_keeps_meta_toolset(self, home):
        with bound(CTX_META):
            enabled, disabled = _resolve_child_toolsets(
                _mock_parent(["web", "todo"]), None, "leaf")
        assert "todo" in enabled
        assert "todo" not in disabled

    def test_effective_child_tools_follow_the_requester(self, home):
        from model_tools import _select_tool_names
        with bound(CTX_AM):
            am_enabled, am_disabled = _resolve_child_toolsets(
                _mock_parent(["web", "todo"]), None, "leaf")
        with bound(CTX_META):
            op_enabled, op_disabled = _resolve_child_toolsets(
                _mock_parent(["web", "todo"]), None, "leaf")
        assert "todo_list" not in _select_tool_names(am_enabled, am_disabled, True)
        assert "todo_list" in _select_tool_names(op_enabled, op_disabled, True)

    def test_mcp_inherit_gated_by_role(self, home, monkeypatch):
        import toolsets
        monkeypatch.setitem(toolsets.TOOLSETS, "mcp-synth",
                            {"description": "synthetic", "tools": ["synth_meta_write"],
                             "includes": []})
        toolsets._resolve_toolset_memo.clear()
        with bound(CTX_AM):
            with patch("tools.delegate_tool_toolsets._get_inherit_mcp_toolsets",
                       return_value=True):
                am_enabled, _ = _resolve_child_toolsets(
                    _mock_parent(["web", "mcp-synth"]), ["web"], "leaf")
        with bound(CTX_META):
            with patch("tools.delegate_tool_toolsets._get_inherit_mcp_toolsets",
                       return_value=True):
                op_enabled, _ = _resolve_child_toolsets(
                    _mock_parent(["web", "mcp-synth"]), ["web"], "leaf")
        assert "mcp-synth" not in am_enabled
        assert "mcp-synth" in op_enabled

    def test_unknown_identity_child_gets_no_toolsets(self, home):
        with bound(CTX_OUTSIDER):
            enabled, _ = _resolve_child_toolsets(
                _mock_parent(["web", "todo"]), None, "leaf")
        assert enabled == []

    def test_ungoverned_child_toolsets_unchanged(self, home_plain):
        with patch("tools.delegate_tool_toolsets._get_inherit_mcp_toolsets",
                   return_value=True):
            enabled, disabled = _resolve_child_toolsets(
                _mock_parent(["web", "mcp-X"]), ["web"], "leaf")
        assert enabled == ["web", "mcp-X"]
        assert "kanban" in disabled

    def test_build_child_agent_passes_filtered_toolsets(self, home):
        from tools.delegate_tool import _build_child_agent
        with patch("tools.delegate_tool._load_config",
                   return_value={"inherit_mcp_toolsets": False}):
            with patch("run_agent.AIAgent") as mock_agent:
                mock_agent.return_value = MagicMock()
                with bound(CTX_AM):
                    _build_child_agent(task_index=0, goal="synthetic", context=None,
                                       toolsets=None, model=None, max_iterations=1,
                                       task_count=1,
                                       parent_agent=_mock_parent(["web", "todo"]))
                am_kwargs = mock_agent.call_args[1]
            with patch("run_agent.AIAgent") as mock_agent:
                mock_agent.return_value = MagicMock()
                with bound(CTX_META):
                    _build_child_agent(task_index=0, goal="synthetic", context=None,
                                       toolsets=None, model=None, max_iterations=1,
                                       task_count=1,
                                       parent_agent=_mock_parent(["web", "todo"]))
                op_kwargs = mock_agent.call_args[1]
        assert "todo" not in am_kwargs["enabled_toolsets"]
        assert "todo" in am_kwargs["disabled_toolsets"]
        assert "todo" in op_kwargs["enabled_toolsets"]


# ---------------------------------------------------------------------------
# Child-run gate (gates 1, 8)
# ---------------------------------------------------------------------------


class TestChildRunGate:
    def _child(self):
        child = MagicMock()
        child.run_conversation.return_value = {
            "final_response": "done", "completed": True, "interrupted": False,
            "api_calls": 1, "messages": [],
        }
        return child

    def test_revoked_member_child_dropped_before_backend(self, home):
        from tools.delegate_tool import _run_single_child
        _revoke(home, AM_ID)
        child = self._child()
        with bound(CTX_AM):
            entry = _run_single_child(task_index=0, goal="synthetic", child=child,
                                      parent_agent=_mock_parent(["web"]))
        assert entry["status"] == "error"
        assert "member-revoked" in entry["error"]
        child.run_conversation.assert_not_called()
        rows = _audit_rows(home)
        assert any(r.get("event") == "delegate-drop" and r.get("decision") == "denied"
                   and r.get("reason") == "member-revoked" for r in rows)

    def test_unknown_identity_child_dropped(self, home):
        from tools.delegate_tool import _run_single_child
        child = self._child()
        with bound(CTX_OUTSIDER):
            entry = _run_single_child(task_index=0, goal="synthetic", child=child,
                                      parent_agent=_mock_parent(["web"]))
        assert entry["status"] == "error"
        assert "unknown-identity" in entry["error"]
        child.run_conversation.assert_not_called()

    def test_active_member_child_runs(self, home):
        from tools.delegate_tool import _run_single_child
        child = self._child()
        with bound(CTX_AM):
            entry = _run_single_child(task_index=0, goal="synthetic", child=child,
                                      parent_agent=_mock_parent(["web"]))
        assert entry["status"] == "completed"
        child.run_conversation.assert_called_once()
        rows = _audit_rows(home)
        assert not [r for r in rows if r.get("event") == "delegate-drop"]

    def test_ungoverned_gate_is_open(self, home_plain):
        assert _team_authz_gate_child_run() is None
        assert not (home_plain / "team_authz" / "audit.jsonl").exists()


# ---------------------------------------------------------------------------
# Async requester stamps (gates 1, 8)
# ---------------------------------------------------------------------------


class TestAsyncRequesterStamps:
    def _dispatch(self, runner, **kw):
        return ad.dispatch_async_delegation(
            goal="synthetic goal", context=None, toolsets=None, role="leaf",
            model="synthetic-model", session_key="", runner=runner, **kw)

    def test_dispatch_persists_identity_only_stamp(self, home):
        started = threading.Event()
        done = threading.Event()

        def _runner():
            started.set()
            done.wait(10)
            return {"status": "completed", "summary": "ok"}

        with bound(CTX_AM):
            expected_digest = grant_digest()
            handle = self._dispatch(_runner)
        assert handle["status"] == "dispatched"
        delegation_id = handle["delegation_id"]
        assert started.wait(5)
        done.set()
        evt = _drain_for(delegation_id)
        assert evt is not None and evt["status"] == "completed"
        task = _task_json(home, delegation_id)
        assert task["requester_governed"] is True
        assert set(task["requester_ref"]) == IDENTITY_FIELDS
        assert task["requester_ref"]["user_id"] == AM_ID
        assert task["requester_ref"]["platform"] == "discord"
        assert task["requester_digest"] == expected_digest
        assert "capabilities" not in task["requester_ref"]
        assert "allowed" not in task["requester_ref"]

    def test_worker_drops_revoked_before_runner(self, home):
        _revoke(home, AM_ID)
        started = threading.Event()

        def _runner():
            started.set()
            return {"status": "completed", "summary": "must-not-run"}

        with bound(CTX_AM):
            handle = self._dispatch(_runner)
        assert handle["status"] == "dispatched"
        delegation_id = handle["delegation_id"]
        assert _wait_status(delegation_id) == "dropped"
        assert not started.is_set()
        durable = ad.get_durable_delegation(delegation_id)
        assert durable["state"] == "dropped"
        assert durable["delivery_state"] == "dropped"
        assert _drain_for(delegation_id, timeout=1.0) is None
        rows = _audit_rows(home)
        assert any(r.get("event") == "async-drop" and r.get("reason") == "member-revoked"
                   and r.get("decision") == "denied" for r in rows)

    def test_completion_drops_when_revoked_mid_run(self, home):
        started = threading.Event()
        release = threading.Event()

        def _runner():
            started.set()
            release.wait(10)
            return {"status": "completed", "summary": "ran-while-active"}

        with bound(CTX_AM):
            handle = self._dispatch(_runner)
        delegation_id = handle["delegation_id"]
        assert started.wait(5)
        _revoke(home, AM_ID)
        release.set()
        assert _wait_status(delegation_id) == "dropped"
        assert _drain_for(delegation_id, timeout=1.0) is None
        durable = ad.get_durable_delegation(delegation_id)
        assert durable["result"]["summary"] == "ran-while-active"
        rows = _audit_rows(home)
        assert any(r.get("event") == "async-completion-drop"
                   and r.get("reason") == "member-revoked" for r in rows)

    def test_completion_delivers_when_authorized(self, home):
        with bound(CTX_AM):
            handle = self._dispatch(lambda: {"status": "completed", "summary": "ok"})
        delegation_id = handle["delegation_id"]
        evt = _drain_for(delegation_id)
        assert evt is not None and evt["status"] == "completed"
        assert _wait_status(delegation_id) == "completed"
        rows = _audit_rows(home)
        assert not [r for r in rows if str(r.get("event", "")).startswith("async-")]

    def test_stale_grant_drops_completion(self, home):
        started = threading.Event()
        release = threading.Event()

        def _runner():
            started.set()
            release.wait(10)
            return {"status": "completed", "summary": "ok"}

        with bound(CTX_AM):
            handle = self._dispatch(_runner)
        delegation_id = handle["delegation_id"]
        assert started.wait(5)
        _reassign_role(home, AM_ID, "meta_ads_operator")
        release.set()
        assert _wait_status(delegation_id) == "dropped"
        rows = _audit_rows(home)
        assert any(r.get("event") == "async-completion-drop"
                   and r.get("reason") == "requester-stale" for r in rows)

    def test_ref_less_governed_record_drops(self, home):
        now = time.time()
        record = {
            "delegation_id": "deleg_synth01", "goal": "synthetic",
            "session_key": "", "origin_ui_session_id": "", "origin_session_id": "",
            "parent_session_id": None, "context": None, "toolsets": None,
            "role": "leaf", "model": "synthetic-model",
            "status": "running", "dispatched_at": now, "completed_at": now,
            "requester_ref": {}, "requester_governed": True, "requester_digest": None,
        }
        ad._persist_dispatch(record)
        ad._records["deleg_synth01"] = dict(record)
        ad._finalize("deleg_synth01", {"status": "completed", "summary": "x"}, "completed")
        assert ad._records["deleg_synth01"]["status"] == "dropped"
        assert _drain_for("deleg_synth01", timeout=1.0) is None
        rows = _audit_rows(home)
        assert any(r.get("event") == "async-completion-drop"
                   and r.get("reason") == "no-requester-context" for r in rows)

    def test_replay_drops_revoked_keeps_authorized(self, home):
        with bound(CTX_AM):
            am_handle = self._dispatch(lambda: {"status": "completed", "summary": "am"})
        with bound(CTX_META):
            meta_handle = self._dispatch(lambda: {"status": "completed", "summary": "meta"})
        assert _drain_for(am_handle["delegation_id"]) is not None
        assert _drain_for(meta_handle["delegation_id"]) is not None
        _revoke(home, AM_ID)
        out = queue.Queue()
        assert ad.restore_undelivered_completions(out) == 1
        replayed = out.get_nowait()
        assert replayed["delegation_id"] == meta_handle["delegation_id"]
        assert out.empty()
        assert ad.get_durable_delegation(am_handle["delegation_id"])["delivery_state"] == "dropped"
        rows = _audit_rows(home)
        assert any(r.get("event") == "async-replay-drop"
                   and r.get("reason") == "member-revoked" for r in rows)

    def test_worker_rebinds_ref_provenance(self, home):
        seen = []

        def _runner():
            current = team_authz.current_requester()
            seen.append((current.user_id if current else None,
                         team_authz._provenance()))
            return {"status": "completed", "summary": "ok"}

        with bound(CTX_AM):
            handle = self._dispatch(_runner)
        assert _drain_for(handle["delegation_id"]) is not None
        assert seen == [(AM_ID, "ref")]

    def test_ungoverned_dispatch_runs_as_base(self, home_plain):
        handle = self._dispatch(lambda: {"status": "completed", "summary": "ok"})
        assert handle["status"] == "dispatched"
        evt = _drain_for(handle["delegation_id"])
        assert evt is not None and evt["status"] == "completed"
        task = _task_json(home_plain, handle["delegation_id"])
        assert task["requester_governed"] is False
        assert not (home_plain / "team_authz" / "audit.jsonl").exists()
