"""HTS-02 gateway tests: transport binding, turn refusal, toolset trap, cache
staleness, owner-context exclusion.

Synthetic identities only (``9000000000000000NN``), temp HERMES_HOME written by
the test, real imports and real dispatch of the gateway seam methods. Behaviour
contracts per INITIAL_SPEC.md section 4: no change-detectors, no source-text
reads. Covers ticket HTS-02 outcome: governed sessions bind the requester from
SessionSource user_id/scope_id, refuse denied principals with a fixed reply
before any agent build or model call, treat override exceptions and empty
toolset results as denials, bust the agent cache when grants change, and build
governed non-owner agents without owner context files. Ungoverned sessions and
disabled config behave exactly as base.
"""

from __future__ import annotations

import dataclasses
import json
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent import team_authz
from agent.team_authz import (
    TeamAuthzDenied,
    bind_requester,
    current_requester,
    grant_digest,
    reset_requester,
)
from gateway.authz_mixin import TEAM_AUTHZ_DENY_REPLY
from gateway.config import Platform
from gateway.session import SessionSource

# ---------------------------------------------------------------------------
# Synthetic identities (never real)
# ---------------------------------------------------------------------------

OWNER_ID = "900000000000000001"
AM_ID = "900000000000000003"
OUTSIDER_ID = "900000000000000009"
GUILD = "910000000000000001"
OTHER_GUILD = "910000000000000002"
CHAT = "920000000000000099"

FIXED_REPLY = "I can't take requests from this account."


def _run(coro):
    """Drive one coroutine; this venv has no pytest-asyncio plugin installed."""
    import asyncio
    return asyncio.run(coro)


def _member(uid: str, key: str, role: str, status: str = "active") -> dict:
    return {"discordUserId": uid, "memberKey": key, "role": role, "status": status,
            "approvedBy": "", "approvedAt": "2026-01-01T00:00:00+00:00"}


def _base_register() -> dict:
    return {
        "schemaVersion": 1,
        "policyVersion": "2026.09.17-r1",
        "guilds": [GUILD],
        "members": [
            _member(OWNER_ID, "charles", "owner"),
            _member(AM_ID, "lianna", "account_manager"),
        ],
        "roles": {
            "owner": {"capabilities": ["basic", "owner.host", "history.read.own"]},
            "account_manager": {"capabilities": ["basic", "history.read.own"]},
        },
        "toolActions": [],
        "connections": [],
        "spendingCaps": [],
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
CONFIG_MALFORMED = "team_authz: [not, a, mapping]\n"


def _audit_rows(home: Path) -> list:
    p = home / "team_authz" / "audit.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Temp HERMES_HOME: team_authz enabled for discord, owner + AM registered."""
    h = tmp_path / "hermes-home"
    h.mkdir()
    _write_config(h, CONFIG_ENABLED)
    _write_register(h, _base_register())
    monkeypatch.setenv("HERMES_HOME", str(h))
    monkeypatch.delenv("HERMES_SESSION_PLATFORM", raising=False)
    team_authz._REGISTER_CACHE.clear()
    yield h
    team_authz._REGISTER_CACHE.clear()
    monkeypatch.delenv("HERMES_HOME", raising=False)


def _src(uid, *, platform=Platform.DISCORD, scope=GUILD, chat=CHAT,
         user_name="someone", role_authorized=False) -> SessionSource:
    return SessionSource(
        platform=platform, chat_id=chat, chat_type="dm", user_id=uid,
        user_name=user_name, scope_id=scope, role_authorized=role_authorized,
    )


def _runner():
    """Bare GatewayRunner: real mixin methods, no live state."""
    from gateway.run import GatewayRunner
    return object.__new__(GatewayRunner)


class _Bound:
    """Bind a transport source for the body; always reset afterwards."""

    def __init__(self, source):
        self.source = source
        self.token = None

    def __enter__(self):
        self.token = bind_requester(self.source)
        return current_requester()

    def __exit__(self, *exc):
        reset_requester(self.token)
        self.token = None
        return False


def _revoke(home: Path, uid: str) -> None:
    reg = _base_register()
    reg["members"] = [
        dict(m, status="revoked") if m["discordUserId"] == uid else m
        for m in reg["members"]
    ]
    _write_register(home, reg)


# ---------------------------------------------------------------------------
# Binding: verified transport provenance
# ---------------------------------------------------------------------------


class TestBindRequester:
    def test_bind_uses_transport_user_and_scope_ids(self, home):
        runner = _runner()
        source = _src(AM_ID, user_name="Charles (Owner)", role_authorized=True)
        token = runner._team_authz_bind_requester(source)
        try:
            ctx = current_requester()
            assert ctx.user_id == AM_ID
            assert ctx.scope_id == GUILD
            assert ctx.platform == "discord"
        finally:
            runner._team_authz_reset_requester(token)
        assert current_requester() is None

    def test_reset_tolerates_none(self, home):
        _runner()._team_authz_reset_requester(None)
        assert current_requester() is None


# ---------------------------------------------------------------------------
# Turn gate: governed denied principals get the fixed reply
# ---------------------------------------------------------------------------


class TestTurnGate:
    def test_active_member_proceeds_without_audit(self, home):
        runner = _runner()
        with _Bound(_src(AM_ID)):
            assert runner._team_authz_turn_deny_reply(_src(AM_ID)) is None
        assert _audit_rows(home) == []

    def test_owner_proceeds(self, home):
        runner = _runner()
        with _Bound(_src(OWNER_ID)):
            assert runner._team_authz_turn_deny_reply(_src(OWNER_ID)) is None

    def test_unknown_identity_fixed_reply_and_audit(self, home):
        runner = _runner()
        with _Bound(_src(OUTSIDER_ID)):
            assert runner._team_authz_turn_deny_reply(_src(OUTSIDER_ID)) == FIXED_REPLY
        rows = _audit_rows(home)
        assert len(rows) == 1
        assert rows[0]["decision"] == "denied"
        assert rows[0]["reason"] == "unknown-identity"
        assert rows[0]["discordUserId"] == OUTSIDER_ID

    def test_revoked_member_same_fixed_reply(self, home):
        _revoke(home, AM_ID)
        runner = _runner()
        with _Bound(_src(AM_ID)):
            reply = runner._team_authz_turn_deny_reply(_src(AM_ID))
        assert reply == FIXED_REPLY
        assert _audit_rows(home)[0]["reason"] == "member-revoked"

    def test_wrong_guild_same_fixed_reply(self, home):
        runner = _runner()
        with _Bound(_src(AM_ID, scope=OTHER_GUILD)):
            assert runner._team_authz_turn_deny_reply(_src(AM_ID, scope=OTHER_GUILD)) == FIXED_REPLY

    def test_display_name_spoof_denied(self, home):
        runner = _runner()
        source = _src("Charles (Owner)", user_name="charles")
        with _Bound(source):
            assert runner._team_authz_turn_deny_reply(source) == FIXED_REPLY
        assert _audit_rows(home)[0]["reason"] == "unknown-identity"

    def test_role_authorized_true_never_authorizes(self, home):
        runner = _runner()
        source = _src(OUTSIDER_ID, role_authorized=True)
        with _Bound(source):
            assert runner._team_authz_turn_deny_reply(source) == FIXED_REPLY

    def test_empty_register_denies_owner_too(self, home):
        reg = _base_register()
        reg["members"] = []
        _write_register(home, reg)
        runner = _runner()
        with _Bound(_src(OWNER_ID)):
            assert runner._team_authz_turn_deny_reply(_src(OWNER_ID)) == FIXED_REPLY

    def test_malformed_config_denies(self, home):
        _write_config(home, CONFIG_MALFORMED)
        runner = _runner()
        with _Bound(_src(AM_ID)):
            assert runner._team_authz_turn_deny_reply(_src(AM_ID)) == FIXED_REPLY

    def test_disabled_config_proceeds_as_base(self, home):
        _write_config(home, CONFIG_DISABLED)
        runner = _runner()
        with _Bound(_src(OUTSIDER_ID)):
            assert runner._team_authz_turn_deny_reply(_src(OUTSIDER_ID)) is None
        assert _audit_rows(home) == []

    def test_unlisted_platform_proceeds_as_base(self, home):
        runner = _runner()
        source = _src(OUTSIDER_ID, platform=Platform.TELEGRAM, scope=None)
        with _Bound(source):
            assert runner._team_authz_turn_deny_reply(source) is None
        assert _audit_rows(home) == []

    def test_fixed_reply_matches_module_constant(self, home):
        assert TEAM_AUTHZ_DENY_REPLY == FIXED_REPLY

    def test_deny_reasons_never_leak_into_reply(self, home):
        runner = _runner()
        with _Bound(_src(OUTSIDER_ID)):
            reply = runner._team_authz_turn_deny_reply(_src(OUTSIDER_ID))
        for leaked in ("unknown-identity", "revoked", "scope", "register", OUTSIDER_ID):
            assert leaked not in reply


# ---------------------------------------------------------------------------
# Authorized turn body: refusal happens before prepare / agent build
# ---------------------------------------------------------------------------


class TestAuthorizedTurnRefusal:
    def test_refused_before_prepare_or_agent_build(self, home, monkeypatch):
        runner = _runner()
        runner._hmwa_prepare_turn = AsyncMock(
            side_effect=AssertionError("prepare must not run for a denied principal")
        )
        monkeypatch.setattr(
            "run_agent.AIAgent",
            MagicMock(side_effect=AssertionError("agent must not be built")),
        )
        source = _src(OUTSIDER_ID)
        with _Bound(source):
            reply = _run(runner._handle_message_with_agent_authorized(
                MagicMock(), source, MagicMock(), "sess-key", "quick", 1,
            ))
        assert reply == FIXED_REPLY
        runner._hmwa_prepare_turn.assert_not_awaited()

    def test_outer_handler_binds_and_resets(self, home):
        runner = _runner()
        source = _src(OUTSIDER_ID)
        entry = MagicMock()
        runner._hmwa_resolve_session = AsyncMock(return_value=(source, entry, "sess-key"))
        reply = _run(runner._handle_message_with_agent(MagicMock(), source, "quick", 1))
        assert reply == FIXED_REPLY
        assert current_requester() is None

    def test_outer_handler_resets_on_early_drop(self, home):
        runner = _runner()
        runner._hmwa_resolve_session = AsyncMock(return_value=None)
        assert _run(runner._handle_message_with_agent(MagicMock(), _src(AM_ID), "q", 1)) is None
        assert current_requester() is None


# ---------------------------------------------------------------------------
# Toolset trap: override exception / empty result denies governed turns
# ---------------------------------------------------------------------------


class _RaisingAdapter:
    def toolsets_for_source(self, source):
        raise RuntimeError("adapter blew up")


class _EmptyAdapter:
    def toolsets_for_source(self, source):
        return []


class _NoneAdapter:
    def toolsets_for_source(self, source):
        return None


class TestToolsetTrap:
    def _trap_runner(self, adapter):
        runner = _runner()
        runner._adapter_for_source = lambda source: adapter
        return runner

    def test_override_exception_denies_governed(self, home):
        runner = self._trap_runner(_RaisingAdapter())
        with _Bound(_src(AM_ID)):
            with pytest.raises(TeamAuthzDenied) as exc:
                runner._resolve_enabled_toolsets_for_source({}, _src(AM_ID), "discord")
        assert str(exc.value) == "toolset-override-error"
        rows = _audit_rows(home)
        assert len(rows) == 1 and rows[0]["reason"] == "toolset-override-error"

    def test_empty_override_denies_governed(self, home):
        runner = self._trap_runner(_EmptyAdapter())
        with _Bound(_src(AM_ID)):
            with pytest.raises(TeamAuthzDenied) as exc:
                runner._resolve_enabled_toolsets_for_source({}, _src(AM_ID), "discord")
        assert str(exc.value) == "empty-toolsets"

    def test_empty_resolved_denies_governed(self, home):
        runner = self._trap_runner(_NoneAdapter())
        with _Bound(_src(AM_ID)):
            with patch(
                "hermes_cli.tools_config._get_platform_tools", return_value=set()
            ):
                with pytest.raises(TeamAuthzDenied) as exc:
                    runner._resolve_enabled_toolsets_for_source({}, _src(AM_ID), "discord")
        assert str(exc.value) == "empty-toolsets"

    def test_override_exception_keeps_bundle_ungoverned(self, home):
        _write_config(home, CONFIG_DISABLED)
        runner = self._trap_runner(_RaisingAdapter())
        from hermes_cli.tools_config import _get_platform_tools
        with _Bound(_src(AM_ID)):
            got = runner._resolve_enabled_toolsets_for_source({}, _src(AM_ID), "discord")
        assert got == sorted(_get_platform_tools({}, "discord"))
        assert _audit_rows(home) == []

    def test_empty_override_keeps_bundle_ungoverned(self, home):
        _write_config(home, CONFIG_DISABLED)
        runner = self._trap_runner(_EmptyAdapter())
        from hermes_cli.tools_config import _get_platform_tools
        with _Bound(_src(AM_ID)):
            got = runner._resolve_enabled_toolsets_for_source({}, _src(AM_ID), "discord")
        assert got == sorted(_get_platform_tools({}, "discord"))

    def test_no_override_uses_platform_config_governed(self, home):
        runner = self._trap_runner(_NoneAdapter())
        from hermes_cli.tools_config import _get_platform_tools
        with _Bound(_src(AM_ID)):
            got = runner._resolve_enabled_toolsets_for_source({}, _src(AM_ID), "discord")
        assert got == sorted(_get_platform_tools({}, "discord"))
        assert _audit_rows(home) == []


# ---------------------------------------------------------------------------
# Agent cache: grant changes bust reuse
# ---------------------------------------------------------------------------


class TestAgentCacheGrant:
    RUNTIME = {"provider": "openrouter", "base_url": "", "api_mode": ""}

    def test_signature_differs_on_grant_change(self):
        from gateway.run import GatewayRunner
        sig_a = GatewayRunner._agent_config_signature(
            "m", self.RUNTIME, ["hermes-discord"], "", grant_digest="grant-a",
        )
        sig_b = GatewayRunner._agent_config_signature(
            "m", self.RUNTIME, ["hermes-discord"], "", grant_digest="grant-b",
        )
        assert sig_a != sig_b

    def test_signature_stable_same_grant_and_default(self):
        from gateway.run import GatewayRunner
        sig_a = GatewayRunner._agent_config_signature(
            "m", self.RUNTIME, ["hermes-discord"], "", grant_digest="grant-a",
        )
        sig_b = GatewayRunner._agent_config_signature(
            "m", self.RUNTIME, ["hermes-discord"], "", grant_digest="grant-a",
        )
        sig_default = GatewayRunner._agent_config_signature("m", self.RUNTIME, ["hermes-discord"], "")
        sig_empty = GatewayRunner._agent_config_signature(
            "m", self.RUNTIME, ["hermes-discord"], "", grant_digest="",
        )
        assert sig_a == sig_b
        assert sig_default == sig_empty

    def test_unchanged_grant_reuses_cached_agent(self, home):
        agent, reused = self._resolve_twice(home, revoke_between=False)
        assert reused is True
        assert agent is self._first_agent

    def test_revoked_grant_rebuilds_cached_agent(self, home):
        agent, reused = self._resolve_twice(home, revoke_between=True)
        assert reused is False
        assert agent is not self._first_agent

    _first_agent = None

    def _resolve_twice(self, home, *, revoke_between):
        """Two ``_resolve_turn_agent`` passes; optionally revoke AM between them."""
        from gateway.run_turn_runner import TurnRunner
        from gateway.turn_context import TurnContext

        built = []

        class _FakeAgent:
            def __init__(self, **kwargs):
                self.kwargs = kwargs
                built.append(self)

        runner = _runner()
        runner._agent_cache = {}
        runner._agent_cache_lock = threading.Lock()
        runner._session_db = None
        runner.session_store = None
        runner._prefill_messages = None
        runner._service_tier = None
        runner._init_cached_agent_for_turn = lambda *a: None
        runner._apply_fallback_chain_to_agent = lambda *a: None
        runner._refresh_fallback_model = lambda: None
        runner._enforce_agent_cache_cap = lambda: None

        source = _src(AM_ID)
        ctx = TurnContext(
            source=source, session_id="sid-1", session_key="sess-key",
            user_config={}, enabled_toolsets=["hermes-discord"],
            disabled_toolsets=None, AIAgent=_FakeAgent,
        )
        turn_route = {"model": "m", "runtime": dict(self.RUNTIME)}
        with _Bound(source):
            first, reused_first = TurnRunner(runner, ctx)._resolve_turn_agent(
                turn_route, "discord", "", 5, None, {},
            )
            assert reused_first is False
            type(self)._first_agent = first
            if revoke_between:
                _revoke(home, AM_ID)
            second, reused_second = TurnRunner(runner, ctx)._resolve_turn_agent(
                turn_route, "discord", "", 5, None, {},
            )
        assert first.kwargs["skip_context_files"] is True
        assert first.kwargs["load_soul_identity"] is False
        return second, reused_second

    def test_ungoverned_digest_stable(self, home):
        _write_config(home, CONFIG_DISABLED)
        assert grant_digest() == grant_digest()


# ---------------------------------------------------------------------------
# Owner-context exclusion for governed non-owner agents
# ---------------------------------------------------------------------------


class TestOwnerContextExclusion:
    def _turn_runner(self, user_config):
        from gateway.run_turn_runner import TurnRunner
        from gateway.turn_context import TurnContext
        return TurnRunner(_runner(), TurnContext(user_config=user_config))

    def test_governed_non_owner_skips_context_files(self, home):
        turn_runner = self._turn_runner({})
        with _Bound(_src(AM_ID)):
            assert turn_runner._skip_context_files("discord") is True

    def test_owner_keeps_config_behavior(self, home):
        turn_runner = self._turn_runner({})
        with _Bound(_src(OWNER_ID)):
            assert turn_runner._skip_context_files("discord") is False

    def test_ungoverned_keeps_config(self, home):
        _write_config(home, CONFIG_DISABLED)
        assert self._turn_runner({})._skip_context_files("discord") is False
        cfg = {"gateway": {"platforms": {"discord": {"skip_context_files": True}}}}
        assert self._turn_runner(cfg)._skip_context_files("discord") is True

    def test_fresh_agent_kwargs_non_owner(self, home):
        from gateway.run_turn_runner import TurnRunner
        from gateway.turn_context import TurnContext

        seen = {}

        class _FakeAgent:
            def __init__(self, **kwargs):
                seen.update(kwargs)

        runner = _runner()
        runner._prefill_messages = None
        runner._service_tier = None
        runner._session_db = None
        runner._refresh_fallback_model = lambda: None
        ctx = TurnContext(
            source=_src(AM_ID), session_id="sid-1", session_key="sess-key",
            user_config={}, enabled_toolsets=[], disabled_toolsets=None,
            AIAgent=_FakeAgent,
        )
        with _Bound(_src(AM_ID)):
            TurnRunner(runner, ctx)._build_fresh_agent(
                {"model": "m", "runtime": {}}, "discord", "", 5, None, {}, True,
            )
        assert seen["skip_context_files"] is True
        assert seen["load_soul_identity"] is False

    def test_fresh_agent_kwargs_owner(self, home):
        from gateway.run_turn_runner import TurnRunner
        from gateway.turn_context import TurnContext

        seen = {}

        class _FakeAgent:
            def __init__(self, **kwargs):
                seen.update(kwargs)

        runner = _runner()
        runner._prefill_messages = None
        runner._service_tier = None
        runner._session_db = None
        runner._refresh_fallback_model = lambda: None
        ctx = TurnContext(
            source=_src(OWNER_ID), session_id="sid-1", session_key="sess-key",
            user_config={}, enabled_toolsets=[], disabled_toolsets=None,
            AIAgent=_FakeAgent,
        )
        with _Bound(_src(OWNER_ID)):
            TurnRunner(runner, ctx)._build_fresh_agent(
                {"model": "m", "runtime": {}}, "discord", "", 5, None, {}, False,
            )
        assert seen["skip_context_files"] is False
        assert seen["load_soul_identity"] is True


# ---------------------------------------------------------------------------
# Background tasks: same binding, same fixed refusal
# ---------------------------------------------------------------------------


class TestBackgroundGate:
    def _bg_runner(self):
        runner = _runner()
        adapter = AsyncMock()
        adapter.send = AsyncMock()
        runner._adapter_for_source = lambda source: adapter
        runner._thread_metadata_for_source = lambda *a, **k: {}
        return runner, adapter

    def test_denied_principal_fixed_reply_no_agent(self, home, monkeypatch):
        runner, adapter = self._bg_runner()
        monkeypatch.setattr(
            "run_agent.AIAgent",
            MagicMock(side_effect=AssertionError("agent must not be built")),
        )
        monkeypatch.setattr(
            "gateway.run._load_gateway_config",
            MagicMock(side_effect=AssertionError("config must not load for denied principal")),
        )
        source = _src(OUTSIDER_ID)
        with _Bound(source):
            _run(runner._run_background_task_inner("do work", source, "bg_1"))
        adapter.send.assert_awaited_once()
        assert adapter.send.call_args[0][1] == FIXED_REPLY
        trail = _audit_rows(home)
        assert trail[0]["event"] == "message"
        assert trail[0]["reason"] == "inbound-received"
        assert trail[1]["reason"] == "unknown-identity"

    def test_active_member_proceeds_past_gate(self, home):
        runner, adapter = self._bg_runner()
        runner._resolve_session_agent_runtime = lambda **k: ("m", {})
        source = _src(AM_ID)
        with _Bound(source):
            _run(runner._run_background_task_inner("do work", source, "bg_1"))
        content = adapter.send.call_args[0][1]
        assert "couldn't start" in content
        assert content != FIXED_REPLY

    def test_toolset_trap_fixed_reply(self, home):
        runner, adapter = self._bg_runner()
        runner._resolve_session_agent_runtime = lambda **k: ("m", {"api_key": "k"})

        def _boom(user_config, source, platform_key):
            raise TeamAuthzDenied("empty-toolsets")

        runner._resolve_turn_toolsets = _boom
        source = _src(AM_ID)
        with _Bound(source):
            _run(runner._run_background_task_inner("do work", source, "bg_1"))
        assert adapter.send.call_args[1]["content"] == FIXED_REPLY

    def test_outer_task_binds_and_resets(self, home):
        runner = _runner()
        observed = {}

        async def _fake_inner(prompt, source, task_id, *a, **k):
            ctx = current_requester()
            observed["user_id"] = ctx.user_id if ctx else None
            observed["scope_id"] = ctx.scope_id if ctx else None

        runner._run_background_task_inner = _fake_inner
        _run(runner._run_background_task("do work", _src(AM_ID), "bg_1"))
        assert observed == {"user_id": AM_ID, "scope_id": GUILD}
        assert current_requester() is None


# ---------------------------------------------------------------------------
# Multiplex: the entry gate reads the served profile's home (A-B-A)
# ---------------------------------------------------------------------------


class TestMultiplexProfileScope:
    @pytest.fixture
    def mux(self, tmp_path, monkeypatch):
        """Fake $HOME with a default home plus a governed-capable secondary."""
        fake_home = tmp_path / "fakehome"
        default_home = fake_home / ".hermes"
        sec_home = default_home / "profiles" / "teambot"
        sec_home.mkdir(parents=True)
        monkeypatch.setattr(Path, "home", lambda: fake_home)
        monkeypatch.setenv("HERMES_HOME", str(default_home))
        monkeypatch.delenv("HERMES_SESSION_PLATFORM", raising=False)
        team_authz._REGISTER_CACHE.clear()
        yield SimpleNamespace(default_home=default_home, sec_home=sec_home)
        team_authz._REGISTER_CACHE.clear()

    def _mux_runner(self):
        runner = _runner()
        runner.config = SimpleNamespace(multiplex_profiles=True)
        return runner

    def test_secondary_governed_denies_while_default_open(self, mux):
        _write_config(mux.default_home, CONFIG_DISABLED)
        _write_config(mux.sec_home, CONFIG_ENABLED)
        _write_register(mux.sec_home, _base_register())
        runner = self._mux_runner()
        runner._hmwa_prepare_turn = AsyncMock(
            side_effect=AssertionError("prepare must not run for a denied principal")
        )
        source = dataclasses.replace(_src(OUTSIDER_ID), profile="teambot")
        token = runner._team_authz_bind_requester(source)
        try:
            reply = _run(runner._handle_message_with_agent_authorized(
                MagicMock(), source, MagicMock(), "sess-key", "quick", 1,
            ))
        finally:
            runner._team_authz_reset_requester(token)
        assert reply == FIXED_REPLY
        runner._hmwa_prepare_turn.assert_not_awaited()

    def test_secondary_open_allows_while_default_governed(self, mux):
        _write_config(mux.default_home, CONFIG_ENABLED)
        _write_register(mux.default_home, _base_register())
        _write_config(mux.sec_home, CONFIG_DISABLED)
        runner = self._mux_runner()
        runner._hmwa_prepare_turn = AsyncMock(return_value=(None, []))
        source = dataclasses.replace(_src(OUTSIDER_ID), profile="teambot")
        token = runner._team_authz_bind_requester(source)
        try:
            reply = _run(runner._handle_message_with_agent_authorized(
                MagicMock(), source, MagicMock(), "sess-key", "quick", 1,
            ))
        finally:
            runner._team_authz_reset_requester(token)
        assert reply is None
        runner._hmwa_prepare_turn.assert_awaited_once()
