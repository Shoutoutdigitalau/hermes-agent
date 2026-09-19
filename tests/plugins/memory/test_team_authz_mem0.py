"""HTS-06: per-member Mem0 namespace isolation.

A governed non-owner is scoped to ``team-<memberKey>`` derived from the
verified member identity — the configured fixed user id can never win — and a
denied principal gets no provider recall or write. Owner and ungoverned
behaviour equals base.

Synthetic identities only (``9000000000000000NN``), temp HERMES_HOME, fake
in-memory backend. Behaviour contracts: namespace bindings plus zero-backend
proofs on every deny path.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path

import pytest

from agent import team_authz
from agent.team_authz import (
    RequesterContext,
    bind_requester,
    reset_requester,
)
from agent.team_authz_sharing import record_sharing_consent
from plugins.memory.mem0 import Mem0MemoryProvider

OWNER_ID = "900000000000000001"
AM_ID = "900000000000000003"
META_ID = "900000000000000004"
OUTSIDER_ID = "900000000000000009"

GUILD = "910000000000000001"
OTHER_GUILD = "910000000000000002"
CHAT_AM = "920000000000000003"
CHAT_META = "920000000000000004"

CONFIGURED_FIXED_ID = "owner-fixed-id"
CONFIG_ENABLED = "team_authz:\n  enabled: true\n  governed_platforms: [\"discord\"]\n"
CONFIG_DISABLED = "team_authz:\n  enabled: false\n"


def _ctx(uid, *, scope=GUILD, chat=CHAT_AM, chat_type="dm", thread=None) -> RequesterContext:
    return RequesterContext(platform="discord", user_id=uid, scope_id=scope,
                            chat_id=chat, chat_type=chat_type, thread_id=thread)


CTX_OWNER = _ctx(OWNER_ID, chat="920000000000000001")
CTX_AM = _ctx(AM_ID, chat=CHAT_AM)
CTX_META = _ctx(META_ID, chat=CHAT_META)


def _member(uid: str, key: str, role: str, status: str = "active") -> dict:
    return {"discordUserId": uid, "memberKey": key, "role": role, "status": status,
            "approvedBy": "", "approvedAt": "2026-01-01T00:00:00+00:00"}


def _base_register() -> dict:
    return {
        "schemaVersion": 1,
        "policyVersion": "2026.09.17-hts06",
        "guilds": [GUILD],
        "members": [
            _member(OWNER_ID, "charles", "owner"),
            _member(AM_ID, "lianna", "account_manager"),
            _member(META_ID, "dianne", "meta_ads_operator"),
        ],
        "roles": {
            "owner": {"capabilities": ["memory.own", "owner.host"]},
            "account_manager": {"capabilities": ["memory.own"]},
            "meta_ads_operator": {"capabilities": ["memory.own"]},
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


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "hermes-home"
    h.mkdir()
    (h / "config.yaml").write_text(CONFIG_ENABLED, encoding="utf-8")
    _write_register(h, _base_register())
    (h / "mem0.json").write_text(json.dumps({"user_id": CONFIGURED_FIXED_ID}), encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(h))
    monkeypatch.delenv("HERMES_SESSION_PLATFORM", raising=False)
    monkeypatch.delenv("MEM0_USER_ID", raising=False)
    monkeypatch.delenv("MEM0_API_KEY", raising=False)
    monkeypatch.delenv("MEM0_HOST", raising=False)
    monkeypatch.delenv("MEM0_MODE", raising=False)
    team_authz._REGISTER_CACHE.clear()
    yield h
    team_authz._REGISTER_CACHE.clear()


@contextmanager
def bound(ctx):
    token = bind_requester(ctx)
    try:
        yield ctx
    finally:
        reset_requester(token)


class PartitionedFakeBackend:
    """Server-side partitioned fake: each user_id sees only its own rows."""

    def __init__(self):
        self.store: dict[str, list[dict]] = {}
        self.calls: list[tuple] = []
        self._seq = 0

    def search(self, query, *, filters, top_k=10, rerank=False):
        self.calls.append(("search", query, dict(filters)))
        rows = list(self.store.get(filters.get("user_id"), []))
        return rows[:top_k]

    def add(self, messages, *, user_id, agent_id, infer=False, metadata=None):
        self.calls.append(("add", list(messages), user_id))
        out = []
        for m in messages:
            self._seq += 1
            row = {"id": f"mem-{self._seq}", "memory": m.get("content", ""), "score": 1.0}
            self.store.setdefault(user_id, []).append(row)
            out.append(row["id"])
        return {"status": "PENDING", "event_id": "evt-fake"}

    def update(self, memory_id, text):
        self.calls.append(("update", memory_id))
        for rows in self.store.values():
            for r in rows:
                if r["id"] == memory_id:
                    r["memory"] = text
                    return {"result": "Memory updated.", "memory_id": memory_id}
        raise LookupError(f"not found: {memory_id}")

    def delete(self, memory_id):
        self.calls.append(("delete", memory_id))
        for rows in self.store.values():
            for r in rows:
                if r["id"] == memory_id:
                    rows.remove(r)
                    return {"result": "Memory deleted.", "memory_id": memory_id}
        raise LookupError(f"not found: {memory_id}")


def _provider_with(home, ctx, backend, monkeypatch, **init_kwargs):
    provider = Mem0MemoryProvider()
    with bound(ctx):
        provider.initialize("sess-hts06", **init_kwargs)
        if provider._backend is None and provider._team_denied_reason is None:
            provider._backend = backend
    return provider


class TestNamespaceBinding:
    def test_member_namespace_overrides_configured_fixed_id(self, home, monkeypatch):
        backend = PartitionedFakeBackend()
        provider = _provider_with(home, CTX_AM, backend, monkeypatch, user_id="discord-native-999")
        assert provider._user_id == "team-lianna"
        with bound(CTX_AM):
            assert json.loads(provider.handle_tool_call("mem0_search", {"query": "q"}))
        assert backend.calls[0][0] == "search"
        assert backend.calls[0][2]["user_id"] == "team-lianna"

    def test_member_write_uses_namespace(self, home, monkeypatch):
        backend = PartitionedFakeBackend()
        provider = _provider_with(home, CTX_AM, backend, monkeypatch)
        with bound(CTX_AM):
            result = json.loads(provider.handle_tool_call("mem0_add", {"content": "lianna fact"}))
        assert "error" not in result
        assert backend.calls[0][0] == "add"
        assert backend.calls[0][2] == "team-lianna"
        assert "team-lianna" in backend.store

    def test_members_get_distinct_namespaces(self, home, monkeypatch):
        for ctx, ns in ((CTX_AM, "team-lianna"), (CTX_META, "team-dianne")):
            provider = _provider_with(home, ctx, PartitionedFakeBackend(), monkeypatch)
            assert provider._user_id == ns
            assert provider._user_id != CONFIGURED_FIXED_ID
        assert "team-lianna" != "team-dianne"

    def test_owner_keeps_configured_id(self, home, monkeypatch):
        provider = _provider_with(home, CTX_OWNER, PartitionedFakeBackend(), monkeypatch,
                                  user_id="discord-native-owner")
        assert provider._user_id == CONFIGURED_FIXED_ID

    def test_owner_without_configured_id_keeps_gateway_native(self, home, monkeypatch):
        (home / "mem0.json").write_text(json.dumps({}), encoding="utf-8")
        provider = _provider_with(home, CTX_OWNER, PartitionedFakeBackend(), monkeypatch,
                                  user_id="discord-native-owner")
        assert provider._user_id == "discord-native-owner"

    def test_disabled_config_keeps_base_precedence(self, home, monkeypatch):
        (home / "config.yaml").write_text(CONFIG_DISABLED, encoding="utf-8")
        provider = _provider_with(home, CTX_AM, PartitionedFakeBackend(), monkeypatch,
                                  user_id="discord-native-999")
        assert provider._user_id == CONFIGURED_FIXED_ID

    def test_absent_config_keeps_base_precedence(self, home, monkeypatch):
        (home / "config.yaml").unlink()
        provider = _provider_with(home, CTX_AM, PartitionedFakeBackend(), monkeypatch,
                                  user_id="discord-native-999")
        assert provider._user_id == CONFIGURED_FIXED_ID


class TestCrossMemberIsolation:
    def test_member_search_never_returns_owner_or_other_member_rows(self, home, monkeypatch):
        backend = PartitionedFakeBackend()
        backend.store[CONFIGURED_FIXED_ID] = [
            {"id": "mem-owner", "memory": "owner-private-secret", "score": 1.0}]
        backend.store["team-dianne"] = [
            {"id": "mem-meta", "memory": "dianne-private-fact", "score": 1.0}]
        provider = _provider_with(home, CTX_AM, backend, monkeypatch)
        with bound(CTX_AM):
            result = json.loads(provider.handle_tool_call("mem0_search", {"query": "secret"}))
        assert result.get("result") == "No relevant memories found."
        assert all(call[2].get("user_id") == "team-lianna"
                   for call in backend.calls if call[0] == "search")

    def test_member_cannot_address_owner_namespace(self, home, monkeypatch):
        backend = PartitionedFakeBackend()
        provider = _provider_with(home, CTX_AM, backend, monkeypatch)
        with bound(CTX_AM):
            provider.handle_tool_call("mem0_add", {"content": "x"})
            provider.handle_tool_call("mem0_search", {"query": "x"})
        namespaces = {c[2] if c[0] == "add" else c[2].get("user_id") for c in backend.calls}
        assert namespaces == {"team-lianna"}

    def test_sharing_consent_creates_no_shared_namespace(self, home, monkeypatch):
        with bound(CTX_AM):
            decision = record_sharing_consent({
                "sourceRef": "sess-am-1", "authorDiscordUserId": AM_ID,
                "summary": "Exact approved summary.",
                "destination": {"shape": "messaging", "platform": "discord",
                                "guild": GUILD, "chatId": CHAT_AM},
            })
        assert decision.allowed is True
        backend = PartitionedFakeBackend()
        provider = _provider_with(home, CTX_META, backend, monkeypatch)
        assert provider._user_id == "team-dianne"
        with bound(CTX_META):
            provider.handle_tool_call("mem0_search", {"query": "summary"})
        assert backend.calls[0][2]["user_id"] == "team-dianne"


class TestDeniedPrincipals:
    def test_unknown_identity_gets_no_provider(self, home, monkeypatch):
        created = []
        monkeypatch.setattr(Mem0MemoryProvider, "_create_backend",
                            lambda self: created.append(True) or None)
        provider = Mem0MemoryProvider()
        with bound(_ctx(OUTSIDER_ID)):
            provider.initialize("sess-denied")
            assert provider._backend is None
            assert provider._team_denied_reason == "unknown-identity"
            for tool, args in (("mem0_search", {"query": "q"}),
                               ("mem0_add", {"content": "c"}),
                               ("mem0_update", {"memory_id": "m", "text": "t"}),
                               ("mem0_delete", {"memory_id": "m"})):
                assert "denied" in json.loads(provider.handle_tool_call(tool, args))["error"]
            assert provider.prefetch("q") == ""
            provider.sync_turn("u", "a")
        assert created == []

    def test_denied_flag_survives_an_injected_backend(self, home, monkeypatch):
        backend = PartitionedFakeBackend()
        provider = Mem0MemoryProvider()
        with bound(_ctx(OUTSIDER_ID)):
            provider.initialize("sess-denied")
            provider._backend = backend
            assert "denied" in json.loads(
                provider.handle_tool_call("mem0_search", {"query": "q"}))["error"]
            assert "denied" in json.loads(
                provider.handle_tool_call("mem0_add", {"content": "c"}))["error"]
            assert provider.prefetch("q") == ""
            provider.sync_turn("u", "a")
            if provider._sync_thread is not None:
                provider._sync_thread.join(timeout=5)
        assert backend.calls == []

    def test_wrong_guild_denied(self, home, monkeypatch):
        provider = Mem0MemoryProvider()
        with bound(_ctx(AM_ID, scope=OTHER_GUILD)):
            provider.initialize("sess-scope")
            assert provider._backend is None
            assert provider._team_denied_reason == "scope-not-listed"

    def test_revoked_mid_session_binds_next_call(self, home, monkeypatch):
        backend = PartitionedFakeBackend()
        provider = _provider_with(home, CTX_AM, backend, monkeypatch)
        with bound(CTX_AM):
            assert "error" not in json.loads(
                provider.handle_tool_call("mem0_search", {"query": "q"}))
        calls_before = len(backend.calls)
        reg = _base_register()
        reg["policyVersion"] = "2026.09.17-hts06-revoked"
        reg["members"] = [dict(m, status="revoked") if m["discordUserId"] == AM_ID else m
                          for m in reg["members"]]
        _write_register(home, reg)
        with bound(CTX_AM):
            assert "denied" in json.loads(
                provider.handle_tool_call("mem0_search", {"query": "q"}))["error"]
            assert "denied" in json.loads(
                provider.handle_tool_call("mem0_add", {"content": "c"}))["error"]
            assert provider.prefetch("q") == ""
            provider.sync_turn("u", "a")
        assert len(backend.calls) == calls_before

    def test_missing_requester_context_denied_when_platform_known(self, home, monkeypatch):
        monkeypatch.setenv("HERMES_SESSION_PLATFORM", "discord")
        provider = Mem0MemoryProvider()
        provider.initialize("sess-noctx")
        assert provider._backend is None
        assert provider._team_denied_reason == "no-requester-context"

    def test_missing_requester_without_platform_is_base(self, home, monkeypatch):
        provider = Mem0MemoryProvider()
        provider.initialize("sess-noctx", user_id="cli-native")
        assert provider._team_denied_reason is None
        assert provider._user_id == CONFIGURED_FIXED_ID

    def test_malformed_config_denies_owner_too(self, home, monkeypatch):
        (home / "config.yaml").write_text("team_authz: [not, a, mapping]\n", encoding="utf-8")
        provider = Mem0MemoryProvider()
        with bound(CTX_OWNER):
            provider.initialize("sess-malformed")
            assert provider._backend is None
            assert provider._team_denied_reason == "config-malformed"


class TestBackgroundPaths:
    def test_sync_turn_writes_to_namespace(self, home, monkeypatch):
        backend = PartitionedFakeBackend()
        provider = _provider_with(home, CTX_AM, backend, monkeypatch)
        with bound(CTX_AM):
            provider.sync_turn("user said", "assistant replied")
            provider._sync_thread.join(timeout=5)
        assert backend.calls and backend.calls[0][0] == "add"
        assert backend.calls[0][2] == "team-lianna"

    def test_prefetch_reads_namespace(self, home, monkeypatch):
        backend = PartitionedFakeBackend()
        backend.store["team-lianna"] = [{"id": "m1", "memory": "lianna likes tea", "score": 0.9}]
        provider = _provider_with(home, CTX_AM, backend, monkeypatch)
        with bound(CTX_AM):
            body = provider.prefetch("likes")
        assert "lianna likes tea" in body
        assert backend.calls[0][2]["user_id"] == "team-lianna"

    def test_member_update_and_delete_own_rows_allowed(self, home, monkeypatch):
        backend = PartitionedFakeBackend()
        backend.store["team-lianna"] = [{"id": "m1", "memory": "old", "score": 1.0}]
        provider = _provider_with(home, CTX_AM, backend, monkeypatch)
        with bound(CTX_AM):
            assert "error" not in json.loads(provider.handle_tool_call(
                "mem0_update", {"memory_id": "m1", "text": "new"}))
            assert "error" not in json.loads(provider.handle_tool_call(
                "mem0_delete", {"memory_id": "m1"}))
        assert ("update", "m1") in backend.calls
        assert ("delete", "m1") in backend.calls
