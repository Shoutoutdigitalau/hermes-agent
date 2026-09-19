"""HTS-06: governed agents never load the owner's built-in memory.

``agent_init._init_memory`` skips the owner's built-in MEMORY.md/USER.md store
for governed non-owners, and gives a denied principal no provider either.
Owner and ungoverned initialisation equals base.

Synthetic identities only (``9000000000000000NN``), temp HERMES_HOME with a
real MEMORY.md marker, real ``MemoryStore`` for the allowed paths and a
refusing factory proving the blocked paths never construct it.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent import team_authz
from agent.agent_init import _init_memory
from agent.team_authz import (
    RequesterContext,
    bind_requester,
    reset_requester,
)

OWNER_ID = "900000000000000001"
AM_ID = "900000000000000003"
OUTSIDER_ID = "900000000000000009"

GUILD = "910000000000000001"
CHAT_AM = "920000000000000003"

MARKER = "owner-private-memory-marker-hts06"

CONFIG_ENABLED = "team_authz:\n  enabled: true\n  governed_platforms: [\"discord\"]\n"
CONFIG_DISABLED = "team_authz:\n  enabled: false\n"


def _ctx(uid, *, scope=GUILD, chat=CHAT_AM) -> RequesterContext:
    return RequesterContext(platform="discord", user_id=uid, scope_id=scope,
                            chat_id=chat, chat_type="dm", thread_id=None)


CTX_OWNER = _ctx(OWNER_ID, chat="920000000000000001")
CTX_AM = _ctx(AM_ID)


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
        ],
        "roles": {
            "owner": {"capabilities": ["memory.own", "owner.host"]},
            "account_manager": {"capabilities": ["memory.own"]},
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
    (h / "memories").mkdir(parents=True, exist_ok=True)
    (h / "memories" / "MEMORY.md").write_text(f"{MARKER}\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(h))
    monkeypatch.delenv("HERMES_SESSION_PLATFORM", raising=False)
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


def _agent(session_id="sess-hts06"):
    agent = SimpleNamespace(
        session_id=session_id,
        enabled_toolsets=[],
        disabled_toolsets=[],
        _session_db=None,
        _user_id=None, _user_id_alt=None, _user_name=None,
        _chat_id=None, _chat_name=None, _chat_type=None, _thread_id=None,
        _gateway_session_key=None,
    )
    return agent


class _RefusingStore:
    def __init__(self, *args, **kwargs):
        raise AssertionError("MemoryStore must not be constructed for this principal")


class _FakeProvider:
    name = "mem0"

    def __init__(self):
        self.init_kwargs: dict | None = None

    def is_available(self):
        return True

    def get_tool_schemas(self):
        return []

    def initialize(self, session_id: str = "", **kwargs):
        self.init_kwargs = {"session_id": session_id, **kwargs}


class TestBuiltinStore:
    def test_owner_loads_builtin_store(self, home):
        agent = _agent()
        with bound(CTX_OWNER):
            _init_memory(agent, {}, False, "discord")
        assert agent._memory_store is not None
        assert agent._memory_enabled is True
        assert agent._user_profile_enabled is True
        assert any(MARKER in entry for entry in agent._memory_store.memory_entries)

    def test_ungoverned_loads_builtin_store(self, home):
        (home / "config.yaml").write_text(CONFIG_DISABLED, encoding="utf-8")
        agent = _agent()
        with bound(CTX_AM):
            _init_memory(agent, {}, False, "discord")
        assert agent._memory_store is not None
        assert any(MARKER in entry for entry in agent._memory_store.memory_entries)

    def test_non_owner_never_constructs_builtin_store(self, home, monkeypatch):
        import tools.memory_tool as memory_tool
        monkeypatch.setattr(memory_tool, "MemoryStore", _RefusingStore)
        agent = _agent()
        with bound(CTX_AM):
            _init_memory(agent, {}, False, "discord")
        assert agent._memory_store is None
        assert agent._memory_enabled is False
        assert agent._user_profile_enabled is False

    def test_denied_principal_gets_no_builtin_store(self, home, monkeypatch):
        import tools.memory_tool as memory_tool
        monkeypatch.setattr(memory_tool, "MemoryStore", _RefusingStore)
        agent = _agent()
        with bound(_ctx(OUTSIDER_ID)):
            _init_memory(agent, {}, False, "discord")
        assert agent._memory_store is None
        assert agent._memory_enabled is False

    def test_memory_toolset_request_cannot_pull_owner_store(self, home, monkeypatch):
        import tools.memory_tool as memory_tool
        monkeypatch.setattr(memory_tool, "MemoryStore", _RefusingStore)
        agent = _agent()
        agent.enabled_toolsets = ["memory"]
        with bound(CTX_AM):
            _init_memory(agent, {}, True, "discord")
        assert agent._memory_store is None

    def test_skip_memory_base_behaviour_preserved(self, home):
        agent = _agent()
        with bound(CTX_OWNER):
            _init_memory(agent, {}, True, "discord")
        assert agent._memory_store is None
        assert agent._memory_manager is None


class TestExternalProvider:
    @staticmethod
    def _stub_ra(monkeypatch):
        import logging
        import agent.agent_init as agent_init
        monkeypatch.setattr(agent_init, "_ra",
                            lambda: SimpleNamespace(logger=logging.getLogger("test")))

    def test_non_owner_still_initializes_provider(self, home, monkeypatch):
        import plugins.memory as memory_plugins
        self._stub_ra(monkeypatch)
        fake = _FakeProvider()
        calls: list = []
        monkeypatch.setattr(memory_plugins, "load_memory_provider",
                            lambda name: calls.append(name) or fake)
        agent = _agent()
        with bound(CTX_AM):
            _init_memory(agent, {"memory": {"provider": "mem0"}}, False, "discord")
        assert calls == ["mem0"]
        assert agent._memory_manager is not None
        assert fake.init_kwargs is not None
        assert fake.init_kwargs["session_id"] == "sess-hts06"

    def test_owner_initializes_provider(self, home, monkeypatch):
        import plugins.memory as memory_plugins
        self._stub_ra(monkeypatch)
        fake = _FakeProvider()
        monkeypatch.setattr(memory_plugins, "load_memory_provider", lambda name: fake)
        agent = _agent()
        with bound(CTX_OWNER):
            _init_memory(agent, {"memory": {"provider": "mem0"}}, False, "discord")
        assert agent._memory_manager is not None
        assert fake.init_kwargs is not None

    def test_denied_principal_gets_no_provider(self, home, monkeypatch):
        import plugins.memory as memory_plugins
        calls: list = []
        monkeypatch.setattr(memory_plugins, "load_memory_provider",
                            lambda name: calls.append(name))
        agent = _agent()
        with bound(_ctx(OUTSIDER_ID)):
            _init_memory(agent, {"memory": {"provider": "mem0"}}, False, "discord")
        assert calls == []
        assert agent._memory_manager is None

    def test_denied_principal_with_memory_toolset_still_has_nothing(self, home, monkeypatch):
        import plugins.memory as memory_plugins
        import tools.memory_tool as memory_tool
        monkeypatch.setattr(memory_plugins, "load_memory_provider",
                            lambda name: (_ for _ in ()).throw(AssertionError("no provider load")))
        monkeypatch.setattr(memory_tool, "MemoryStore", _RefusingStore)
        agent = _agent()
        agent.enabled_toolsets = ["memory"]
        with bound(_ctx(OUTSIDER_ID)):
            _init_memory(agent, {"memory": {"provider": "mem0"}}, False, "discord")
        assert agent._memory_store is None
        assert agent._memory_manager is None
