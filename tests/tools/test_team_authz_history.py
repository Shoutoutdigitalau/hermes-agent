"""HTS-05 history isolation: one ownership predicate across every session_search mode.

Synthetic identities only (9000000000000000NN), temp HERMES_HOME and temp
SessionDB written by the test. Behaviour contracts per INITIAL_SPEC.md section 4
gates 4-5 plus r2 destination-before-own and r3 owner-only overlays: no
change-detectors, no source-text reads, real imports and real dispatch.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from agent import team_authz
from agent.team_authz import (
    RequesterContext,
    bind_requester,
    may_send_to,
    reset_requester,
)
from hermes_state import SessionDB
from tools.session_search_tool import session_search

OWNER_ID = "900000000000000001"
MANAGER_ID = "900000000000000002"
AM_ID = "900000000000000003"
SOCIAL_ID = "900000000000000005"
OUTSIDER_ID = "900000000000000009"

GUILD = "910000000000000001"
CHAT_AM = "920000000000000003"
CHAT_SOCIAL = "920000000000000005"
CHAT_OWNER = "920000000000000001"
CHAT_MANAGER_DM = "920000000000000002"
CHAT_OVERSIGHT = "930000000000000001"
CHAT_TEAM = "930000000000000002"
CHAT_SHARED = "940000000000000001"
THREAD_SHARED = "940000000000000001t"


def _ctx(uid, *, chat, chat_type="dm", thread=None, scope=GUILD):
    return RequesterContext(platform="discord", user_id=uid, scope_id=scope,
                            chat_id=chat, chat_type=chat_type, thread_id=thread,
                            session_key=None)


CTX_OWNER = _ctx(OWNER_ID, chat=CHAT_OWNER)
CTX_MANAGER_DM = _ctx(MANAGER_ID, chat=CHAT_MANAGER_DM)
CTX_MANAGER_TEAM = _ctx(MANAGER_ID, chat=CHAT_TEAM, chat_type="channel")
CTX_MANAGER_OVERSIGHT = _ctx(MANAGER_ID, chat=CHAT_OVERSIGHT, chat_type="channel")
CTX_AM = _ctx(AM_ID, chat=CHAT_AM)
CTX_AM_TEAM = _ctx(AM_ID, chat=CHAT_TEAM, chat_type="channel")
CTX_AM_SHARED = _ctx(AM_ID, chat=CHAT_SHARED, chat_type="channel", thread=THREAD_SHARED)
CTX_SOCIAL = _ctx(SOCIAL_ID, chat=CHAT_SOCIAL)
CTX_OUTSIDER = _ctx(OUTSIDER_ID, chat="920000000000000099")


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
            _member(MANAGER_ID, "bettina", "manager"),
            _member(AM_ID, "lianna", "account_manager"),
            _member(SOCIAL_ID, "caila", "content_publisher"),
        ],
        "roles": {
            "owner": {"capabilities": ["basic", "history.read.own", "history.oversight", "owner.host"]},
            "manager": {"capabilities": ["basic", "history.read.own", "history.oversight"]},
            "account_manager": {"capabilities": ["basic", "history.read.own"]},
            "content_publisher": {"capabilities": ["basic", "history.read.own"]},
        },
        "toolActions": [],
        "connections": [],
        "spendingCaps": [],
        "oversight": {"destinations": [{"chatId": CHAT_OVERSIGHT}]},
    }


CONFIG_ENABLED = 'team_authz:\n  enabled: true\n  governed_platforms: ["discord"]\n'
CONFIG_DISABLED = "team_authz:\n  enabled: false\n"


def _write_config(home: Path, text: str):
    (home / "config.yaml").write_text(text, encoding="utf-8")


def _write_register(home: Path, reg: dict):
    d = home / "team_authz"
    d.mkdir(parents=True, exist_ok=True)
    (d / "register.json").write_text(json.dumps(reg), encoding="utf-8")


def _audit_rows(home: Path):
    p = home / "team_authz" / "audit.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


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


def _mk_session(db, sid, *, source="discord", user_id="", chat_id="", chat_type="dm",
                thread_id=None, title=None, parent=None):
    db.create_session(sid, source=source, user_id=user_id, chat_id=chat_id,
                      chat_type=chat_type, thread_id=thread_id, parent_session_id=parent)
    if title:
        db.set_session_title(sid, title)
    return sid


def _msg(db, sid, content, role="user"):
    return db.append_message(sid, role=role, content=content)


@pytest.fixture
def db(tmp_path):
    database = SessionDB(tmp_path / "state.db")
    now = int(time.time())
    _mk_session(database, "sess-am-own", user_id=AM_ID, chat_id=CHAT_AM, title="AM Private Work")
    _msg(database, "sess-am-own", "am-private-alpha quarterly plan notes")
    _msg(database, "sess-am-own", "follow-up on am-private-alpha", role="assistant")
    _mk_session(database, "sess-social-private", user_id=SOCIAL_ID, chat_id=CHAT_SOCIAL,
                title="Social Private Draft")
    _msg(database, "sess-social-private", "social-private-beta campaign draft")
    _mk_session(database, "sess-owner-private", user_id=OWNER_ID, chat_id=CHAT_OWNER,
                title="Charles Private Notes")
    _msg(database, "sess-owner-private", "charles-private-gamma personal reminder")
    _mk_session(database, "sess-cli", source="cli", user_id=AM_ID, title="CLI Work")
    _msg(database, "sess-cli", "cli-work-delta terminal session notes")
    _mk_session(database, "sess-unknown", user_id="", chat_id="legacy", title="Legacy Import")
    _msg(database, "sess-unknown", "legacy-unknown-epsilon imported notes")
    _mk_session(database, "sess-shared", user_id=SOCIAL_ID, chat_id=CHAT_SHARED,
                chat_type="channel", thread_id=THREAD_SHARED, title="Shared Thread Work")
    _msg(database, "sess-shared", "shared-theta channel discussion")
    _mk_session(database, "sess-parent", user_id=AM_ID, chat_id=CHAT_AM, title="Parent Work")
    _msg(database, "sess-parent", "parent-iota lineage root notes")
    parent_mid = _msg(database, "sess-parent", "parent-iota second message")
    _mk_session(database, "sess-child", user_id=AM_ID, chat_id=CHAT_AM,
                parent="sess-parent", title="Child Work")
    child_mid = _msg(database, "sess-child", "child-kappa lineage tip notes")
    database._conn.execute("UPDATE sessions SET started_at = ? WHERE id = ?", (now - 5000, "sess-am-own"))
    database._conn.execute("UPDATE sessions SET started_at = ? WHERE id = ?", (now - 4000, "sess-social-private"))
    database._conn.execute("UPDATE sessions SET started_at = ? WHERE id = ?", (now - 3000, "sess-owner-private"))
    database._conn.execute("UPDATE sessions SET started_at = ? WHERE id = ?", (now - 2000, "sess-shared"))
    database._conn.commit()
    database._parent_mid = parent_mid
    database._child_mid = child_mid
    return database


def _search_as(ctx, **kwargs):
    token = bind_requester(ctx)
    try:
        return json.loads(session_search(**kwargs))
    finally:
        reset_requester(token)


def _ids_from_discover(result):
    assert result["success"] is True
    assert result["mode"] == "discover"
    return {r["session_id"] for r in result["results"]}


def _ids_from_browse(result):
    assert result["success"] is True
    assert result["mode"] == "browse"
    return {r["session_id"] for r in result["results"]}


class TestUngovernedBaseline:
    def test_disabled_config_reads_everything(self, tmp_path, monkeypatch, db):
        h = tmp_path / "h2"
        h.mkdir()
        _write_config(h, CONFIG_DISABLED)
        monkeypatch.setenv("HERMES_HOME", str(h))
        team_authz._REGISTER_CACHE.clear()
        try:
            found = _search_as(CTX_AM, db=db, query="social-private-beta")
            assert "sess-social-private" in _ids_from_discover(found)
            browsed = _search_as(CTX_AM, db=db, limit=10)
            ids = _ids_from_browse(browsed)
            assert "sess-social-private" in ids
            assert "sess-owner-private" in ids
            read = _search_as(CTX_AM, db=db, session_id="sess-social-private")
            assert read["success"] is True
        finally:
            team_authz._REGISTER_CACHE.clear()
            monkeypatch.delenv("HERMES_HOME", raising=False)


class TestOwnAndSharedPositive:
    def test_own_discover_title_browse_read_scroll(self, home, db):
        found = _search_as(CTX_AM, db=db, query="am-private-alpha")
        assert "sess-am-own" in _ids_from_discover(found)
        titled = _search_as(CTX_AM, db=db, query="AM Private Work")
        assert "sess-am-own" in _ids_from_discover(titled)
        browsed = _search_as(CTX_AM, db=db, limit=10)
        assert "sess-am-own" in _ids_from_browse(browsed)
        read = _search_as(CTX_AM, db=db, session_id="sess-am-own")
        assert read["success"] is True
        assert read["mode"] == "read"
        mid = read["messages"][0]["id"]
        scrolled = _search_as(CTX_AM, db=db, session_id="sess-am-own", around_message_id=mid)
        assert scrolled["success"] is True
        assert scrolled["mode"] == "scroll"

    def test_shared_conversation_readable(self, home, db):
        found = _search_as(CTX_AM_SHARED, db=db, query="shared-theta")
        assert "sess-shared" in _ids_from_discover(found)
        read = _search_as(CTX_AM_SHARED, db=db, session_id="sess-shared")
        assert read["success"] is True
        browsed = _search_as(CTX_AM_SHARED, db=db, limit=10)
        assert "sess-shared" in _ids_from_browse(browsed)


class TestStaffIsolationNegative:
    def test_other_member_private_absent_every_mode(self, home, db):
        found = _search_as(CTX_AM, db=db, query="social-private-beta")
        assert "sess-social-private" not in _ids_from_discover(found)
        titled = _search_as(CTX_AM, db=db, query="Social Private Draft")
        assert "sess-social-private" not in _ids_from_discover(titled)
        browsed = _search_as(CTX_AM, db=db, limit=10)
        assert "sess-social-private" not in _ids_from_browse(browsed)
        read = _search_as(CTX_AM, db=db, session_id="sess-social-private")
        assert read["success"] is False
        assert "not found" in read["error"].lower()

    def test_other_member_scroll_absent(self, home, db):
        rooted = _search_as(CTX_SOCIAL, db=db, session_id="sess-social-private")
        assert rooted["success"] is True
        mid = rooted["messages"][0]["id"]
        denied = _search_as(CTX_AM, db=db, session_id="sess-social-private", around_message_id=mid)
        assert denied["success"] is False
        assert "not found" in denied["error"].lower()

    def test_unknown_and_cli_absent_for_staff(self, home, db):
        for sid, keyword in (("sess-unknown", "legacy-unknown-epsilon"), ("sess-cli", "cli-work-delta")):
            found = _search_as(CTX_AM, db=db, query=keyword)
            assert sid not in _ids_from_discover(found)
            read = _search_as(CTX_AM, db=db, session_id=sid)
            assert read["success"] is False
            assert "not found" in read["error"].lower()
        browsed = _search_as(CTX_AM, db=db, limit=10)
        ids = _ids_from_browse(browsed)
        assert "sess-unknown" not in ids
        assert "sess-cli" not in ids

    def test_outsider_gets_nothing(self, home, db):
        found = _search_as(CTX_OUTSIDER, db=db, query="am-private-alpha")
        assert _ids_from_discover(found) == set()
        browsed = _search_as(CTX_OUTSIDER, db=db, limit=10)
        assert _ids_from_browse(browsed) == set()
        read = _search_as(CTX_OUTSIDER, db=db, session_id="sess-am-own")
        assert read["success"] is False


class TestOwnerPrivate:
    def test_owner_reads_own_unknown_and_cli(self, home, db):
        for sid, keyword in (("sess-owner-private", "charles-private-gamma"),
                             ("sess-unknown", "legacy-unknown-epsilon"),
                             ("sess-cli", "cli-work-delta")):
            found = _search_as(CTX_OWNER, db=db, query=keyword)
            assert sid in _ids_from_discover(found)
            read = _search_as(CTX_OWNER, db=db, session_id=sid)
            assert read["success"] is True

    def test_manager_never_reads_owner_private(self, home, db):
        for ctx in (CTX_MANAGER_DM, CTX_MANAGER_OVERSIGHT):
            found = _search_as(ctx, db=db, query="charles-private-gamma")
            assert "sess-owner-private" not in _ids_from_discover(found)
            titled = _search_as(ctx, db=db, query="Charles Private Notes")
            assert "sess-owner-private" not in _ids_from_discover(titled)
            browsed = _search_as(ctx, db=db, limit=10)
            assert "sess-owner-private" not in _ids_from_browse(browsed)
            read = _search_as(ctx, db=db, session_id="sess-owner-private")
            assert read["success"] is False
            assert "not found" in read["error"].lower()
        rooted = _search_as(CTX_OWNER, db=db, session_id="sess-owner-private")
        mid = rooted["messages"][0]["id"]
        denied = _search_as(CTX_MANAGER_DM, db=db, session_id="sess-owner-private", around_message_id=mid)
        assert denied["success"] is False

    def test_staff_never_reads_owner_private(self, home, db):
        found = _search_as(CTX_AM, db=db, query="charles-private-gamma")
        assert "sess-owner-private" not in _ids_from_discover(found)
        read = _search_as(CTX_AM, db=db, session_id="sess-owner-private")
        assert read["success"] is False


class TestOversight:
    def test_manager_dm_oversight_allowed_and_audited(self, home, db):
        before = len(_audit_rows(home))
        found = _search_as(CTX_MANAGER_DM, db=db, query="am-private-alpha")
        assert "sess-am-own" in _ids_from_discover(found)
        read = _search_as(CTX_MANAGER_DM, db=db, session_id="sess-am-own")
        assert read["success"] is True
        browsed = _search_as(CTX_MANAGER_DM, db=db, limit=10)
        assert "sess-am-own" in _ids_from_browse(browsed)
        rows = _audit_rows(home)[before:]
        oversight = [r for r in rows if r.get("event") == "oversight" and r.get("decision") == "allowed"]
        assert oversight, "oversight reads must audit before output"
        for row in oversight:
            assert "summary" not in row
            assert "content" not in row
            assert "transcript" not in row

    def test_manager_oversight_destination_allowed(self, home, db):
        found = _search_as(CTX_MANAGER_OVERSIGHT, db=db, query="am-private-alpha")
        assert "sess-am-own" in _ids_from_discover(found)
        read = _search_as(CTX_MANAGER_OVERSIGHT, db=db, session_id="sess-am-own")
        assert read["success"] is True

    def test_manager_team_channel_denied(self, home, db):
        before = _audit_rows(home)
        found = _search_as(CTX_MANAGER_TEAM, db=db, query="am-private-alpha")
        assert "sess-am-own" not in _ids_from_discover(found)
        read = _search_as(CTX_MANAGER_TEAM, db=db, session_id="sess-am-own")
        assert read["success"] is False
        after = _audit_rows(home)
        new_oversight = [r for r in after[len(before):] if r.get("event") == "oversight"]
        assert new_oversight == []

    def test_owner_staff_read_needs_dm_or_oversight(self, home, db):
        allowed = _search_as(CTX_OWNER, db=db, session_id="sess-am-own")
        assert allowed["success"] is True
        team_ctx = _ctx(OWNER_ID, chat=CHAT_TEAM, chat_type="channel")
        denied = _search_as(team_ctx, db=db, session_id="sess-am-own")
        assert denied["success"] is False

    def test_oversight_is_not_redistribution(self, home, db):
        read = _search_as(CTX_MANAGER_DM, db=db, session_id="sess-am-own")
        assert read["success"] is True
        rows = _audit_rows(home)
        assert all(not str(r.get("event", "")).startswith("sharing-") for r in rows)
        token = bind_requester(CTX_MANAGER_DM)
        try:
            assert may_send_to({"chatId": CHAT_TEAM}, CTX_MANAGER_DM).allowed is False
        finally:
            reset_requester(token)


class TestR2DestinationBeforeOwn:
    def test_own_dm_hidden_in_team_channel(self, home, db):
        found = _search_as(CTX_AM_TEAM, db=db, query="am-private-alpha")
        assert "sess-am-own" not in _ids_from_discover(found)
        read = _search_as(CTX_AM_TEAM, db=db, session_id="sess-am-own")
        assert read["success"] is False
        browsed = _search_as(CTX_AM_TEAM, db=db, limit=10)
        assert "sess-am-own" not in _ids_from_browse(browsed)

    def test_current_conversation_visible_in_team_channel(self, home, db):
        team_shared = _ctx(SOCIAL_ID, chat=CHAT_TEAM, chat_type="channel")
        token = bind_requester(team_shared)
        try:
            pass
        finally:
            reset_requester(token)
        db.create_session("sess-team-current", source="discord", user_id=SOCIAL_ID,
                          chat_id=CHAT_TEAM, chat_type="channel")
        db.append_message("sess-team-current", role="user", content="team-current-lambda standup notes")
        found = _search_as(CTX_AM_TEAM, db=db, query="team-current-lambda")
        assert "sess-team-current" in _ids_from_discover(found)
        read = _search_as(CTX_AM_TEAM, db=db, session_id="sess-team-current")
        assert read["success"] is True


class TestExplicitProfile:
    def test_non_owner_profile_denied_without_open(self, home, db, monkeypatch):
        calls = []
        from tools import session_search_tool as mod

        def _spy(profile):
            calls.append(profile)
            raise AssertionError("profile store must not open for non-owners")

        monkeypatch.setattr(mod, "_resolve_profile_db", _spy)
        read = _search_as(CTX_AM, db=db, session_id="sess-am-own", profile="other")
        assert read["success"] is False
        assert "not found" in read["error"].lower()
        found = _search_as(CTX_AM, db=db, query="am-private-alpha", profile="other")
        assert found["success"] is True
        assert found["results"] == []
        browsed = _search_as(CTX_AM, db=db, profile="other")
        assert browsed["success"] is True
        assert browsed["results"] == []
        assert calls == []

    def test_owner_profile_allowed(self, home, db, tmp_path, monkeypatch):
        other = SessionDB(tmp_path / "other.db")
        other.create_session("sess-other", source="discord", user_id=AM_ID, chat_id=CHAT_AM)
        other.append_message("sess-other", role="user", content="other-profile-mu notes")
        from tools import session_search_tool as mod
        monkeypatch.setattr(mod, "_resolve_profile_db", lambda profile: other if profile == "other" else None)
        read = _search_as(CTX_OWNER, db=db, session_id="sess-other", profile="other")
        assert read["success"] is True
        found = _search_as(CTX_OWNER, db=db, query="other-profile-mu", profile="other")
        assert "sess-other" in _ids_from_discover(found)

    def test_embedded_link_profile_owner_only(self, home, db, tmp_path, monkeypatch):
        other = SessionDB(tmp_path / "other2.db")
        other.create_session("sess-linked", source="discord", user_id=AM_ID, chat_id=CHAT_AM)
        other.append_message("sess-linked", role="user", content="linked-nu notes")
        from tools import session_search_tool as mod
        seen = []
        def _spy(profile):
            seen.append(profile)
            return other if profile == "other" else None
        monkeypatch.setattr(mod, "_resolve_profile_db", _spy)
        denied = _search_as(CTX_AM, db=db, session_id="other/sess-linked")
        assert denied["success"] is False
        assert seen == []
        allowed = _search_as(CTX_OWNER, db=db, session_id="other/sess-linked")
        assert allowed["success"] is True


class TestLineageScrollLinks:
    def test_lineage_stops_at_denied_parent(self, home, db):
        db.create_session("sess-denied-parent", source="discord", user_id=SOCIAL_ID, chat_id=CHAT_SOCIAL)
        db.append_message("sess-denied-parent", role="user", content="denied-parent-xi notes")
        db.create_session("sess-allowed-child", source="discord", user_id=AM_ID, chat_id=CHAT_AM,
                          parent_session_id="sess-denied-parent")
        db.append_message("sess-allowed-child", role="user", content="allowed-child-omicron notes")
        from tools.session_search_tool import _resolve_lineage
        token = bind_requester(CTX_AM)
        try:
            assert _resolve_lineage(db, "sess-allowed-child") == "sess-allowed-child"
        finally:
            reset_requester(token)
        found = _search_as(CTX_AM, db=db, query="allowed-child-omicron")
        assert "sess-allowed-child" in _ids_from_discover(found)
        hidden = _search_as(CTX_AM, db=db, query="denied-parent-xi")
        assert "sess-denied-parent" not in _ids_from_discover(hidden)

    def test_scroll_rebind_requires_readable_owner(self, home, db):
        child_mid = db._child_mid
        allowed = _search_as(CTX_AM, db=db, session_id="sess-parent", around_message_id=child_mid)
        assert allowed["success"] is True
        assert allowed["session_id"] == "sess-child"
        denied = _search_as(CTX_SOCIAL, db=db, session_id="sess-parent", around_message_id=child_mid)
        assert denied["success"] is False

    def test_denied_rows_have_no_links(self, home, db):
        found = _search_as(CTX_AM, db=db, query="social-private-beta")
        for entry in found["results"]:
            assert entry["session_id"] != "sess-social-private"
            assert "sess-social-private" not in entry.get("link", "")


class TestInlineExecutor:
    def test_denied_principal_blocked_before_db(self, home, db):
        from agent.inline_tool_executors import INLINE_TOOL_EXECUTORS, InlineToolContext

        class _Agent:
            session_id = "sess-am-own"
            def _get_session_db_for_recall(self):
                raise AssertionError("DB must not be touched for denied principals")

        token = bind_requester(CTX_OUTSIDER)
        try:
            out = json.loads(INLINE_TOOL_EXECUTORS["session_search"](
                _Agent(), {"query": "am-private-alpha"}, InlineToolContext(effective_task_id="t")))
        finally:
            reset_requester(token)
        assert out["success"] is False
        assert "denied" in out["error"].lower()

    def test_allowed_principal_filters_rows(self, home, db):
        from agent.inline_tool_executors import INLINE_TOOL_EXECUTORS, InlineToolContext

        class _Agent:
            session_id = "sess-am-own"
            def _get_session_db_for_recall(self):
                return db

        token = bind_requester(CTX_AM)
        try:
            out = json.loads(INLINE_TOOL_EXECUTORS["session_search"](
                _Agent(), {"query": "social-private-beta"}, InlineToolContext(effective_task_id="t")))
        finally:
            reset_requester(token)
        assert out["success"] is True
        assert all(r["session_id"] != "sess-social-private" for r in out["results"])
