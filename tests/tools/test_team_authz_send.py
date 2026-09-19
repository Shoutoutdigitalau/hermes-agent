"""HTS-06: destination-restricted outbound delivery with consented summaries.

A governed non-owner reaches only the originating chat/thread — checked at
dispatch against the FINAL resolved destination (home fallback, directory
aliases and thread included) — and a consented summary additionally requires
its exact author bytes/destination via ``authorize_sharing`` (audited before
delivery, conjunctive with ordinary authority) and carries no attachments.
Owner and ungoverned behaviour equals base.

Synthetic identities only (``9000000000000000NN``), temp HERMES_HOME, fake
standalone sender. Every deny path proves zero egress.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent import team_authz
from agent.team_authz import (
    RequesterContext,
    bind_requester,
    reset_requester,
)
from agent.team_authz_sharing import record_sharing_consent
from gateway.config import Platform
from tools.send_message_tool import send_message_tool

OWNER_ID = "900000000000000001"
AM_ID = "900000000000000003"
OUTSIDER_ID = "900000000000000009"

GUILD = "910000000000000001"
CHAT_AM = "920000000000000003"
CHAT_TEAM = "930000000000000010"
CHAT_OUTSIDE = "930000000000000099"
HOME_CHAT = "920000000000000003"
THREAD_A = "940000000000000001"
THREAD_B = "940000000000000002"

SUMMARY = "Exact approved summary bytes."

CONFIG_ENABLED = "team_authz:\n  enabled: true\n  governed_platforms: [\"discord\"]\n"
CONFIG_DISABLED = "team_authz:\n  enabled: false\n"


def _ctx(uid, *, scope=GUILD, chat=CHAT_AM, chat_type="group", thread=None) -> RequesterContext:
    return RequesterContext(platform="discord", user_id=uid, scope_id=scope,
                            chat_id=chat, chat_type=chat_type, thread_id=thread)


CTX_OWNER = _ctx(OWNER_ID, chat="920000000000000001", chat_type="dm")
CTX_AM = _ctx(AM_ID, chat=CHAT_AM)
CTX_AM_TEAM = _ctx(AM_ID, chat=CHAT_TEAM)


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
            "owner": {"capabilities": ["client.message.send", "owner.host"]},
            "account_manager": {"capabilities": ["client.message.send"]},
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


def _audit_rows(home: Path) -> list:
    p = home / "team_authz" / "audit.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "hermes-home"
    h.mkdir()
    (h / "config.yaml").write_text(CONFIG_ENABLED, encoding="utf-8")
    _write_register(h, _base_register())
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


def _gateway_config(home_chat=HOME_CHAT):
    discord_cfg = SimpleNamespace(enabled=True, token="t", extra={})
    return SimpleNamespace(
        platforms={Platform.DISCORD: discord_cfg},
        get_home_channel=lambda _p: SimpleNamespace(chat_id=home_chat),
    )


def _send(home, args, sent, *, home_chat=HOME_CHAT):
    """Drive the REAL tool entrypoint; record any dispatch the gate permits."""

    async def _record(pconfig, chat_id, text, **kw):
        rows = _audit_rows(home)
        sent.append({"chat_id": chat_id, "text": text, "kw": kw,
                     "sharing_check_visible": any(r.get("event") == "sharing-check"
                                                  for r in rows)})
        return {"success": True, "message_id": "m1"}

    # The relay egress guard is neutralised: it answers from live-gateway state
    # this suite does not construct, and its own suite covers it. The team gate
    # under test runs downstream at dispatch.
    with patch("gateway.config.load_gateway_config", return_value=_gateway_config(home_chat)), \
         patch("tools.interrupt.is_interrupted", return_value=False), \
         patch("model_tools._run_async", side_effect=lambda c: asyncio.run(c)), \
         patch("tools.send_message_tool._authorize_relay_target", return_value=None), \
         patch("tools.send_message_tool._plugin_standalone_sender",
               return_value=(_record, None)), \
         patch("gateway.mirror.mirror_to_session", return_value=False):
        return json.loads(send_message_tool(args))


def _record_consent(ctx, summary=SUMMARY, chat=CHAT_TEAM, thread=None, status="approved"):
    dest = {"shape": "messaging", "platform": "discord", "guild": GUILD, "chatId": chat}
    if thread is not None:
        dest["threadId"] = thread
    with bound(ctx):
        decision = record_sharing_consent({
            "sourceRef": "sess-am-1", "authorDiscordUserId": AM_ID,
            "summary": summary, "destination": dest, "status": status,
        })
    assert decision.allowed is True
    return decision.action


class TestPrivateMedia:
    @pytest.mark.parametrize("relative", ["owner.png", "cache/owner.png"])
    def test_origin_send_attaches_own_local_file(self, home, relative):
        private = home / relative
        private.parent.mkdir(parents=True, exist_ok=True)
        private.write_bytes(b"\x89PNG\r\n\x1a\n" + b"synthetic-owner-media")
        sent = []
        with bound(CTX_AM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_AM}",
                                  "message": "Private file MEDIA:" + str(private)}, sent)
        assert result == {"success": True, "message_id": "m1"}
        assert [s["chat_id"] for s in sent] == [CHAT_AM]
        assert sent[0]["kw"].get("media_files")


class TestOriginOnly:
    def test_member_send_to_origin_allowed(self, home):
        sent: list = []
        with bound(CTX_AM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_AM}",
                                  "message": "hello"}, sent)
        assert result == {"success": True, "message_id": "m1"}
        assert [s["chat_id"] for s in sent] == [CHAT_AM]

    def test_member_send_to_other_chat_denied_with_zero_egress(self, home):
        sent: list = []
        with bound(CTX_AM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_OUTSIDE}",
                                  "message": "hello"}, sent)
        assert "Refusing to send" in result["error"]
        assert "destination-outside-origin" in result["error"]
        assert sent == []

    def test_matching_thread_allowed_mismatch_denied(self, home):
        sent: list = []
        ctx = _ctx(AM_ID, chat=CHAT_TEAM, thread=THREAD_A)
        with bound(ctx):
            ok = _send(home, {"action": "send",
                              "target": f"discord:{CHAT_TEAM}:{THREAD_A}",
                              "message": "hello"}, sent)
            denied = _send(home, {"action": "send",
                                  "target": f"discord:{CHAT_TEAM}:{THREAD_B}",
                                  "message": "hello"}, sent)
        assert ok["success"] is True
        assert "destination-outside-origin" in denied["error"]
        assert [s["chat_id"] for s in sent] == [CHAT_TEAM]
        assert sent[0]["kw"].get("thread_id") == THREAD_A

    def test_home_channel_fallback_is_checked_at_dispatch(self, home):
        sent: list = []
        with bound(CTX_AM_TEAM):
            denied = _send(home, {"action": "send", "target": "discord",
                                  "message": "hello"}, sent, home_chat=CHAT_OUTSIDE)
            assert "destination-outside-origin" in denied["error"]
            assert sent == []
            ok = _send(home, {"action": "send", "target": "discord",
                              "message": "hello"}, sent, home_chat=CHAT_TEAM)
        assert ok["success"] is True
        assert [s["chat_id"] for s in sent] == [CHAT_TEAM]

    def test_directory_alias_is_resolved_then_authorized(self, home):
        sent: list = []
        with bound(CTX_AM):
            with patch("gateway.channel_directory.resolve_channel_name",
                       return_value=CHAT_OUTSIDE):
                denied = _send(home, {"action": "send", "target": "discord:#bot-home",
                                      "message": "hello"}, sent)
            assert "destination-outside-origin" in denied["error"]
            assert sent == []
            with patch("gateway.channel_directory.resolve_channel_name",
                       return_value=CHAT_AM):
                ok = _send(home, {"action": "send", "target": "discord:#bot-home",
                                  "message": "hello"}, sent)
        assert ok["success"] is True
        assert [s["chat_id"] for s in sent] == [CHAT_AM]

    def test_owner_send_anywhere_allowed(self, home):
        sent: list = []
        with bound(CTX_OWNER):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_OUTSIDE}",
                                  "message": "hello"}, sent)
        assert result["success"] is True
        assert [s["chat_id"] for s in sent] == [CHAT_OUTSIDE]

    def test_disabled_config_is_base_behaviour(self, home):
        (home / "config.yaml").write_text(CONFIG_DISABLED, encoding="utf-8")
        sent: list = []
        with bound(CTX_AM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_OUTSIDE}",
                                  "message": "hello"}, sent)
        assert result["success"] is True
        assert [s["chat_id"] for s in sent] == [CHAT_OUTSIDE]

    def test_denied_principal_sends_nothing(self, home):
        sent: list = []
        with bound(_ctx(OUTSIDER_ID, chat=CHAT_OUTSIDE)):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_OUTSIDE}",
                                  "message": "hello"}, sent)
        assert "unknown-identity" in result["error"]
        assert sent == []

    def test_revoked_mid_session_denies_next_send(self, home):
        sent: list = []
        with bound(CTX_AM):
            assert _send(home, {"action": "send", "target": f"discord:{CHAT_AM}",
                               "message": "hello"}, sent)["success"] is True
        reg = _base_register()
        reg["policyVersion"] = "2026.09.17-hts06-revoked"
        reg["members"] = [dict(m, status="revoked") if m["discordUserId"] == AM_ID else m
                          for m in reg["members"]]
        _write_register(home, reg)
        with bound(CTX_AM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_AM}",
                                  "message": "hello"}, sent)
        assert "revoked" in result["error"]
        assert len(sent) == 1

    def test_ordinary_attachment_constrained_to_origin(self, home, tmp_path):
        from gateway.platforms.base import _write_cache_file
        sent: list = []
        with bound(CTX_AM):
            # Real producer, trusted bytes; a model-selected arbitrary path is
            # not evidence that this requester produced the attachment.
            media = _write_cache_file(tmp_path, "note", ".txt", b"attachment bytes")
            ok = _send(home, {"action": "send", "target": f"discord:{CHAT_AM}",
                              "message": f"see this MEDIA:{media}"}, sent)
            denied = _send(home, {"action": "send", "target": f"discord:{CHAT_OUTSIDE}",
                                  "message": f"see this MEDIA:{media}"}, sent)
        assert ok["success"] is True
        assert "destination-outside-origin" in denied["error"]
        assert [s["chat_id"] for s in sent] == [CHAT_AM]
        assert sent[0]["kw"].get("media_files")

    def test_react_is_origin_only(self, home):
        reacted: list = []

        class _FakeAdapter:
            async def add_reaction(self, *, chat_id, message_id, emoji):
                reacted.append((chat_id, emoji))
                return {"success": True}

        with bound(CTX_AM):
            with patch("tools.send_message_tool._authorize_relay_target", return_value=None), \
                 patch("tools.send_message_tool._live_adapter",
                       return_value=(SimpleNamespace(), _FakeAdapter())):
                ok = json.loads(send_message_tool(
                    {"action": "react", "target": f"discord:{CHAT_AM}", "emoji": "👍"}))
                denied = json.loads(send_message_tool(
                    {"action": "react", "target": f"discord:{CHAT_OUTSIDE}", "emoji": "👍"}))
        assert ok == {"success": True}
        assert "destination-outside-origin" in denied["error"]
        assert reacted == [(CHAT_AM, "👍")]


class TestConsentedDelivery:
    def test_exact_consent_allowed_and_audited_before_dispatch(self, home):
        consent_id = _record_consent(CTX_AM_TEAM)
        sent: list = []
        with bound(CTX_AM_TEAM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_TEAM}",
                                  "message": SUMMARY,
                                  "sharing_consent_id": consent_id,
                                  "sharing_source_ref": "sess-am-1"}, sent)
        assert result["success"] is True
        assert len(sent) == 1
        assert sent[0]["sharing_check_visible"] is True
        rows = [r for r in _audit_rows(home) if r.get("event") == "sharing-check"]
        assert rows and rows[0]["approvalRef"] == consent_id

    def test_one_byte_mutation_denied(self, home):
        consent_id = _record_consent(CTX_AM_TEAM)
        sent: list = []
        with bound(CTX_AM_TEAM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_TEAM}",
                                  "message": SUMMARY + "!",
                                  "sharing_consent_id": consent_id,
                                  "sharing_source_ref": "sess-am-1"}, sent)
        assert "consent-summary-mismatch" in result["error"]
        assert sent == []

    def test_wrong_destination_consent_denied(self, home):
        consent_id = _record_consent(CTX_AM_TEAM, chat=CHAT_OUTSIDE)
        sent: list = []
        with bound(CTX_AM_TEAM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_TEAM}",
                                  "message": SUMMARY,
                                  "sharing_consent_id": consent_id,
                                  "sharing_source_ref": "sess-am-1"}, sent)
        assert "consent-destination-mismatch" in result["error"]
        assert sent == []

    def test_revoked_consent_denied(self, home):
        consent_id = _record_consent(CTX_AM_TEAM)
        _record_consent(CTX_AM_TEAM, status="revoked")
        sent: list = []
        with bound(CTX_AM_TEAM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_TEAM}",
                                  "message": SUMMARY,
                                  "sharing_consent_id": consent_id,
                                  "sharing_source_ref": "sess-am-1"}, sent)
        assert "consent-revoked" in result["error"]
        assert sent == []

    def test_unknown_consent_denied(self, home):
        sent: list = []
        with bound(CTX_AM_TEAM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_TEAM}",
                                  "message": SUMMARY,
                                  "sharing_consent_id": "shc_missing",
                                  "sharing_source_ref": "sess-am-1"}, sent)
        assert "consent-unknown" in result["error"]
        assert sent == []

    def test_consent_with_attachment_denied(self, home, tmp_path):
        consent_id = _record_consent(CTX_AM_TEAM)
        media = tmp_path / "note.txt"
        media.write_text("attachment bytes", encoding="utf-8")
        sent: list = []
        with bound(CTX_AM_TEAM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_TEAM}",
                                  "message": f"{SUMMARY} MEDIA:{media}",
                                  "sharing_consent_id": consent_id,
                                  "sharing_source_ref": "sess-am-1"}, sent)
        assert "no attachments" in result["error"]
        assert sent == []

    def test_perfect_consent_cannot_override_off_origin(self, home):
        consent_id = _record_consent(CTX_AM_TEAM)
        sent: list = []
        with bound(CTX_AM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_TEAM}",
                                  "message": SUMMARY,
                                  "sharing_consent_id": consent_id,
                                  "sharing_source_ref": "sess-am-1"}, sent)
        assert "destination-outside-origin" in result["error"]
        assert sent == []

    def test_consent_cannot_overcome_revoked_requester(self, home):
        consent_id = _record_consent(CTX_AM_TEAM)
        reg = _base_register()
        reg["policyVersion"] = "2026.09.17-hts06-revoked"
        reg["members"] = [dict(m, status="revoked") if m["discordUserId"] == AM_ID else m
                          for m in reg["members"]]
        _write_register(home, reg)
        sent: list = []
        with bound(CTX_AM_TEAM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_TEAM}",
                                  "message": SUMMARY,
                                  "sharing_consent_id": consent_id,
                                  "sharing_source_ref": "sess-am-1"}, sent)
        assert "revoked" in result["error"]
        assert sent == []

    def test_incomplete_consent_reference_denied(self, home):
        consent_id = _record_consent(CTX_AM_TEAM)
        sent: list = []
        with bound(CTX_AM_TEAM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_TEAM}",
                                  "message": SUMMARY,
                                  "sharing_consent_id": consent_id}, sent)
        assert "incomplete sharing-consent reference" in result["error"]
        assert sent == []

    def test_consent_audit_failure_denies_delivery(self, home, monkeypatch):
        import agent.team_authz_sharing as sharing
        consent_id = _record_consent(CTX_AM_TEAM)
        monkeypatch.setattr(sharing, "audit", lambda event: False)
        sent: list = []
        with bound(CTX_AM_TEAM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_TEAM}",
                                  "message": SUMMARY,
                                  "sharing_consent_id": consent_id,
                                  "sharing_source_ref": "sess-am-1"}, sent)
        assert "audit-failure" in result["error"]
        assert sent == []

    def test_ordinary_send_without_consent_still_allowed(self, home):
        _record_consent(CTX_AM_TEAM)
        sent: list = []
        with bound(CTX_AM_TEAM):
            result = _send(home, {"action": "send", "target": f"discord:{CHAT_TEAM}",
                                  "message": "ordinary chatter"}, sent)
        assert result["success"] is True
        assert len(sent) == 1

    def test_summary_body_never_in_audit(self, home):
        consent_id = _record_consent(CTX_AM_TEAM)
        sent: list = []
        with bound(CTX_AM_TEAM):
            assert _send(home, {"action": "send", "target": f"discord:{CHAT_TEAM}",
                               "message": SUMMARY,
                               "sharing_consent_id": consent_id,
                               "sharing_source_ref": "sess-am-1"}, sent)["success"] is True
        raw = (home / "team_authz" / "audit.jsonl").read_text(encoding="utf-8")
        assert SUMMARY not in raw
        assert consent_id in raw
