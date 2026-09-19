"""HTS-04 cron tests: job origin stamps persisted at creation and re-resolved
at fire time, with unknown, revoked, stale or ref-less governed jobs dropped
with an audit row before any script or agent runs.

Synthetic identities only (``9000000000000000NN``), temp HERMES_HOME written by
the test, synthetic jobs only. Behaviour contracts per INITIAL_SPEC.md
section 4 (gates 1, 8): no change-detectors, no source-text reads, real
imports and real seam functions.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from agent import team_authz
from agent.team_authz import (
    RequesterContext,
    bind_requester,
    grant_digest,
    reset_requester,
)
from cron.jobs import create_job, get_job, update_job
from cron.scheduler import (
    _CronRunScope,
    _FireOwnership,
    _RunDelivery,
    _deliver_crash_failure,
    _gate_governed_delivery,
    _gate_job_requester,
    _save_compose_deliver,
    drain_delivery_queue,
    run_job,
)

AM_ID = "900000000000000003"
META_ID = "900000000000000004"
OUTSIDER_ID = "900000000000000009"
OWNER_ID = "900000000000000001"
GUILD = "910000000000000001"

CTX_AM = RequesterContext(platform="discord", user_id=AM_ID, scope_id=GUILD,
                          chat_id="920000000000000003", chat_type="dm")
CTX_OWNER = RequesterContext(platform="discord", user_id=OWNER_ID, scope_id=GUILD,
                             chat_id="920000000000000001", chat_type="dm")
CTX_OUTSIDER = RequesterContext(platform="discord", user_id=OUTSIDER_ID,
                                scope_id=GUILD, chat_id="920000000000000009")
CTX_AM_THREAD = RequesterContext(platform="discord", user_id=AM_ID, scope_id=GUILD,
                                 chat_id="920000000000000003", chat_type="dm",
                                 thread_id="960000000000000001")

OTHER_CHAT = "920000000000000099"
OTHER_THREAD = "960000000000000002"
CHAT_AM = "920000000000000003"

IDENTITY_FIELDS = {"platform", "user_id", "scope_id", "chat_id", "chat_type",
                   "thread_id", "session_key"}

CONFIG_ENABLED = "team_authz:\n  enabled: true\n  governed_platforms: [\"discord\"]\n"
FUTURE_ISO = "2030-01-02T03:04:05Z"


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
            "owner": {"capabilities": ["basic", "web.read", "delegate", "owner.host"]},
            "account_manager": {"capabilities": ["basic", "web.read", "delegate"]},
            "meta_ads_operator": {"capabilities": ["basic", "web.read", "delegate"]},
        },
        "toolActions": [],
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


def _cron_drops(home: Path):
    return [r for r in _audit_rows(home) if r.get("event") == "cron-drop"]


# ---------------------------------------------------------------------------
# Origin stamps
# ---------------------------------------------------------------------------


class TestJobOriginStamp:
    def test_create_job_stamps_governed_origin(self, home):
        with bound(CTX_AM):
            expected_digest = grant_digest()
            job = create_job(prompt="synthetic cron prompt", schedule=FUTURE_ISO,
                             name="synthetic")
        assert job["requester_governed"] is True
        assert set(job["requester_ref"]) == IDENTITY_FIELDS
        assert job["requester_ref"]["user_id"] == AM_ID
        assert job["requester_digest"] == expected_digest
        reread = get_job(job["id"])
        assert reread["requester_ref"] == job["requester_ref"]
        assert reread["requester_digest"] == expected_digest

    def test_create_job_ungoverned_has_no_stamp(self, home_plain):
        job = create_job(prompt="synthetic cron prompt", schedule=FUTURE_ISO,
                         name="synthetic")
        assert "requester_ref" not in job
        assert "requester_governed" not in job
        assert "requester_digest" not in job

    def test_update_rejects_stamp_rewrite(self, home):
        with bound(CTX_AM):
            job = create_job(prompt="synthetic cron prompt", schedule=FUTURE_ISO,
                             name="synthetic")
        with pytest.raises(ValueError):
            update_job(job["id"], {"requester_governed": False})
        with pytest.raises(ValueError):
            update_job(job["id"], {"requester_ref": {"user_id": OUTSIDER_ID}})
        with pytest.raises(ValueError):
            update_job(job["id"], {"requester_digest": "forged"})
        updated = update_job(job["id"], {"name": "renamed"})
        assert updated["name"] == "renamed"
        assert updated["requester_ref"]["user_id"] == AM_ID
        assert updated["requester_governed"] is True


# ---------------------------------------------------------------------------
# Fire-time gate (gates 1, 8)
# ---------------------------------------------------------------------------


class TestFireGate:
    def _governed_job(self, home, ctx=CTX_AM):
        with bound(ctx):
            return create_job(prompt="synthetic cron prompt", schedule=FUTURE_ISO,
                              name="synthetic")

    def test_fire_drops_revoked_before_backend(self, home):
        job = self._governed_job(home)
        _revoke(home, AM_ID)
        with patch("run_agent.AIAgent", side_effect=AssertionError("backend touched")):
            success, doc, final, error = run_job(get_job(job["id"]))
        assert success is False
        assert "member-revoked" in error
        assert "NOT run" in doc
        assert final == ""
        drops = _cron_drops(home)
        assert any(d.get("reason") == "member-revoked" and d.get("decision") == "denied"
                   for d in drops)

    def test_fire_drops_no_agent_job_before_script(self, home):
        with bound(CTX_AM):
            job = create_job(prompt="", script="/nonexistent-dir/synth-cron-04.sh",
                             no_agent=True, schedule=FUTURE_ISO, name="synthetic")
        assert job["requester_governed"] is True
        _revoke(home, AM_ID)
        success, _doc, final, error = run_job(get_job(job["id"]))
        assert success is False
        assert "member-revoked" in error
        assert final == ""

    def test_fire_drops_unknown_requester(self, home):
        job = self._governed_job(home, CTX_OUTSIDER)
        assert job["requester_governed"] is True
        success, _doc, _final, error = run_job(get_job(job["id"]))
        assert success is False
        assert "unknown-identity" in error

    def test_fire_drops_ref_less_governed_job(self, home):
        job = self._governed_job(home)
        job = dict(job, requester_ref={})
        success, _doc, _final, error = run_job(job)
        assert success is False
        assert "no-requester-context" in error
        assert any(d.get("reason") == "no-requester-context" for d in _cron_drops(home))

    def test_fire_drops_stale_grant(self, home):
        job = self._governed_job(home)
        _reassign_role(home, AM_ID, "meta_ads_operator")
        success, _doc, _final, error = run_job(get_job(job["id"]))
        assert success is False
        assert "requester-stale" in error

    def test_fire_gate_passes_active_member(self, home):
        job = self._governed_job(home)
        assert _gate_job_requester(get_job(job["id"]), job["id"], job["name"]) is None
        assert _cron_drops(home) == []

    def test_legacy_job_ungated(self, home_plain):
        job = create_job(prompt="synthetic cron prompt", schedule=FUTURE_ISO,
                         name="synthetic")
        assert _gate_job_requester(job, job["id"], job["name"]) is None


# ---------------------------------------------------------------------------
# Run-scope binding
# ---------------------------------------------------------------------------


class TestRunScopeBinding:
    def test_scope_binds_and_releases_requester(self, home):
        with bound(CTX_AM):
            job = create_job(prompt="synthetic cron prompt", schedule=FUTURE_ISO,
                             name="synthetic")
        scope = _CronRunScope(get_job(job["id"]), job["id"], None)
        try:
            scope.enter()
            current = team_authz.current_requester()
            assert current is not None and current.user_id == AM_ID
            assert team_authz._provenance() == "ref"
        finally:
            scope.exit()
        assert team_authz.current_requester() is None

    def test_scope_ignores_unmarked_job(self, home_plain):
        job = create_job(prompt="synthetic cron prompt", schedule=FUTURE_ISO,
                         name="synthetic")
        scope = _CronRunScope(job, job["id"], None)
        try:
            scope.enter()
            assert team_authz.current_requester() is None
        finally:
            scope.exit()


def _delivery_drops(home: Path):
    return [r for r in _audit_rows(home) if r.get("event") == "cron-delivery-drop"]


# ---------------------------------------------------------------------------
# Governed delivery floor (repair: origin-only adapter delivery)
# ---------------------------------------------------------------------------


class TestGovernedDelivery:
    def _job(self, home, ctx=CTX_AM, origin_chat=CHAT_AM, origin_platform="discord",
             origin_thread=None, deliver="origin", **kw):
        origin = {"platform": origin_platform, "chat_id": origin_chat}
        if origin_thread is not None:
            origin["thread_id"] = origin_thread
        with bound(ctx):
            return create_job(prompt="synthetic cron prompt", schedule=FUTURE_ISO,
                              name="synthetic", origin=origin, deliver=deliver, **kw)

    def test_origin_delivery_allowed(self, home):
        job = self._job(home)
        assert _gate_governed_delivery(get_job(job["id"]), for_failure=False) is None
        assert _delivery_drops(home) == []

    def test_cross_origin_delivery_denied(self, home):
        job = self._job(home, origin_chat=OTHER_CHAT)
        reason = _gate_governed_delivery(get_job(job["id"]), for_failure=False)
        assert reason == "destination-outside-origin"
        drops = _delivery_drops(home)
        assert len(drops) == 1
        assert drops[0]["decision"] == "denied"
        assert drops[0]["destination"] == OTHER_CHAT

    def test_cross_platform_delivery_denied(self, home):
        job = self._job(home, origin_platform="telegram")
        reason = _gate_governed_delivery(get_job(job["id"]), for_failure=False)
        assert reason == "destination-outside-origin"

    def test_thread_mismatch_denied(self, home):
        job = self._job(home, ctx=CTX_AM_THREAD, origin_thread=OTHER_THREAD)
        reason = _gate_governed_delivery(get_job(job["id"]), for_failure=False)
        assert reason == "destination-outside-origin"

    def test_owner_cross_origin_allowed(self, home):
        job = self._job(home, ctx=CTX_OWNER, origin_chat=OTHER_CHAT)
        assert _gate_governed_delivery(get_job(job["id"]), for_failure=False) is None
        assert _delivery_drops(home) == []

    def test_delivery_denies_revoked_requester(self, home):
        job = self._job(home)
        _revoke(home, AM_ID)
        reason = _gate_governed_delivery(get_job(job["id"]), for_failure=False)
        assert reason == "member-revoked"

    def test_delivery_denies_stale_grant(self, home):
        job = self._job(home)
        _reassign_role(home, AM_ID, "meta_ads_operator")
        reason = _gate_governed_delivery(get_job(job["id"]), for_failure=False)
        assert reason == "requester-stale"

    def test_local_only_delivery_allowed(self, home):
        with bound(CTX_AM):
            job = create_job(prompt="synthetic cron prompt", schedule=FUTURE_ISO,
                             name="synthetic", deliver="local")
        assert job["requester_governed"] is True
        assert _gate_governed_delivery(get_job(job["id"]), for_failure=False) is None

    def test_failure_lane_gated_independently(self, home):
        job = self._job(home, deliver="local", failure_deliver="origin")
        assert _gate_governed_delivery(get_job(job["id"]), for_failure=False) is None
        job = self._job(home, origin_chat=OTHER_CHAT, deliver="local",
                        failure_deliver="origin")
        assert _gate_governed_delivery(get_job(job["id"]), for_failure=False) is None
        reason = _gate_governed_delivery(get_job(job["id"]), for_failure=True)
        assert reason == "destination-outside-origin"

    def test_ungoverned_delivery_ungated(self, home_plain):
        job = create_job(prompt="synthetic cron prompt", schedule=FUTURE_ISO,
                         name="synthetic", origin={"platform": "discord", "chat_id": OTHER_CHAT},
                         deliver="origin")
        assert _gate_governed_delivery(job, for_failure=False) is None

    def test_save_compose_deliver_blocks_before_adapter(self, home):
        job = self._job(home, origin_chat=OTHER_CHAT)
        d = _RunDelivery(job=get_job(job["id"]), success=True, error=None)
        fence = _FireOwnership(d.job, None)
        with patch("cron.scheduler._deliver_result",
                   side_effect=AssertionError("adapter touched")) as spy:
            _save_compose_deliver(d, fence, "synthetic final", "synthetic output",
                                  adapters=None, loop=None, verbose=False,
                                  execution_token=None)
        assert d.delivery_attempted is True
        assert "destination-outside-origin" in (d.delivery_error or "")
        spy.assert_not_called()
        assert any(r.get("reason") == "destination-outside-origin"
                   for r in _delivery_drops(home))

    def test_save_compose_deliver_sends_to_origin(self, home):
        job = self._job(home)
        d = _RunDelivery(job=get_job(job["id"]), success=True, error=None)
        fence = _FireOwnership(d.job, None)
        with patch("cron.scheduler._deliver_result", return_value=None) as spy:
            _save_compose_deliver(d, fence, "synthetic final", "synthetic output",
                                  adapters=None, loop=None, verbose=False,
                                  execution_token=None)
        spy.assert_called_once()
        assert d.delivery_error is None

    def test_crash_failure_delivery_blocked(self, home):
        job = self._job(home, origin_chat=OTHER_CHAT)
        with patch("cron.scheduler._deliver_result",
                   side_effect=AssertionError("adapter touched")) as spy:
            delivery_error, outcome = _deliver_crash_failure(
                get_job(job["id"]), "synthetic error", adapters=None, loop=None)
        assert "destination-outside-origin" in (delivery_error or "")
        assert outcome == "failed"
        spy.assert_not_called()

    def test_queued_delivery_blocked_at_drain(self, home):
        from cron.delivery_queue import enqueue
        job = self._job(home, origin_chat=OTHER_CHAT)
        enqueue("exec-synth-hts04", get_job(job["id"]), "synthetic content",
                for_failure=False)
        with patch("cron.scheduler._deliver_result",
                   side_effect=AssertionError("adapter touched")) as spy:
            assert drain_delivery_queue(None, None) == 1
            assert drain_delivery_queue(None, None) == 0
        spy.assert_not_called()
        assert any(r.get("reason") == "destination-outside-origin"
                   for r in _delivery_drops(home))
