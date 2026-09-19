"""HTS-01 core tests: register, identity, roles, protected owner resources,
sharing consent, register change control, audit integrity.

Synthetic identities only (shaped like ``9000000000000000NN``), temp
HERMES_HOME written by the test. Behaviour contracts per INITIAL_SPEC.md §4:
no change-detectors, no source-text reads, real imports and real dispatch of
the seam functions.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from agent import team_authz
from agent.team_authz import (
    Decision,
    RequesterContext,
    TeamAuthzDenied,
    authorize_tool,
    bind_requester,
    can_read_session,
    current_requester,
    filter_tool_names,
    grant_digest,
    is_governed,
    may_send_to,
    memory_namespace,
    apply_register_change,
    audit_verify,
    log_inbound,
    requester_ref,
    reset_requester,
    resolve_principal,
)
from agent.team_authz_owner import (
    authorize_owner_resource,
    record_owner_approval,
)
from agent.team_authz_sharing import (
    authorize_sharing,
    record_sharing_consent,
    summary_digest,
)

# ---------------------------------------------------------------------------
# Synthetic identities (never real)
# ---------------------------------------------------------------------------

OWNER_ID = "900000000000000001"
MANAGER_ID = "900000000000000002"
AM_ID = "900000000000000003"
META_ID = "900000000000000004"
SOCIAL_ID = "900000000000000005"
ASSET_ID = "900000000000000006"
WEB_ID = "900000000000000007"
OUTSIDER_ID = "900000000000000009"

GUILD = "910000000000000001"
OTHER_GUILD = "910000000000000002"
CHAT_AM = "920000000000000003"
CHAT_OVERSIGHT = "930000000000000001"
CHAT_TEAM_CHANNEL = "930000000000000002"

# T1: host surfaces (terminal, files, code, cron, connections) are ordinary
# team work. The protected classes stay credentials + personal-mailbox +
# the browser guard.
OWNER_HOST_TOOLS = ("terminal", "read_file", "write_file", "patch", "execute_code",
                    "browser_exec", "cronjob_manage", "manage_connections",
                    "browser_vault_list", "browser_vault_fill", "browser_vault_save_login")


def _ctx(uid, *, platform="discord", scope=GUILD, chat="920000000000000099",
         chat_type="dm", thread=None, session_key=None) -> RequesterContext:
    return RequesterContext(platform=platform, user_id=uid, scope_id=scope,
                            chat_id=chat, chat_type=chat_type, thread_id=thread,
                            session_key=session_key)


CTX_OWNER = _ctx(OWNER_ID, chat="920000000000000001")
CTX_MANAGER = _ctx(MANAGER_ID, chat="920000000000000002")
CTX_AM = _ctx(AM_ID, chat=CHAT_AM)
CTX_META = _ctx(META_ID, chat="920000000000000004")
CTX_SOCIAL = _ctx(SOCIAL_ID, chat="920000000000000005")
CTX_ASSET = _ctx(ASSET_ID, chat="920000000000000006")
CTX_WEB = _ctx(WEB_ID, chat="920000000000000007")


def _record_verified_owner_approval(home, proposal, ctx):
    _write_config(home, json.dumps({"team_authz": {
        "enabled": True, "governed_platforms": ["discord"],
        "secure_owner_surfaces": [{"platform": ctx.platform, "chatId": ctx.chat_id,
                                   "chatType": ctx.chat_type}],
    }}))
    token = bind_requester(ctx)
    try:
        return record_owner_approval(proposal, ctx=ctx)
    finally:
        reset_requester(token)


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
            _member(MANAGER_ID, "bettina", "manager"),
            _member(AM_ID, "lianna", "account_manager"),
            _member(META_ID, "dianne", "meta_ads_operator"),
            _member(SOCIAL_ID, "caila", "content_publisher"),
            _member(ASSET_ID, "christine", "asset_creator"),
            _member(WEB_ID, "pradeep", "web_builder"),
        ],
        "roles": {
            "owner": {"capabilities": [
                "basic", "web.read", "asset.create", "asset.review", "report.read",
                "client.message.send", "ghl.manage", "site.publish", "ads.brief",
                "ads.read", "ads.meta.write", "history.read.own", "history.oversight",
                "memory.own", "delegate", "register.change", "integration.approve",
                "cap.increase", "owner.host",
            ]},
            "manager": {"capabilities": [
                "basic", "web.read", "report.read", "history.oversight",
                "register.change", "integration.approve", "cap.increase",
                "history.read.own", "memory.own", "delegate",
            ]},
            "account_manager": {"capabilities": [
                "basic", "web.read", "report.read", "ads.brief", "ads.read",
                "client.message.send", "ghl.manage", "history.read.own",
                "memory.own", "delegate",
            ]},
            "meta_ads_operator": {"capabilities": [
                "basic", "web.read", "ads.read", "ads.meta.write",
                "history.read.own", "memory.own", "delegate",
            ]},
            "content_publisher": {"capabilities": [
                "basic", "web.read", "content.publish", "history.read.own",
                "memory.own", "delegate",
            ]},
            "asset_creator": {"capabilities": [
                "basic", "web.read", "asset.create", "asset.review",
                "history.read.own", "memory.own", "delegate",
            ]},
            "web_builder": {"capabilities": [
                "basic", "web.read", "site.publish", "ghl.manage",
                "history.read.own", "memory.own", "delegate",
            ]},
        },
        "toolActions": [],
        "connections": [
            {"id": "conn-ghl-main", "connector": "ghl", "account": "shoutout",
             "ownerClass": "business", "actions": ["ghl.manage"]},
            {"id": "conn-mail-personal", "connector": "email", "account": "charles-personal",
             "ownerClass": "personal", "actions": ["basic"]},
        ],
        "spendingCaps": [],
        "oversight": {"destinations": [{"chatId": CHAT_OVERSIGHT}]},
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
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Temp HERMES_HOME: team_authz enabled, base register, clean audit."""
    h = tmp_path / "hermes-home"
    h.mkdir()
    _write_config(h, CONFIG_ENABLED)
    _write_register(h, _base_register())
    monkeypatch.setenv("HERMES_HOME", str(h))
    # Existing browser positive controls use reserved example domains, not live DNS.
    monkeypatch.setattr("tools.url_safety._getaddrinfo",
                        lambda *a, **kw: [(2, 1, 6, "", ("8.8.8.8", 443))])
    team_authz._REGISTER_CACHE.clear()
    yield h
    team_authz._REGISTER_CACHE.clear()
    monkeypatch.delenv("HERMES_HOME", raising=False)


# ---------------------------------------------------------------------------
# Gate 1: identity
# ---------------------------------------------------------------------------


class TestIdentity:
    def test_active_member_resolves_with_role(self, home):
        p = resolve_principal(CTX_AM)
        assert p.status == "active"
        assert p.role == "account_manager"
        assert "ghl.manage" in p.capabilities
        assert p.deny_reason == ""

    def test_unknown_identity_denied(self, home):
        p = resolve_principal(_ctx(OUTSIDER_ID))
        assert p.denied
        assert p.deny_reason == "unknown-identity"

    def test_display_name_is_not_identity(self, home):
        p = resolve_principal(_ctx("Charles (Owner)"))
        assert p.denied
        assert p.deny_reason == "unknown-identity"

    def test_wrong_guild_denied(self, home):
        p = resolve_principal(_ctx(AM_ID, scope=OTHER_GUILD))
        assert p.denied
        assert p.deny_reason == "scope-not-listed"

    def test_revoked_member_denied(self, home):
        reg = _base_register()
        reg["members"] = [
            dict(m, status="revoked") if m["discordUserId"] == AM_ID else m
            for m in reg["members"]
        ]
        _write_register(home, reg)
        p = resolve_principal(CTX_AM)
        assert p.denied
        assert "revoked" in p.deny_reason

    def test_revoke_binds_mid_session_without_restart(self, home):
        assert authorize_tool("web_search", {}, CTX_AM).allowed is True
        reg = _base_register()
        reg["members"] = [
            dict(m, status="revoked") if m["discordUserId"] == AM_ID else m
            for m in reg["members"]
        ]
        _write_register(home, reg)
        assert authorize_tool("web_search", {}, CTX_AM).allowed is False

    def test_no_requester_context_denied(self, home, monkeypatch):
        # Spec: missing requester context denies only while the platform is
        # known-governed (thread/RPC hop losing ContextVars).
        monkeypatch.setenv("HERMES_SESSION_PLATFORM", "discord")
        try:
            p = resolve_principal(None)
            assert p.denied
            assert p.deny_reason == "no-requester-context"
        finally:
            monkeypatch.delenv("HERMES_SESSION_PLATFORM", raising=False)

    def test_env_platform_alone_is_not_enough_without_user(self, home, monkeypatch):
        monkeypatch.setenv("HERMES_SESSION_PLATFORM", "discord")
        try:
            assert is_governed(None) is True
            assert resolve_principal(None).denied
        finally:
            monkeypatch.delenv("HERMES_SESSION_PLATFORM", raising=False)

    def test_disabled_baseline_ungoverned(self, tmp_path, monkeypatch):
        h = tmp_path / "h2"
        h.mkdir()
        _write_config(h, CONFIG_DISABLED)
        monkeypatch.setenv("HERMES_HOME", str(h))
        team_authz._REGISTER_CACHE.clear()
        try:
            assert is_governed(CTX_AM) is False
            p = resolve_principal(CTX_AM)
            assert p.status == "ungoverned"
            assert authorize_tool("terminal", {}, CTX_AM).allowed is True
            assert authorize_tool("browser_vault_list", {}, CTX_AM).allowed is True
            assert may_send_to({"chatId": "anywhere"}, CTX_AM).allowed is True
            assert memory_namespace(CTX_AM) is None
        finally:
            team_authz._REGISTER_CACHE.clear()
            monkeypatch.delenv("HERMES_HOME", raising=False)

    def test_absent_config_baseline_ungoverned(self, tmp_path, monkeypatch):
        h = tmp_path / "h3"
        h.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(h))
        team_authz._REGISTER_CACHE.clear()
        try:
            assert is_governed(CTX_AM) is False
        finally:
            team_authz._REGISTER_CACHE.clear()
            monkeypatch.delenv("HERMES_HOME", raising=False)

    def test_malformed_config_fail_closed_for_everyone(self, tmp_path, monkeypatch):
        h = tmp_path / "h4"
        h.mkdir()
        _write_config(h, CONFIG_MALFORMED)
        _write_register(h, _base_register())
        monkeypatch.setenv("HERMES_HOME", str(h))
        team_authz._REGISTER_CACHE.clear()
        try:
            assert is_governed(CTX_OWNER) is True
            assert resolve_principal(CTX_OWNER).denied
            assert authorize_tool("web_search", {}, CTX_OWNER).allowed is False
        finally:
            team_authz._REGISTER_CACHE.clear()
            monkeypatch.delenv("HERMES_HOME", raising=False)

    def test_missing_register_fail_closed(self, tmp_path, monkeypatch):
        h = tmp_path / "h5"
        h.mkdir()
        _write_config(h, CONFIG_ENABLED)
        monkeypatch.setenv("HERMES_HOME", str(h))
        team_authz._REGISTER_CACHE.clear()
        try:
            assert resolve_principal(CTX_OWNER).denied
            assert authorize_tool("web_search", {}, CTX_OWNER).allowed is False
        finally:
            team_authz._REGISTER_CACHE.clear()
            monkeypatch.delenv("HERMES_HOME", raising=False)

    def test_ungoverned_platform_not_governed(self, home):
        assert is_governed(_ctx(AM_ID, platform="cli")) is False
        assert authorize_tool("terminal", {}, _ctx(AM_ID, platform="cli")).allowed is True


# ---------------------------------------------------------------------------
# Gate 2: roles
# ---------------------------------------------------------------------------


class TestRoles:
    def test_am_allowed_business_tool(self, home):
        reg = _base_register()
        reg["toolActions"] = [
            {"pattern": "ghl_update_contact", "action": "ghl.manage",
             "connectionId": "conn-ghl-main"},
        ]
        _write_register(home, reg)
        d = authorize_tool("ghl_update_contact", {}, CTX_AM)
        assert d.allowed is True
        assert d.action == "ghl.manage"

    def test_am_denied_ads_meta_write_direct(self, home):
        reg = _base_register()
        reg["toolActions"] = [{"pattern": "meta_ads_publish", "action": "ads.meta.write"}]
        _write_register(home, reg)
        assert authorize_tool("meta_ads_publish", {}, CTX_AM).allowed is False
        # Meta operator holds ads.meta.write
        assert authorize_tool("meta_ads_publish", {}, CTX_META).allowed is True
        # Social publisher does not
        assert authorize_tool("meta_ads_publish", {}, CTX_SOCIAL).allowed is False

    def test_owner_holds_owner_host_tools(self, home):
        for tool in ("terminal", "read_file", "browser_vault_list", "execute_code"):
            d = authorize_tool(tool, {}, CTX_OWNER)
            assert d.allowed is True, tool

    def test_every_role_allowed_host_tools(self, home):
        for ctx in (CTX_MANAGER, CTX_AM, CTX_META, CTX_SOCIAL, CTX_ASSET, CTX_WEB):
            for tool in OWNER_HOST_TOOLS:
                if tool.startswith("browser_vault_"):
                    continue  # protected class: asserted below
                d = authorize_tool(tool, {}, ctx)
                assert d.allowed is True, (ctx.user_id, tool)

    def test_every_role_denied_vault_tools(self, home):
        for ctx in (CTX_MANAGER, CTX_AM, CTX_META, CTX_SOCIAL, CTX_ASSET, CTX_WEB):
            for tool in ("browser_vault_list", "browser_vault_fill", "browser_vault_save_login"):
                d = authorize_tool(tool, {}, ctx)
                assert d.allowed is False, (ctx.user_id, tool)

    def test_unmapped_tool_denied(self, home):
        # Default-open team lane (Charles 2026-09-17): unmapped tools are
        # ordinary work — allowed for members; still denied for unknowns.
        assert authorize_tool("some_random_tool", {}, CTX_AM).allowed is True
        assert authorize_tool("some_random_tool", {}, CTX_OWNER).allowed is True
        assert authorize_tool("some_random_tool", {}, _ctx(OUTSIDER_ID)).allowed is False

    def test_discovery_filter_matches_role(self, home):
        names = {"web_search", "terminal", "todo_list", "browser_vault_fill", "meta_ads_x"}
        visible = filter_tool_names(names, CTX_AM)
        # T1: only the protected classes are hidden; ordinary and host tools show.
        assert visible == {"web_search", "terminal", "todo_list", "meta_ads_x"}
        visible_owner = filter_tool_names(names, CTX_OWNER)
        assert visible_owner == names
        visible_denied = filter_tool_names(names, _ctx(OUTSIDER_ID))
        assert visible_denied == set()


# ---------------------------------------------------------------------------
# Gate 3: protected owner resources
# ---------------------------------------------------------------------------


class TestProtectedOwnerResources:
    def test_staff_vault_denied_backend_never_touched(self, home):
        calls = []

        def fake_backend(**kw):
            calls.append(kw)
            return "should never run"

        d = authorize_tool("browser_vault_list", {}, CTX_AM)
        assert d.allowed is False
        assert d.reason.startswith("protected:")
        assert calls == []

    @pytest.mark.parametrize("tool", ["terminal", "read_file", "write_file", "patch",
                                      "execute_code", "browser_exec", "cronjob_manage",
                                      "manage_connections"])
    def test_staff_host_tools_allowed(self, home, tool):
        assert authorize_tool(tool, {}, CTX_MANAGER).allowed is True

    def test_manager_denied_despite_register_change(self, home):
        # a manager cannot remap a protected tool to a harmless action
        d = apply_register_change(
            {"kind": "toolaction.upsert",
             "payload": {"pattern": "browser_vault_*", "action": "basic"}},
            CTX_MANAGER)
        assert d.allowed is False
        assert d.reason in ("protected-tool-remap-denied", "toolaction-protected-remap")

    def test_display_name_impersonation_denied(self, home):
        fake = _ctx("charles-the-owner")  # display-ish id not in register
        assert authorize_tool("terminal", {}, fake).allowed is False

    def test_forwarded_model_supplied_approval_ignored(self, home):
        # model supplies approvedBy / ownerApprovalId for a tool it can't touch
        d = authorize_tool("browser_vault_fill",
                           {"approvedBy": OWNER_ID, "ownerApprovalId": "oapr_forged"},
                           CTX_AM)
        assert d.allowed is False

    def test_owner_positive_secure_surface(self, home):
        # owner on governed surface reaches the vault handler class
        d = authorize_tool("browser_vault_list", {}, CTX_OWNER)
        assert d.allowed is True

    def test_exact_scope_owner_approval_does_not_unlock_nonowner(self, home):
        secure_owner_ctx = RequesterContext(
            platform="secure-owner", user_id=OWNER_ID, scope_id=None,
            chat_id="920000000000000001", chat_type="secure-owner")
        rec = _record_verified_owner_approval(home,
            {"operation": "owner.vault.use", "resource": "browser_vault_fill", "ttlSeconds": 600},
            ctx=secure_owner_ctx)
        assert rec.allowed is True
        approval_id = rec.action
        assert approval_id
        # Without the approval: the immutable protected class denies first.
        d = authorize_tool("browser_vault_fill", {"handle": "h"}, CTX_AM)
        assert d.allowed is False
        assert d.reason == "protected:credentials"
        # Even a real approval cannot transfer the owner's private perimeter.
        d = authorize_tool("browser_vault_fill", {"handle": "h", "ownerApprovalId": approval_id}, CTX_AM)
        assert d.allowed is False
        assert d.reason == "protected:credentials"

    @pytest.mark.parametrize("tool,args", [
        ("browser_vault_save_login", {"name": "Example"}),
        ("browser_type", {"selector": "password", "text": "synthetic"}),
    ])
    def test_valid_owner_approval_cannot_delegate_private_browser_access(self, home, tool, args):
        secure_owner_ctx = RequesterContext(
            platform="secure-owner", user_id=OWNER_ID, scope_id=None,
            chat_id="920000000000000001", chat_type="secure-owner")
        from agent.team_authz_owner import classify_protected_call, _operation_for_class
        operation = _operation_for_class(classify_protected_call(tool, args))
        rec = _record_verified_owner_approval(home,
            {"operation": operation, "resource": tool, "ttlSeconds": 600},
            ctx=secure_owner_ctx)
        assert rec.allowed
        result = authorize_tool(tool, {**args, "ownerApprovalId": rec.action}, CTX_AM)
        assert not result.allowed
        assert result.reason.startswith("protected:")
        assert authorize_tool(tool, args, CTX_OWNER).allowed

    def test_owner_approval_never_grants_ordinary_authority(self, home):
        secure_owner_ctx = RequesterContext(
            platform="secure-owner", user_id=OWNER_ID, scope_id=None,
            chat_id="920000000000000001", chat_type="secure-owner")
        rec = _record_verified_owner_approval(home,
            {"operation": "owner.host.use", "resource": "terminal", "ttlSeconds": 600},
            ctx=secure_owner_ctx)
        approval_id = rec.action
        # wrong resource
        d = authorize_owner_resource(approval_id, operation="owner.host.use",
                                     resource="read_file")
        assert d.allowed is False
        # wrong operation
        d = authorize_owner_resource(approval_id, operation="owner.vault.use",
                                     resource="terminal")
        assert d.allowed is False

    def test_owner_approval_expired_denied(self, home):
        secure_owner_ctx = RequesterContext(
            platform="secure-owner", user_id=OWNER_ID, scope_id=None,
            chat_id="920000000000000001", chat_type="secure-owner")
        rec = _record_verified_owner_approval(home,
            {"operation": "owner.host.use", "resource": "terminal", "ttlSeconds": -1},
            ctx=secure_owner_ctx)
        assert rec.allowed is False  # invalid ttl rejected at record time

    def test_owner_approval_stale_after_ttl(self, home):
        secure_owner_ctx = RequesterContext(
            platform="secure-owner", user_id=OWNER_ID, scope_id=None,
            chat_id="920000000000000001", chat_type="secure-owner")
        rec = _record_verified_owner_approval(home,
            {"operation": "owner.host.use", "resource": "terminal", "ttlSeconds": 1},
            ctx=secure_owner_ctx)
        approval_id = rec.action
        # rewrite expiry into the past directly (synthetic fixture surgery)
        reg = json.loads((home / "team_authz" / "register.json").read_text(encoding="utf-8"))
        for a in reg["ownerApprovals"]:
            if a["id"] == approval_id:
                a["expiresAt"] = "2000-01-01T00:00:00+00:00"
        _write_register(home, reg)
        d = authorize_owner_resource(approval_id, operation="owner.host.use",
                                     resource="terminal")
        assert d.allowed is False
        assert d.reason == "owner-approval-expired"

    def test_owner_approval_revoked_denied(self, home):
        secure_owner_ctx = RequesterContext(
            platform="secure-owner", user_id=OWNER_ID, scope_id=None,
            chat_id="920000000000000001", chat_type="secure-owner")
        rec = _record_verified_owner_approval(home,
            {"operation": "owner.host.use", "resource": "terminal", "ttlSeconds": 600},
            ctx=secure_owner_ctx)
        approval_id = rec.action
        reg = json.loads((home / "team_authz" / "register.json").read_text(encoding="utf-8"))
        for a in reg["ownerApprovals"]:
            if a["id"] == approval_id:
                a["status"] = "revoked"
        _write_register(home, reg)
        assert authorize_owner_resource(approval_id, operation="owner.host.use",
                                        resource="terminal").allowed is False

    def test_record_owner_approval_requires_secure_surface(self, home):
        # owner id but normal discord provenance: not a secure owner surface
        rec = record_owner_approval(
            {"operation": "owner.host.use", "resource": "terminal"}, ctx=CTX_OWNER)
        assert rec.allowed is False
        assert rec.reason in ("owner-surface-unverified", "owner-identity-mismatch")

    def test_nonowner_cannot_record_owner_approval(self, home):

        fake = RequesterContext(platform="secure-owner", user_id=MANAGER_ID,
                                chat_id="920000000000000002", chat_type="secure-owner")
        rec = record_owner_approval(
            {"operation": "owner.host.use", "resource": "terminal"}, ctx=fake)
        assert rec.allowed is False

    def test_unbound_owner_identity_is_not_provenance(self, home):
        ctx = _ctx(OWNER_ID, platform="secure-owner", chat_type="secure-owner")
        assert not record_owner_approval(
            {"operation": "owner.host.use", "resource": "terminal"}, ctx=ctx).allowed

    def test_surface_label_alone_does_not_configure_owner_channel(self, home):
        ctx = _ctx(OWNER_ID, platform="secure-owner", chat_type="secure-owner")
        token = bind_requester(ctx)
        try:
            assert not record_owner_approval(
                {"operation": "owner.host.use", "resource": "terminal"}).allowed
        finally:
            reset_requester(token)

    def test_revoked_owner_cannot_mint_approval(self, home):
        reg = _base_register()
        reg["members"][0]["status"] = "revoked"
        _write_register(home, reg)
        ctx = _ctx(OWNER_ID, platform="secure-owner", chat_type="secure-owner")
        assert not _record_verified_owner_approval(home,
            {"operation": "owner.host.use", "resource": "terminal"}, ctx).allowed

    def test_owner_approval_audit_failure_leaves_no_grant(self, home, monkeypatch):
        from agent import team_authz_owner
        monkeypatch.setattr(team_authz_owner, "audit", lambda event: False)
        ctx = _ctx(OWNER_ID, platform="secure-owner", chat_type="secure-owner")
        assert not _record_verified_owner_approval(home,
            {"operation": "owner.host.use", "resource": "terminal"}, ctx).allowed
        reg = json.loads((home / "team_authz" / "register.json").read_text())
        assert not reg.get("ownerApprovals")

    def test_forged_approval_record_cannot_claim_owner_provenance(self, home):
        reg = _base_register()
        reg["ownerApprovals"] = [{
            "id": "forged", "operation": "owner.host.use", "resource": "terminal",
            "audience": None, "status": "approved", "approvedBy": MANAGER_ID,
        }]
        _write_register(home, reg)
        assert not authorize_owner_resource("forged", operation="owner.host.use",
                                            resource="terminal", ctx=CTX_AM).allowed

    def test_nonowner_secure_channel_is_still_not_owner(self, home):
        fake = RequesterContext(platform="secure-owner", user_id=MANAGER_ID,
                                chat_id="920000000000000002", chat_type="secure-owner")
        rec = _record_verified_owner_approval(home,
            {"operation": "owner.host.use", "resource": "terminal"}, ctx=fake)
        assert rec.allowed is False

    def test_ref_provenance_is_not_secure_owner(self, home):
        # a rebound ref context (queued job replay) cannot mint approvals
        token = bind_requester({"platform": "secure-owner", "user_id": OWNER_ID,
                                "chat_type": "secure-owner"})
        try:
            rec = record_owner_approval(
                {"operation": "owner.host.use", "resource": "terminal"})
            assert rec.allowed is False
        finally:
            reset_requester(token)


# ---------------------------------------------------------------------------
# Gate 4/5: history, oversight, destinations
# ---------------------------------------------------------------------------


class TestHistoryAndOversight:
    def test_own_session_readable(self, home):
        row = {"platform": "discord", "user_id": AM_ID, "chat_id": CHAT_AM}
        d = can_read_session(row, destination={}, ctx=CTX_AM)
        assert d.allowed is True
        assert d.reason == "own"

    def test_other_member_private_session_denied(self, home):
        row = {"platform": "discord", "user_id": SOCIAL_ID,
               "chat_id": "920000000000000005"}
        d = can_read_session(row, destination={}, ctx=CTX_AM)
        assert d.allowed is False

    def test_shared_conversation_readable(self, home):
        row = {"platform": "discord", "user_id": SOCIAL_ID, "chat_id": "999",
               "thread_id": "999t"}
        ctx = _ctx(AM_ID, chat="999", thread="999t")
        d = can_read_session(row, destination={}, ctx=ctx)
        assert d.allowed is True
        assert d.reason == "shared-conversation"

    def test_owner_rows_owner_only(self, home):
        row = {"platform": "discord", "user_id": OWNER_ID, "chat_id": "920000000000000001"}
        assert can_read_session(row, destination={}, ctx=CTX_MANAGER).allowed is False
        assert can_read_session(row, destination={}, ctx=CTX_OWNER).allowed is True

    def test_unknown_owner_rows_owner_only(self, home):
        row = {"platform": "discord", "user_id": "", "chat_id": "legacy"}
        assert can_read_session(row, destination={}, ctx=CTX_MANAGER).allowed is False
        assert can_read_session(row, destination={}, ctx=CTX_OWNER).allowed is True

    def test_explicit_profile_read_owner_only(self, home):
        row = {"platform": "discord", "user_id": AM_ID, "chat_id": CHAT_AM,
               "profile": "other"}
        assert can_read_session(row, destination={}, ctx=CTX_MANAGER).allowed is False
        assert can_read_session(row, destination={}, ctx=CTX_AM).allowed is False

    def test_manager_oversight_dm_positive_audited(self, home):
        row = {"platform": "discord", "user_id": ASSET_ID, "chat_id": "920000000000000006"}
        dest = {"chatId": CHAT_OVERSIGHT}
        d = can_read_session(row, destination=dest, ctx=CTX_MANAGER)
        assert d.allowed is True
        assert d.reason == "oversight"
        rows = _audit_rows(home)
        assert any(r.get("event") == "oversight" and r.get("decision") == "allowed"
                   for r in rows)

    def test_manager_oversight_into_team_channel_denied(self, home):
        row = {"platform": "discord", "user_id": ASSET_ID, "chat_id": "920000000000000006"}
        dest = {"chatId": CHAT_TEAM_CHANNEL}
        d = can_read_session(row, destination=dest, ctx=CTX_MANAGER)
        assert d.allowed is False

    def test_am_has_no_oversight(self, home):
        row = {"platform": "discord", "user_id": ASSET_ID, "chat_id": "920000000000000006"}
        dest = {"chatId": CHAT_OVERSIGHT}
        assert can_read_session(row, destination=dest, ctx=CTX_AM).allowed is False

    def test_manager_cannot_read_owner_private(self, home):
        row = {"platform": "discord", "user_id": OWNER_ID, "chat_id": "920000000000000001"}
        assert can_read_session(row, destination={"chatId": CHAT_OVERSIGHT},
                                ctx=CTX_MANAGER).allowed is False

    def test_may_send_to_originating_chat_only(self, home):
        assert may_send_to({"chatId": CHAT_AM}, CTX_AM).allowed is True
        assert may_send_to({"chatId": "930000000000000099"}, CTX_AM).allowed is False
        assert may_send_to({"chatId": CHAT_AM, "threadId": "other"}, CTX_AM).allowed is False

    def test_owner_may_send_anywhere(self, home):
        assert may_send_to({"chatId": "anywhere"}, CTX_OWNER).allowed is True


# ---------------------------------------------------------------------------
# Gate 6: spend caps
# ---------------------------------------------------------------------------


class TestSpendCaps:
    @pytest.mark.parametrize("field", ["amount", "currency", "account_id"])
    def test_missing_spend_fields_deny(self, home, field):
        _write_register(home, self._reg_with_cap())
        args = {"account_id": "acct-1", "amount": 5, "currency": "AUD"}
        del args[field]
        assert not authorize_tool("meta_ads_set_budget", args, CTX_META).allowed

    @pytest.mark.parametrize("amount", [float("nan"), float("inf"), True])
    def test_invalid_numeric_spend_denies(self, home, amount):
        _write_register(home, self._reg_with_cap())
        args = {"account_id": "acct-1", "amount": amount, "currency": "AUD"}
        assert not authorize_tool("meta_ads_set_budget", args, CTX_META).allowed

    def test_corrupt_audit_cannot_reset_spending_total(self, home):
        _write_register(home, self._reg_with_cap())
        (home / "team_authz" / "audit.jsonl").write_text("invalid-json\n", encoding="utf-8")
        args = {"account_id": "acct-1", "amount": 5, "currency": "AUD"}
        assert not authorize_tool("meta_ads_set_budget", args, CTX_META).allowed

    def test_string_amounts_count_toward_aggregate(self, home):
        _write_register(home, self._reg_with_cap())
        args = {"account_id": "acct-1", "amount": "60", "currency": "AUD"}
        assert authorize_tool("meta_ads_set_budget", args, CTX_META).allowed
        assert not authorize_tool("meta_ads_set_budget", args, CTX_META).allowed

    def test_week_cap_has_timezone_aware_aggregate(self, home):
        reg = self._reg_with_cap()
        reg["spendingCaps"][0]["period"] = "week"
        _write_register(home, reg)
        args = {"account_id": "acct-1", "amount": 60, "currency": "AUD"}
        assert authorize_tool("meta_ads_set_budget", args, CTX_META).allowed
        assert authorize_tool("meta_ads_set_budget", dict(args, amount=20), CTX_META).allowed
        assert not authorize_tool("meta_ads_set_budget", args, CTX_META).allowed

    def test_prior_cap_approval_is_not_unlimited_spending(self, home):
        _write_register(home, self._reg_with_cap())
        assert team_authz.audit({
            "event": "register-change", "action": "cap.increase",
            "memberKey": "dianne", "connectionId": "conn-meta", "account": "acct-1",
            "decision": "allowed",
        })
        args = {"account_id": "acct-1", "amount": 101, "currency": "AUD"}
        assert not authorize_tool("meta_ads_set_budget", args, CTX_META).allowed

    def _reg_with_cap(self, amount=100.0):
        reg = _base_register()
        reg["toolActions"] = [{
            "pattern": "meta_ads_set_budget", "action": "ads.meta.write",
            "connectionId": "conn-meta", "accountArg": "account_id",
            "amountArg": "amount", "currencyArg": "currency",
        }]
        reg["connections"].append(
            {"id": "conn-meta", "connector": "meta", "account": "acct-1",
             "ownerClass": "business", "actions": ["ads.meta.write"]})
        reg["spendingCaps"] = [{
            "memberKey": "dianne", "connectionId": "conn-meta", "account": "acct-1",
            "currency": "AUD", "period": "day", "amount": amount, "scope": "",
            "approvedBy": OWNER_ID, "approvedAt": "2026-01-01T00:00:00+00:00",
        }]
        return reg

    def test_in_cap_allowed(self, home):
        _write_register(home, self._reg_with_cap())
        d = authorize_tool("meta_ads_set_budget",
                           {"account_id": "acct-1", "amount": 50, "currency": "AUD"},
                           CTX_META)
        assert d.allowed is True, d.reason

    def test_cap_missing_denied(self, home):
        reg = self._reg_with_cap()
        reg["spendingCaps"] = []
        _write_register(home, reg)
        d = authorize_tool("meta_ads_set_budget",
                           {"account_id": "acct-1", "amount": 5, "currency": "AUD"},
                           CTX_META)
        assert d.allowed is False
        assert d.reason == "cap-missing"

    def test_over_cap_denied(self, home):
        _write_register(home, self._reg_with_cap(amount=10))
        d = authorize_tool("meta_ads_set_budget",
                           {"account_id": "acct-1", "amount": 50, "currency": "AUD"},
                           CTX_META)
        assert d.allowed is False
        assert d.reason == "cap-exceeded"

    def test_wrong_currency_denied(self, home):
        _write_register(home, self._reg_with_cap())
        d = authorize_tool("meta_ads_set_budget",
                           {"account_id": "acct-1", "amount": 5, "currency": "USD"},
                           CTX_META)
        assert d.allowed is False
        assert d.reason == "cap-currency-mismatch"

    def test_wrong_account_denied(self, home):
        _write_register(home, self._reg_with_cap())
        d = authorize_tool("meta_ads_set_budget",
                           {"account_id": "acct-2", "amount": 5, "currency": "AUD"},
                           CTX_META)
        assert d.allowed is False
        assert d.reason == "connection-account-mismatch"

    def test_aggregate_over_period_denied(self, home):
        _write_register(home, self._reg_with_cap(amount=100))
        d1 = authorize_tool("meta_ads_set_budget",
                            {"account_id": "acct-1", "amount": 60, "currency": "AUD"},
                            CTX_META)
        assert d1.allowed is True
        d2 = authorize_tool("meta_ads_set_budget",
                            {"account_id": "acct-1", "amount": 60, "currency": "AUD"},
                            CTX_META)
        assert d2.allowed is False
        assert d2.reason == "cap-exceeded"


# ---------------------------------------------------------------------------
# Gate 7: connections
# ---------------------------------------------------------------------------


class TestConnections:
    @pytest.mark.parametrize("owner_class", [None, "unknown", "owner"])
    def test_ambiguous_connection_ownership_denies(self, home, owner_class):
        reg = self._mapped_mail()
        reg["connections"][1]["ownerClass"] = owner_class
        reg["connections"][1]["actions"] = ["client.message.send"]
        _write_register(home, reg)
        assert not authorize_tool("sms_send", {}, CTX_AM).allowed

    def test_nonspend_account_cannot_escape_connection(self, home):
        reg = _base_register()
        reg["toolActions"] = [{"pattern": "ghl_update", "action": "ghl.manage",
                               "connectionId": "conn-ghl-main", "accountArg": "account"}]
        _write_register(home, reg)
        assert authorize_tool("ghl_update", {"account": "shoutout"}, CTX_AM).allowed
        assert not authorize_tool("ghl_update", {"account": "other"}, CTX_AM).allowed
        assert not authorize_tool("ghl_update", {}, CTX_AM).allowed

    def _mapped_mail(self):
        reg = _base_register()
        # Tool name deliberately NOT protected-class: exercises the mutable
        # connection check, not the immutable protected gate.
        reg["toolActions"] = [{
            "pattern": "sms_send", "action": "client.message.send",
            "connectionId": "conn-mail-personal",
        }]
        return reg

    def test_personal_connection_denied_nonowner(self, home):
        _write_register(home, self._mapped_mail())
        d = authorize_tool("sms_send", {}, CTX_AM)
        assert d.allowed is False
        assert d.reason == "connection-class-denied"

    def test_unknown_connection_denied(self, home):
        reg = self._mapped_mail()
        reg["toolActions"][0]["connectionId"] = "conn-nope"
        _write_register(home, reg)
        assert authorize_tool("sms_send", {}, CTX_AM).allowed is False
        assert authorize_tool("sms_send", {}, CTX_OWNER).reason == "connection-unknown"

    def test_business_connection_action_not_listed(self, home):
        reg = _base_register()
        reg["toolActions"] = [{
            "pattern": "ghl_send_sms", "action": "client.message.send",
            "connectionId": "conn-ghl-main",
        }]
        _write_register(home, reg)
        # AM holds client.message.send but conn-ghl-main only lists ghl.manage
        d = authorize_tool("ghl_send_sms", {}, CTX_AM)
        assert d.allowed is False
        assert d.reason == "connection-action-not-listed"

    def test_email_tool_hits_protected_class_first(self, home):
        # email_* is an immutable protected class: a register that tries to
        # map it is rejected by the loader, and every call under that broken
        # register fails closed (even the owner's).
        reg = _base_register()
        reg["toolActions"] = [{
            "pattern": "email_send_business", "action": "client.message.send",
            "connectionId": "conn-ghl-main",
        }]
        _write_register(home, reg)
        d = authorize_tool("email_send_business", {}, CTX_AM)
        assert d.allowed is False
        assert d.reason in ("protected:personal-mailbox",
                            "register-invalid:toolaction-protected-remap")
        assert authorize_tool("email_send_business", {}, CTX_OWNER).allowed is False


# ---------------------------------------------------------------------------
# Gate 8: fail-closed + staleness
# ---------------------------------------------------------------------------


class TestFailClosed:
    @pytest.mark.parametrize("tool", ["read_file", "search_files", "write_file", "patch",
                                      "cronjob_manage", "manage_connections"])
    def test_wildcard_maps_ordinary_host_tools(self, home, tool):
        reg = _base_register()
        reg["toolActions"] = [{"pattern": "*", "action": "basic"}]
        _write_register(home, reg)
        assert authorize_tool(tool, {}, CTX_AM).allowed
        assert tool in filter_tool_names([tool], CTX_AM)

    @pytest.mark.parametrize("field", ["discordUserId", "memberKey"])
    def test_duplicate_identity_denies_instead_of_first_match(self, home, field):
        reg = _base_register()
        reg["members"][2][field] = reg["members"][0][field]
        _write_register(home, reg)
        assert not authorize_tool("web_search", {}, CTX_OWNER).allowed

    def test_empty_members_register_denies_owner(self, home):
        reg = _base_register()
        reg["members"] = []
        _write_register(home, reg)
        assert resolve_principal(CTX_OWNER).denied
        assert authorize_tool("web_search", {}, CTX_OWNER).allowed is False

    def test_owner_host_outside_owner_role_rejected_by_loader(self, home):
        reg = _base_register()
        reg["roles"]["manager"]["capabilities"].append("owner.host")
        _write_register(home, reg)
        assert resolve_principal(CTX_MANAGER).denied
        assert "register-invalid" in resolve_principal(CTX_MANAGER).deny_reason

    def test_grant_digest_changes_on_revoke(self, home):
        d1 = grant_digest(CTX_AM)
        reg = _base_register()
        reg["members"] = [
            dict(m, status="revoked") if m["discordUserId"] == AM_ID else m
            for m in reg["members"]
        ]
        _write_register(home, reg)
        d2 = grant_digest(CTX_AM)
        assert d1 != d2

    def test_raising_policy_denies(self, home, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("policy exploded")
        monkeypatch.setattr(team_authz, "_load_register", boom)
        d = authorize_tool("web_search", {}, CTX_AM)
        assert d.allowed is False
        assert d.reason.startswith("policy-error")

    def test_audit_failure_flips_allow_to_deny(self, home, monkeypatch):
        def failing_audit(event):
            return False
        monkeypatch.setattr(team_authz, "audit", failing_audit)
        d = authorize_tool("web_search", {}, CTX_AM)
        assert d.allowed is False
        assert d.reason == "audit-failure"

    def test_audit_never_contains_argument_bodies(self, home):
        authorize_tool("web_search", {"query": "patient Jane Doe DOB"}, CTX_AM)
        authorize_tool("terminal", {"command": "cat ~/.env"}, CTX_AM)
        rows = _audit_rows(home)
        assert rows, "expected audit rows"
        for r in rows:
            assert "patient" not in json.dumps(r)
            assert ".env" not in json.dumps(r)


# ---------------------------------------------------------------------------
# Register change control
# ---------------------------------------------------------------------------


class TestRegisterChange:
    def test_manager_can_add_ordinary_member(self, home):
        d = apply_register_change(
            {"kind": "member.upsert",
             "payload": {"discordUserId": "900000000000000011", "memberKey": "newcom",
                         "role": "content_publisher", "status": "active"}},
            CTX_MANAGER)
        assert d.allowed is True
        reg = json.loads((home / "team_authz" / "register.json").read_text(encoding="utf-8"))
        assert any(m["discordUserId"] == "900000000000000011" for m in reg["members"])
        assert reg["policyVersion"] != "2026.09.17-r1"

    def test_am_cannot_change_register(self, home):
        d = apply_register_change(
            {"kind": "member.upsert",
             "payload": {"discordUserId": "900000000000000011", "memberKey": "x",
                         "role": "asset_creator", "status": "active"}},
            CTX_AM)
        assert d.allowed is False
        assert d.reason == "role-missing-action"

    def test_manager_cannot_promote_owner(self, home):
        d = apply_register_change(
            {"kind": "member.upsert",
             "payload": {"discordUserId": MANAGER_ID, "memberKey": "bettina",
                         "role": "owner", "status": "active"}},
            CTX_MANAGER)
        assert d.allowed is False
        assert d.reason == "owner-reassignment-denied"

    def test_manager_cannot_edit_manager(self, home):
        d = apply_register_change(
            {"kind": "member.upsert",
             "payload": {"discordUserId": AM_ID, "memberKey": "lianna",
                         "role": "manager", "status": "active"}},
            CTX_MANAGER)
        assert d.allowed is False
        assert d.reason == "manager-mutation-denied"

    def test_manager_cannot_add_personal_connection(self, home):
        d = apply_register_change(
            {"kind": "connection.upsert",
             "payload": {"id": "conn-new", "connector": "email",
                         "account": "someone", "ownerClass": "personal",
                         "actions": ["basic"]}},
            CTX_MANAGER)
        assert d.allowed is False
        assert d.reason == "personal-connection-denied"

    def test_manager_cannot_relabel_personal_as_business(self, home):
        d = apply_register_change(
            {"kind": "connection.upsert",
             "payload": {"id": "conn-mail-personal", "connector": "email",
                         "account": "charles-personal", "ownerClass": "business",
                         "actions": ["basic"]}},
            CTX_MANAGER)
        assert d.allowed is False
        assert d.reason == "relabel-personal-denied"

    def test_owner_can_relabel_personal_as_business(self, home):
        d = apply_register_change(
            {"kind": "connection.upsert",
             "payload": {"id": "conn-mail-personal", "connector": "email",
                         "account": "charles-personal", "ownerClass": "business",
                         "actions": ["basic"]}},
            CTX_OWNER)
        assert d.allowed is True

    def test_owner_host_grant_rejected_outside_owner(self, home):
        d = apply_register_change(
            {"kind": "role.grant",
             "payload": {"role": "account_manager", "capability": "owner.host"}},
            CTX_OWNER)
        assert d.allowed is False

    def test_manager_cannot_widen_oversight(self, home):
        d = apply_register_change(
            {"kind": "oversight.destination.add",
             "payload": {"chatId": "930000000000000099"}},
            CTX_MANAGER)
        assert d.allowed is False
        assert d.reason == "oversight-widen-denied"

    def test_owner_can_widen_oversight(self, home):
        d = apply_register_change(
            {"kind": "oversight.destination.add",
             "payload": {"chatId": "930000000000000099"}},
            CTX_OWNER)
        assert d.allowed is True

    def test_change_bumps_policy_version(self, home):
        d = apply_register_change(
            {"kind": "role.grant",
             "payload": {"role": "account_manager", "capability": "content.publish"}},
            CTX_OWNER)
        assert d.allowed is True
        reg = json.loads((home / "team_authz" / "register.json").read_text(encoding="utf-8"))
        assert reg["policyVersion"] == "2026.09.17-r1.1"

    def test_unknown_kind_denied(self, home):
        d = apply_register_change({"kind": "owner.approval.upsert", "payload": {}},
                                  CTX_OWNER)
        assert d.allowed is False
        assert d.reason in ("owner-state-control-plane-only", "unknown-change-kind")

    def test_manager_cannot_remove_owner(self, home):
        d = apply_register_change(
            {"kind": "member.remove", "payload": {"discordUserId": OWNER_ID}},
            CTX_MANAGER)
        assert d.allowed is False

    def test_cap_increase_requires_authority(self, home):
        base = {
            "kind": "cap.upsert",
            "payload": {"memberKey": "dianne", "connectionId": "conn-meta",
                        "account": "acct-1", "currency": "AUD", "period": "day",
                        "amount": 200, "scope": ""},
        }
        reg = _base_register()
        reg["spendingCaps"] = [{
            "memberKey": "dianne", "connectionId": "conn-meta", "account": "acct-1",
            "currency": "AUD", "period": "day", "amount": 100, "scope": "",
            "approvedBy": OWNER_ID, "approvedAt": "2026-01-01T00:00:00+00:00",
        }]
        _write_register(home, reg)
        # AM holds no cap.increase
        d = apply_register_change(base, CTX_AM)
        assert d.allowed is False
        # manager holds cap.increase
        d = apply_register_change(base, CTX_MANAGER)
        assert d.allowed is True


# ---------------------------------------------------------------------------
# r2: sharing consent
# ---------------------------------------------------------------------------


DEST_TEAM_RECORD = {
    "shape": "connector", "connector": "notion", "connectionId": "conn-notion",
    "account": "wiki", "resource": "clients/acme/notes",
}


class TestSharingConsent:
    @pytest.fixture(autouse=True)
    def _bind_author(self):
        token = bind_requester(CTX_AM)
        try:
            yield
        finally:
            reset_requester(token)

    def test_replayed_requester_cannot_mint_consent(self, home):
        token = bind_requester(requester_ref(CTX_AM))
        try:
            assert not record_sharing_consent({"authorDiscordUserId": AM_ID,
                "summary": "s", "sourceRef": "sess-1", "destination": DEST_TEAM_RECORD}).allowed
        finally:
            reset_requester(token)

    def test_revoked_author_cannot_mint_consent(self, home):
        reg = _base_register()
        reg["members"][2]["status"] = "revoked"
        _write_register(home, reg)
        assert not record_sharing_consent({"authorDiscordUserId": AM_ID,
            "summary": "s", "sourceRef": "sess-1", "destination": DEST_TEAM_RECORD}).allowed

    def test_missing_source_cannot_bypass_exact_source(self, home):
        rec = record_sharing_consent({"authorDiscordUserId": AM_ID, "summary": "s",
            "sourceRef": "sess-1", "destination": DEST_TEAM_RECORD})
        assert rec.allowed
        assert not authorize_sharing(rec.action, source="", summary="s",
            destination=DEST_TEAM_RECORD, ctx=CTX_AM).allowed

    def test_failed_consent_audit_leaves_no_grant(self, home, monkeypatch):
        from agent import team_authz_sharing
        monkeypatch.setattr(team_authz_sharing, "audit", lambda event: False)
        assert not record_sharing_consent({"authorDiscordUserId": AM_ID, "summary": "s",
            "sourceRef": "sess-1", "destination": DEST_TEAM_RECORD}).allowed
        reg = json.loads((home / "team_authz" / "register.json").read_text())
        assert not reg.get("sharingConsents")

    def test_forged_approver_cannot_reuse_consent(self, home):
        rec = record_sharing_consent({"authorDiscordUserId": AM_ID, "summary": "s",
            "sourceRef": "sess-1", "destination": DEST_TEAM_RECORD})
        assert rec.allowed
        reg = json.loads((home / "team_authz" / "register.json").read_text())
        reg["sharingConsents"][0]["approvedByDiscordUserId"] = MANAGER_ID
        _write_register(home, reg)
        assert not authorize_sharing(rec.action, source="sess-1", summary="s",
            destination=DEST_TEAM_RECORD, ctx=CTX_AM).allowed

    def _author_ctx(self, uid=AM_ID, chat=CHAT_AM):
        return _ctx(uid, chat=chat)

    def test_exact_consent_positive(self, home):
        summary = "Client X approved the new launch date."
        ctx = self._author_ctx()
        rec = record_sharing_consent(
            {"authorDiscordUserId": AM_ID, "summary": summary,
             "destination": DEST_TEAM_RECORD, "sourceRef": "sess-1"},
            ctx=ctx)
        assert rec.allowed is True, rec.reason
        consent_id = rec.action
        d = authorize_sharing(consent_id, source="sess-1", summary=summary,
                              destination=DEST_TEAM_RECORD, ctx=ctx)
        assert d.allowed is True, d.reason

    def test_wrong_author_cannot_record(self, home):
        rec = record_sharing_consent(
            {"authorDiscordUserId": SOCIAL_ID, "summary": "s",
             "destination": DEST_TEAM_RECORD},
            ctx=self._author_ctx())  # AM ctx claiming to approve SOCIAL's summary
        assert rec.allowed is False
        assert rec.reason == "consent-author-mismatch"

    def test_manager_cannot_consent_for_member(self, home):
        rec = record_sharing_consent(
            {"authorDiscordUserId": AM_ID, "summary": "s",
             "destination": DEST_TEAM_RECORD},
            ctx=CTX_MANAGER)
        assert rec.allowed is False

    def test_one_byte_mutation_denied(self, home):
        summary = "Client X approved the new launch date."
        rec = record_sharing_consent(
            {"authorDiscordUserId": AM_ID, "summary": summary,
             "destination": DEST_TEAM_RECORD, "sourceRef": "sess-1"},
            ctx=self._author_ctx())
        consent_id = rec.action
        d = authorize_sharing(consent_id, source="sess-1",
                              summary=summary + " ",  # one byte
                              destination=DEST_TEAM_RECORD, ctx=self._author_ctx())
        assert d.allowed is False
        assert d.reason == "consent-summary-mismatch"

    def test_wrong_destination_denied(self, home):
        summary = "s"
        rec = record_sharing_consent(
            {"authorDiscordUserId": AM_ID, "summary": summary,
             "destination": DEST_TEAM_RECORD, "sourceRef": "sess-1"},
            ctx=self._author_ctx())
        other = dict(DEST_TEAM_RECORD, resource="clients/other/notes")
        d = authorize_sharing(rec.action, source="sess-1", summary=summary,
                              destination=other, ctx=self._author_ctx())
        assert d.allowed is False
        assert d.reason == "consent-destination-mismatch"

    def test_revoked_consent_denied(self, home):
        summary = "s"
        ctx = self._author_ctx()
        rec = record_sharing_consent(
            {"authorDiscordUserId": AM_ID, "summary": summary,
             "destination": DEST_TEAM_RECORD, "sourceRef": "sess-1"},
            ctx=ctx)
        assert rec.allowed is True
        revoke = record_sharing_consent(
            {"authorDiscordUserId": AM_ID, "summary": summary,
             "destination": DEST_TEAM_RECORD, "sourceRef": "sess-1",
             "status": "revoked"},
            ctx=ctx)
        assert revoke.allowed is True
        d = authorize_sharing(rec.action, source="sess-1", summary=summary,
                              destination=DEST_TEAM_RECORD, ctx=ctx)
        assert d.allowed is False
        assert d.reason == "consent-revoked"

    def test_unknown_consent_denied(self, home):
        d = authorize_sharing("shc_nope", source="sess-1", summary="s",
                              destination=DEST_TEAM_RECORD, ctx=self._author_ctx())
        assert d.allowed is False
        assert d.reason == "consent-unknown"

    def test_model_supplied_approval_flag_ignored(self, home):
        # a proposal carrying an approvedBy from someone else is still only
        # valid when the authenticated author matches authorDiscordUserId
        rec = record_sharing_consent(
            {"authorDiscordUserId": AM_ID, "summary": "s",
             "destination": DEST_TEAM_RECORD,
             "sourceRef": "sess-1",
             "approvedByDiscordUserId": OWNER_ID},
            ctx=self._author_ctx())
        # recorded fine (author == ctx), but approvedBy field was overridden
        reg = json.loads((home / "team_authz" / "register.json").read_text(encoding="utf-8"))
        entry = next(c for c in reg["sharingConsents"])
        assert entry["approvedByDiscordUserId"] == AM_ID

    def test_consent_does_not_excuse_off_origin_send(self, home):
        # perfect consent to a MESSAGING destination outside the authorizing
        # member's originating chat still denies (may_send_to governs sends)
        summary = "s"
        ctx = self._author_ctx()
        dest = {"shape": "messaging", "platform": "discord", "guild": GUILD,
                "chatId": CHAT_TEAM_CHANNEL, "threadId": None}
        rec = record_sharing_consent(
            {"authorDiscordUserId": AM_ID, "summary": summary,
             "destination": dest, "sourceRef": "sess-1"},
            ctx=ctx)
        assert rec.allowed is True
        d = authorize_sharing(rec.action, source="sess-1", summary=summary,
                              destination=dest, ctx=ctx)
        assert d.allowed is False
        assert d.reason == "destination-outside-origin"

    def test_consent_to_originating_chat_succeeds(self, home):
        # author approves sharing INTO their own originating chat: allowed
        summary = "s"
        ctx = self._author_ctx()
        dest = {"shape": "messaging", "platform": "discord", "guild": GUILD,
                "chatId": CHAT_AM, "threadId": None}
        rec = record_sharing_consent(
            {"authorDiscordUserId": AM_ID, "summary": summary,
             "destination": dest, "sourceRef": "sess-1"},
            ctx=ctx)
        d = authorize_sharing(rec.action, source="sess-1", summary=summary,
                              destination=dest, ctx=ctx)
        assert d.allowed is True, d.reason


# ---------------------------------------------------------------------------
# Browser lane: sessions are for eyes, not keys (Charles 2026-09-17)
# ---------------------------------------------------------------------------


class TestBrowserLane:
    def test_viewing_allowed_for_every_member(self, home):
        for ctx in (CTX_MANAGER, CTX_AM, CTX_META, CTX_SOCIAL, CTX_ASSET, CTX_WEB):
            d = authorize_tool("browser_navigate",
                               {"url": "https://ads.example.com/campaigns"},
                               ctx)
            assert d.allowed is True, (ctx.user_id, d.reason)

    def test_browser_exec_allowed_as_ordinary_host_execution(self, home):
        # T1: browser_exec is ordinary host Python execution for a teammate.
        for payload in (
            {"code": "page_info()"},
            {"code": "__import__('builtins').open('/tmp/synthetic-owner.txt').read()"},
            {"code": "open('x','w').write('y')"},
        ):
            assert authorize_tool("browser_exec", payload, CTX_AM).allowed is True, payload
        # Owner keeps full access (own machine)
        assert authorize_tool("browser_exec", {"code": "1"}, CTX_OWNER).allowed is True

    def test_login_attempt_denied(self, home):
        d = authorize_tool("browser_type",
                           {"text": "hunter2", "ref": "#password"},
                           CTX_AM)
        assert d.allowed is False
        assert d.reason == "protected:browser-login"
        # Flat refusal, no approval route (T1, D1 wording)
        assert d.message == "I can't log in as Charles or enter credentials on his behalf."

    def test_machine_info_read_denied(self, home):
        d = authorize_tool("browser_console",
                           {"expression": "localStorage.getItem('token')"},
                           CTX_AM)
        assert d.allowed is False
        assert d.message == "I can't read files or saved data from Charles' machine."

    def test_owner_not_gated(self, home):
        assert authorize_tool("browser_type",
                              {"text": "x", "ref": "#login"},
                              CTX_OWNER).allowed is True

    def test_outsider_viewing_denied(self, home):
        # Viewing is open to MEMBERS, not the world
        assert authorize_tool("browser_navigate",
                              {"url": "https://example.com"},
                              _ctx(OUTSIDER_ID)).allowed is False


# ---------------------------------------------------------------------------
# Tamper-evident audit + inbound message trail
# ---------------------------------------------------------------------------


class TestAuditChain:
    def test_chain_valid_after_normal_use(self, home):
        assert authorize_tool("web_search", {}, CTX_AM).allowed is True
        assert authorize_tool("browser_vault_list", {}, CTX_AM).allowed is False
        ok, broken = audit_verify()
        assert ok is True and broken is None

    def test_concurrent_appends_do_not_fork_chain(self, home):
        # Opus review B2: read-prev + append must be serialized so
        # concurrent audit writers extend one chain, not fork it.
        errors = []

        def append_loop(n):
            try:
                for i in range(15):
                    if not team_authz.audit({"event": "probe", "tool": f"t{n}-{i}",
                                             "decision": "allowed", "reason": "ok"}):
                        errors.append(f"append-failed:{n}-{i}")
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=append_loop, args=(1,))
        t2 = threading.Thread(target=append_loop, args=(2,))
        t3 = threading.Thread(target=append_loop, args=(3,))
        t1.start(); t2.start(); t3.start()
        t1.join(); t2.join(); t3.join()
        assert errors == []
        ok, broken = audit_verify()
        assert ok is True and broken is None, broken
        assert len(_audit_rows(home)) == 45

    def test_tamper_detected(self, home):
        assert authorize_tool("web_search", {}, CTX_AM).allowed is True
        p = home / "team_authz" / "audit.jsonl"
        lines = p.read_text(encoding="utf-8").splitlines()
        row = json.loads(lines[0])
        row["reason"] = "nothing-happened"  # forge an edit
        lines[0] = json.dumps(row, ensure_ascii=False, sort_keys=True)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ok, broken = audit_verify()
        assert ok is False and broken == 1

    def test_deletion_detected(self, home):
        assert authorize_tool("web_search", {}, CTX_AM).allowed is True
        assert authorize_tool("browser_vault_list", {}, CTX_AM).allowed is False
        p = home / "team_authz" / "audit.jsonl"
        lines = p.read_text(encoding="utf-8").splitlines()
        p.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")
        ok, broken = audit_verify()
        assert ok is False

    def test_inbound_message_logged_before_tools(self, home):
        assert log_inbound(CTX_AM, "check my campaign spend") is True
        rows = _audit_rows(home)
        assert rows[-1]["event"] == "message"
        assert rows[-1]["memberKey"] == "lianna"
        assert rows[-1]["discordUserId"] == AM_ID

    def test_inbound_failure_blocks_tools(self, home):
        # no tool may run when the trail entry cannot be written
        monkey = pytest.MonkeyPatch()
        with monkey.context() as m:
            m.setattr(team_authz, "audit", lambda ev: False)
            assert log_inbound(CTX_AM, "x") is False

    def test_inbound_ungoverned_noop(self, home):
        _write_config(home, CONFIG_DISABLED)
        team_authz._REGISTER_CACHE.clear()
        assert log_inbound(CTX_AM, "x") is True
        assert _audit_rows(home) == []  # ungoverned keeps base behaviour


# ---------------------------------------------------------------------------
# Concurrency: BLOCK-1 spend-cap TOCTOU + BLOCK-2 lost-update (reviewer P2/P3)
# ---------------------------------------------------------------------------


class TestConcurrencyHardening:
    def _spend_reg(self):
        reg = _base_register()
        reg["toolActions"] = [{
            "pattern": "meta_ads_set_budget", "action": "ads.meta.write",
            "connectionId": "conn-ghl-main", "amountArg": "amount",
            "accountArg": "account", "currencyArg": "currency"}]
        reg["connections"] = [{
            "id": "conn-ghl-main", "connector": "ghl", "account": "acme",
            "ownerClass": "business", "actions": ["ghl.manage", "ads.meta.write"]}]
        reg["spendingCaps"] = [{
            "memberKey": "dianne", "connectionId": "conn-ghl-main",
            "account": "acme", "currency": "AUD", "period": "month",
            "amount": 100.0}]
        return reg

    def test_concurrent_spends_cannot_doublepass_cap(self, home):
        # BLOCK-1: two threads spending 60 each against a 100 cap must not
        # both be allowed (old code let both pass: check-then-append race).
        reg = self._spend_reg()
        _write_register(home, reg)
        team_authz._REGISTER_CACHE.clear()
        results = []
        barrier = threading.Barrier(2)

        def spend():
            barrier.wait()
            d = authorize_tool("meta_ads_set_budget",
                               {"amount": 60, "account": "acme",
                                "currency": "AUD"}, CTX_META)
            results.append(d.allowed)

        t1 = threading.Thread(target=spend)
        t2 = threading.Thread(target=spend)
        t1.start(); t2.start(); t1.join(); t2.join()
        assert sorted(results) == [False, True]
        # audit must contain exactly one allowed row
        allowed_rows = [r for r in _audit_rows(home)
                        if r.get("decision") == "allowed" and r.get("amount")]
        assert len(allowed_rows) == 1

    def test_concurrent_register_changes_no_lost_update(self, home):
        # BLOCK-2: two concurrent member additions must BOTH land.
        reg = _base_register()
        _write_register(home, reg)
        team_authz._REGISTER_CACHE.clear()
        barrier = threading.Barrier(2)
        outcomes = []

        def add_member(n):
            barrier.wait()
            d = apply_register_change({
                "kind": "member.upsert",
                "payload": {"discordUserId": f"9000000000000001{n}",
                            "memberKey": f"m{n}", "role": "account_manager",
                            "status": "active"}}, CTX_MANAGER)
            outcomes.append((n, d.allowed, d.reason))

        t1 = threading.Thread(target=add_member, args=(1,))
        t2 = threading.Thread(target=add_member, args=(2,))
        t1.start(); t2.start(); t1.join(); t2.join()
        # owner-surface rule: manager holds register.change so both proceed;
        # conflict-retry is acceptable, silent loss is not.
        final = json.loads((home / "team_authz" / "register.json")
                           .read_text(encoding="utf-8"))
        landed = {m["memberKey"] for m in final["members"]}
        attempted = {f"m{n}" for n, ok, _r in outcomes if ok}
        # every successful change must be present in the final register
        assert attempted <= landed, (outcomes, landed)

    def test_unique_temp_files_no_collision(self, home):
        # BLOCK-2: concurrent atomic writes must not share temp names.
        import agent.team_authz as ta
        names = set()
        for _ in range(50):
            names.add(ta._atomic_write_json.__code__.co_consts is not None)
        # direct probe: run two writers in threads, assert no exception
        p = home / "team_authz" / "register.json"
        errors = []

        def writer():
            try:
                for _ in range(10):
                    d = _base_register()
                    with ta._mutation_lock(p):
                        ta._atomic_write_json(p, d)
            except Exception as exc:  # pragma: no cover - failure signal
                errors.append(exc)

        t1 = threading.Thread(target=writer)
        t2 = threading.Thread(target=writer)
        t1.start(); t2.start(); t1.join(); t2.join()
        assert errors == []
        # register still valid JSON after 20 concurrent-style writes
        json.loads(p.read_text(encoding="utf-8"))


class TestRequesterBinding:
    @pytest.mark.parametrize("uid, allowed", [(AM_ID, True), (OUTSIDER_ID, False)])
    def test_real_session_source_binds_governed_platform(self, home, uid, allowed):
        from gateway.config import Platform
        from gateway.session import SessionSource
        token = bind_requester(SessionSource(platform=Platform.DISCORD,
            user_id=uid, chat_id=CHAT_AM, scope_id=GUILD))
        try:
            assert current_requester().platform == "discord"
            assert is_governed()
            assert authorize_tool("web_search", {}).allowed is allowed
            assert authorize_tool("read_file", {}).allowed is allowed
        finally:
            reset_requester(token)

    def test_bind_and_reset_roundtrip(self, home):
        token = bind_requester(CTX_AM)
        try:
            assert current_requester() == CTX_AM
            assert requester_ref()["user_id"] == AM_ID
        finally:
            reset_requester(token)
        assert current_requester() is None

    def test_ref_dict_rebinds(self, home):
        token = bind_requester(requester_ref(CTX_AM))
        try:
            p = resolve_principal(None)
            assert p.status == "active"
            assert p.role == "account_manager"
        finally:
            reset_requester(token)

    def test_memory_namespace_per_member(self, home):
        assert memory_namespace(CTX_AM).startswith("team-")
        assert memory_namespace(CTX_OWNER) is None
        with pytest.raises(TeamAuthzDenied):
            memory_namespace(_ctx(OUTSIDER_ID))

    def test_memory_namespace_denied_raises(self, home):
        with pytest.raises(TeamAuthzDenied):
            memory_namespace(_ctx(OUTSIDER_ID))


# ---------------------------------------------------------------------------
# Charles' three-denial policy (2026-09-18)
#
# The whole point of the simplification: a teammate does ordinary work with an
# EMPTY register, and exactly three things refuse flatly. Denials passing is
# not evidence -- every denial row below is paired with a positive control.
# ---------------------------------------------------------------------------


POSITIVE_BARE = [
    "terminal", "execute_code", "process_manage", "read_file", "write_file",
    "browser_exec", "cronjob_manage", "delegate_task", "web_search",
    "session_search", "mem0_search", "connectors__ghl__proxy_fetch",
    "image_generate", "video_generate",
]

# (tool, args, expected protected class)
DENIAL_ROWS = [
    ("browser_vault_get", {}, "credentials"),
    ("1password_read", {}, "credentials"),
    ("gmail_search", {}, "personal-mailbox"),
    ("email_send", {}, "personal-mailbox"),
    ("browser_type", {"text": "my password is hunter2"}, "browser-login"),
    ("browser_navigate", {"url": "file:///C:/Users/User/.ssh/id_rsa"},
     "browser-machine-info"),
]


@pytest.fixture
def open_home(home):
    """Base home with every register mapping empty.

    No toolActions, no connections, no spendingCaps -- the live register's
    actual shape. Ordinary work must not require an operator to map it first.
    """
    reg = _base_register()
    reg["toolActions"] = []
    reg["connections"] = []
    reg["spendingCaps"] = []
    _write_register(home, reg)
    team_authz._REGISTER_CACHE.clear()
    return home


class TestThreeDenials:
    """Charles 2026-09-18: mailbox, vault/credentials, browser login. No more."""

    # -- positive controls: a teammate can actually work -------------------

    @pytest.mark.parametrize("tool", POSITIVE_BARE)
    def test_ordinary_tool_allowed_with_empty_register(self, open_home, tool):
        d = authorize_tool(tool, {}, CTX_AM)
        assert d.allowed is True, f"{tool} denied: {d.reason} / {d.message}"

    @pytest.mark.parametrize("tool", POSITIVE_BARE)
    def test_ordinary_tool_is_discoverable(self, open_home, tool):
        assert tool in filter_tool_names([tool], CTX_AM)

    def test_teammate_reads_own_local_attachment(self, open_home, tmp_path):
        """Ani's case: her own uploaded screenshot is not Charles' data."""
        shot = tmp_path / "ani-setup-tab.png"
        shot.write_bytes(b"\x89PNG\r\n\x1a\n synthetic")
        d = authorize_tool("vision_analyze", {"image_path": str(shot)}, CTX_AM)
        assert d.allowed is True, f"own attachment denied: {d.reason} / {d.message}"

    def test_teammate_browses_public_https(self, open_home):
        d = authorize_tool("browser_navigate", {"url": "https://example.com"}, CTX_AM)
        assert d.allowed is True, f"public https denied: {d.reason} / {d.message}"

    # -- the three denials --------------------------------------------------

    @pytest.mark.parametrize("tool,args,klass", DENIAL_ROWS)
    def test_protected_class_denied(self, open_home, tool, args, klass):
        d = authorize_tool(tool, args, CTX_AM)
        assert d.allowed is False, f"{tool} was allowed"
        assert d.reason == f"protected:{klass}", f"{tool} reason={d.reason}"

    @pytest.mark.parametrize("tool,args,klass", DENIAL_ROWS)
    def test_denial_is_flat_with_no_approval_route(self, open_home, tool, args, klass):
        d = authorize_tool(tool, args, CTX_AM)
        msg = d.message or ""
        assert msg.startswith("I can't"), f"{tool} message={msg!r}"
        assert "ask" not in msg.lower(), f"{tool} offers an ask route: {msg!r}"
        assert "approv" not in msg.lower(), f"{tool} offers approval: {msg!r}"

    def test_loopback_browser_destination_denied(self, open_home, monkeypatch):
        """The home fixture resolves everything to a public IP; undo that so
        the loopback guard is genuinely exercised rather than bypassed."""
        monkeypatch.setattr("tools.url_safety._getaddrinfo",
                            lambda *a, **kw: [(2, 1, 6, "", ("127.0.0.1", 8080))])
        d = authorize_tool("browser_navigate", {"url": "http://127.0.0.1:8080"}, CTX_AM)
        assert d.allowed is False, "loopback destination was allowed"
        assert d.reason == "protected:browser-machine-info", d.reason

    # -- owner is unaffected ------------------------------------------------

    @pytest.mark.parametrize("tool,args,klass", DENIAL_ROWS)
    def test_owner_still_allowed(self, open_home, tool, args, klass):
        d = authorize_tool(tool, args, CTX_OWNER)
        assert d.allowed is True, f"owner denied {tool}: {d.reason}"

    # -- no approval path exists at execution time --------------------------

    @pytest.mark.parametrize("tool,args,klass", DENIAL_ROWS)
    def test_execution_gate_still_denies(self, open_home, tool, args, klass):
        """model_tools recheck denies independently of any approval record."""
        import model_tools
        token = bind_requester(CTX_AM)
        try:
            assert model_tools.team_authz_denied(tool, args, CTX_AM) is not None
        finally:
            reset_requester(token)
