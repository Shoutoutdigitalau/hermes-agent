"""Protected owner resources (mission hermes-team-security-20260917, HTS-01 r3).

Charles-private resources are denied to every governed non-owner BEFORE any
mutable ``toolActions`` mapping, business-role permission, spend/integration
approval or general approval handling is even consulted. Protected classes
come from immutable built-ins plus protected register metadata — register
edits cannot weaken them.

Only verified owner identity on a configured secure owner surface may mint a
specifically scoped ``ownerApprovals`` entry, and only through
:func:`record_owner_approval` — a trusted control-plane function, not an
agent-callable tool. Display names, forwarded/pasted statements, model
``approvedBy`` arguments, manager approvals, ``approvals.mode=off``, yolo /
bypass modes, child identities and cron/job provenance are never owner
approval.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional

from agent.team_authz import (
    ACTION_OWNER_HOST,
    ROLE_OWNER,
    Decision,
    Principal,
    RequesterContext,
    _atomic_write_json,
    _load_register,
    _mutation_lock,
    _provenance,
    _read_config_state,
    _utcnow,
    _validate_register,
    audit,
    classify_protected,
    classify_protected_call,
    register_path,
)

__all__ = [
    "record_owner_approval",
    "authorize_owner_resource",
    "check_protected_for_tool",
    "check_register_change_protected",
]

# Operations that may be covered by an owner approval (checked exactly).
_OWNER_OPERATIONS = frozenset({
    "owner.private.read",
    "owner.private.write",
    "owner.account.use",
    "owner.vault.use",
    "owner.browser.use",
    "owner.host.use",
})

# Surfaces trusted to carry the owner's live identity. "secure-owner"
# provenance is minted only by the trusted control plane (config-declared
# secure channel), never by a model-facing tool path.
_SECURE_OWNER_SURFACES = frozenset({"secure-owner", "owner-desktop", "owner-cli"})

_DEFAULT_TTL_SECONDS = 3600


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_protected_for_tool(tool_name: str, args: Optional[Mapping],
                             principal: Principal, reg: Mapping,
                             ctx: Optional[RequesterContext]) -> Optional[str]:
    """Protected-resource gate for ``authorize_tool``.

    Returns None when the call may proceed to ordinary checks, else a fixed
    deny reason. Order: immutable class → owner identity. An approval ID
    never transfers the owner's private perimeter to a non-owner.
    """
    protected_class = classify_protected_call(tool_name, args)
    if protected_class is None:
        return None
    if principal.is_owner:
        # Owner holds owner.host by construction; approval not required for
        # built-in protected classes on a governed surface.
        if ACTION_OWNER_HOST in principal.capabilities:
            return None
        return "owner-capability-missing"
    # Approval records are not bearer grants to a teammate. The owner must
    # perform protected operations on the owner's own authenticated turn.
    return f"protected:{protected_class}"


def _operation_for_class(protected_class: str) -> str:
    return {
        "credentials": "owner.vault.use",
        "browser-login": "owner.browser.use",
        "browser-machine-info": "owner.browser.use",
        "personal-mailbox": "owner.account.use",
    }.get(protected_class, "owner.private.read")


def check_register_change_protected(change: Mapping, principal: Principal,
                                    reg: Mapping) -> Optional[str]:
    """Reject register changes that touch protected owner state.

    Nobody — manager or otherwise — may reassign/promote the owner, edit
    owner approvals, relabel personal→business for non-owners, remap
    protected tools, disable the guard or widen protected audiences.
    """
    kind = change.get("kind")
    payload = change.get("payload", {}) or {}

    if kind in ("owner.identity.set", "owner.approval.upsert",
                "owner.approval.revoke", "owner.guard.disable",
                "sharing.consent.upsert", "sharing.consent.revoke"):
        # Trusted control plane only: apply_register_change never routes
        # these kinds (unknown-kind deny); an explicit attempt names intent.
        return "owner-state-control-plane-only"

    if kind == "member.upsert":
        role = str(payload.get("role", ""))
        target_id = str(payload.get("discordUserId", ""))
        existing = next((m for m in reg.get("members", [])
                         if m.get("discordUserId") == target_id), None)
        if role == ROLE_OWNER and not principal.is_owner:
            return "owner-reassignment-denied"
        if existing and existing.get("role") == ROLE_OWNER and not principal.is_owner:
            return "owner-reassignment-denied"
        if role == "manager" and not principal.is_owner:
            return "manager-mutation-denied"
        if existing and existing.get("role") == "manager" and not principal.is_owner:
            return "manager-mutation-denied"

    if kind == "member.remove":
        target_id = str(payload.get("discordUserId", ""))
        existing = next((m for m in reg.get("members", [])
                         if m.get("discordUserId") == target_id), None)
        if existing and existing.get("role") in (ROLE_OWNER, "manager") and not principal.is_owner:
            return "owner-reassignment-denied" if existing.get("role") == ROLE_OWNER \
                else "manager-mutation-denied"

    if kind == "role.grant":
        cap = str(payload.get("capability", ""))
        if cap == ACTION_OWNER_HOST and str(payload.get("role", "")) != ROLE_OWNER:
            return "owner-host-grant-outside-owner"

    if kind == "toolaction.upsert":
        import re as _re
        pattern = str(payload.get("pattern", ""))
        if _re.search(r"(vault|password|credential|token|cookie|browser|terminal"
                      r"|shell|execute_code|proxy|http_request|email_|mail_)", pattern,
                      _re.IGNORECASE):
            return "protected-tool-remap-denied"

    if kind == "connection.upsert":
        existing = next((c for c in reg.get("connections", [])
                         if c.get("id") == payload.get("id")), None)
        if existing and existing.get("ownerClass") == "personal" \
                and payload.get("ownerClass") != "personal" and not principal.is_owner:
            return "relabel-personal-denied"

    if kind == "oversight.destination.add":
        # Widening oversight audiences is owner-only.
        if not principal.is_owner:
            return "oversight-widen-denied"

    return None


# ---------------------------------------------------------------------------
# Owner approvals (trusted control plane)
# ---------------------------------------------------------------------------


def _secure_surface_ok(ctx: Optional[RequesterContext]) -> bool:
    """Require bound transport identity AND an explicitly configured surface."""
    if _provenance() != "transport" or ctx is None or ctx != _ctx_from_contextvar():
        return False
    if _owner_surface_for(ctx) not in _SECURE_OWNER_SURFACES:
        return False
    state, block = _read_config_state()
    if state != "enabled":
        return False
    surfaces = block.get("secure_owner_surfaces", [])
    return isinstance(surfaces, list) and any(
        isinstance(surface, Mapping)
        and surface.get("platform") == ctx.platform
        and surface.get("chatId") == ctx.chat_id and bool(ctx.chat_id)
        and surface.get("chatType") == ctx.chat_type
        for surface in surfaces
    )


def _owner_surface_for(ctx: Optional[RequesterContext]) -> Optional[str]:
    if ctx is None:
        return None
    # chat_type is the only transport field we can key a "secure surface" off
    # at this layer; the desktop/CLI owner surfaces are ungoverned and never
    # reach these APIs. The trusted control plane passes chat_type="secure-owner".
    ct = str(ctx.chat_type or "")
    if ct in _SECURE_OWNER_SURFACES:
        return ct
    platform = str(ctx.platform or "")
    if platform in _SECURE_OWNER_SURFACES:
        return platform
    return None


def _owner_identity(reg: Mapping) -> Optional[str]:
    owners = [m for m in reg.get("members", []) if m.get("role") == ROLE_OWNER]
    if len(owners) != 1 or owners[0].get("status") != "active":
        return None
    owner_id = owners[0].get("discordUserId")
    oi = reg.get("ownerIdentity")
    if oi is not None and (not isinstance(oi, Mapping) or oi.get("discordUserId") != owner_id):
        return None
    return owner_id


def record_owner_approval(proposal: Mapping, *, ctx: Optional[RequesterContext] = None) -> Decision:
    """Record one specifically scoped owner approval. Control plane only.

    Accepts ONLY verified Charles identity on a configured secure owner
    surface. Never agent-callable: enforcement points call it internally.
    """
    try:
        reg, err = _load_register()
        if reg is None:
            return Decision(False, err or "register-invalid")
        owner_id = _owner_identity(reg)
        if owner_id is None:
            return Decision(False, "owner-identity-missing")
        p = Principal(member_key="owner", discord_user_id=owner_id, role=ROLE_OWNER,
                      status="active", policy_version=reg.get("policyVersion", ""))
        if ctx is None:
            ctx = _ctx_from_contextvar()
        if not _secure_surface_ok(ctx):
            audit({"event": "owner-approval", "decision": "denied",
                   "reason": "owner-surface-unverified", "policyVersion": p.policy_version})
            return Decision(False, "owner-surface-unverified")
        if ctx is None or ctx.user_id != owner_id:
            audit({"event": "owner-approval", "decision": "denied",
                   "reason": "owner-identity-mismatch", "policyVersion": p.policy_version})
            return Decision(False, "owner-identity-mismatch")
        operation = str(proposal.get("operation", ""))
        resource = str(proposal.get("resource", ""))
        if operation not in _OWNER_OPERATIONS:
            return Decision(False, "owner-operation-unknown")
        if not resource:
            return Decision(False, "owner-resource-missing")
        audience = proposal.get("audience")
        if audience is not None and not isinstance(audience, str):
            return Decision(False, "owner-audience-invalid")
        ttl = proposal.get("ttlSeconds")
        try:
            ttl = int(ttl) if ttl is not None else _DEFAULT_TTL_SECONDS
        except (TypeError, ValueError):
            return Decision(False, "owner-ttl-invalid")
        if ttl <= 0:
            return Decision(False, "owner-ttl-invalid")

        now = _utcnow()
        entry = {
            "id": "oapr_" + _digest(f"{operation}|{resource}|{audience}|{now.isoformat()}")[:24],
            "operation": operation,
            "resource": resource,
            "audience": audience,
            "status": "approved",
            "approvedBy": owner_id,
            "provenance": "verified-owner-transport",
            "surface": {"platform": ctx.platform, "chatId": ctx.chat_id,
                        "chatType": ctx.chat_type},
            "approvedAt": now.isoformat(timespec="seconds"),
            "expiresAt": (now + timedelta(seconds=ttl)).isoformat(timespec="seconds"),
        }
        approvals = list(reg.get("ownerApprovals", []))
        approvals.append(entry)
        new_reg = dict(reg)
        new_reg["ownerApprovals"] = approvals
        reason = _validate_register(new_reg)
        if reason is not None:
            return Decision(False, f"invalid-result:{reason}")
        if not audit({"event": "owner-approval", "decision": "allowed", "reason": "ok",
                      "policyVersion": reg.get("policyVersion", ""),
                      "approvalRef": entry["id"], "action": operation}):
            return Decision(False, "audit-failure")
        # BLOCK-2: append approvals under the mutation lock with a freshness
        # re-check, so concurrent approval/consent writes cannot lose updates.
        with _mutation_lock(register_path()):
            current, cur_err = _load_register()
            if current is None or json.dumps(current, sort_keys=True) != json.dumps(reg, sort_keys=True):
                return Decision(False, "register-conflict-retry")
            _atomic_write_json(register_path(), new_reg)
        return Decision(True, "ok", entry["id"])
    except Exception as exc:
        return Decision(False, f"policy-error:{type(exc).__name__}")


def authorize_owner_resource(approval_id: str, *, operation: str, resource: str,
                             audience: Optional[str] = None,
                             ctx: Optional[RequesterContext] = None) -> Decision:
    """Validate an owner approval for an exact operation/resource/audience.

    Never grants ordinary role/action/account/cap/destination authority —
    callers must still run the ordinary pipeline after this returns allowed.
    """
    return authorize_owner_resource_full(
        approval_id, operation=operation, resource=resource, audience=audience,
        ctx=ctx, principal=None, reg=None)


def authorize_owner_resource_full(approval_id: str, *, operation: str, resource: str,
                                  audience: Optional[str] = None,
                                  ctx: Optional[RequesterContext] = None,
                                  principal: Optional[Principal] = None,
                                  reg: Optional[Mapping] = None) -> Decision:
    try:
        if reg is None:
            reg, err = _load_register()
            if reg is None:
                return Decision(False, err or "register-invalid")
        approvals = reg.get("ownerApprovals", [])
        if not isinstance(approvals, list):
            return Decision(False, "owner-approvals-malformed")
        entry = next((a for a in approvals
                      if isinstance(a, Mapping) and a.get("id") == approval_id), None)
        if entry is None:
            return Decision(False, "owner-approval-unknown")
        if entry.get("status") != "approved":
            return Decision(False, "owner-approval-revoked")
        owner_id = _owner_identity(reg)
        if not owner_id or entry.get("approvedBy") != owner_id \
                or entry.get("provenance") != "verified-owner-transport":
            return Decision(False, "owner-approval-provenance-invalid")
        state, block = _read_config_state()
        if state != "enabled" or entry.get("surface") not in block.get("secure_owner_surfaces", []):
            return Decision(False, "owner-approval-surface-revoked")
        # Authenticated owner provenance: the ORIGINAL approval was minted on
        # a secure surface by the owner; the CURRENT requester must be the
        # same active owner, or a non-owner explicitly invoking the approval
        # must still pass ordinary checks (owner approval is not ordinary
        # authority — a non-owner presenting an approval id still needs the
        # protected call unblocked exactly as scoped).
        if entry.get("operation") != operation:
            return Decision(False, "owner-approval-operation-mismatch")
        if entry.get("resource") != resource:
            return Decision(False, "owner-approval-resource-mismatch")
        entry_audience = entry.get("audience")
        if entry_audience is None:
            if audience is not None:
                return Decision(False, "owner-approval-audience-mismatch")
        elif audience is None or audience != entry_audience:
            return Decision(False, "owner-approval-audience-mismatch")
        expires = entry.get("expiresAt")
        if expires:
            try:
                exp = datetime.fromisoformat(str(expires))
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if _utcnow() > exp:
                    return Decision(False, "owner-approval-expired")
            except ValueError:
                return Decision(False, "owner-approval-expiry-malformed")
        if not audit({"event": "owner-approval-check", "decision": "allowed",
                      "reason": "ok", "approvalRef": approval_id, "action": operation}):
            return Decision(False, "audit-failure")
        return Decision(True, "ok")
    except Exception as exc:
        return Decision(False, f"policy-error:{type(exc).__name__}")


def _ctx_from_contextvar() -> Optional[RequesterContext]:
    from agent.team_authz import current_requester
    return current_requester()
