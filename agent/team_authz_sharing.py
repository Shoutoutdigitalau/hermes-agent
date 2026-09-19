"""Sharing consent for private-DM summaries (mission HTS-01, r2 overlay).

Private-DM client information may enter shared team records ONLY after the
originating teammate approves the EXACT summary bytes and the EXACT typed
destination. Generic consent, manager oversight, owner status, model-supplied
approval flags and aliases cannot mint consent. Amendments require new
author approval. Consent is subordinate to ordinary authority: it never
elevates role/action/account/cap/destination grants.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Optional

from agent.team_authz import (
    Decision,
    Principal,
    RequesterContext,
    _atomic_write_json,
    _load_register,
    _mutation_lock,
    _provenance,
    _utcnow,
    _validate_register,
    audit,
    current_requester,
    is_governed,
    register_path,
    resolve_principal,
)

__all__ = [
    "record_sharing_consent",
    "authorize_sharing",
    "summary_digest",
]

_DEST_FIELDS = ("platform", "guild", "chatId", "threadId", "connector",
                "connectionId", "account", "resource", "field")
# Destination identity fields that must be present for each shape:
#   messaging: platform + guild + chatId (+ optional threadId)
#   connector: connector + connectionId + account + resource (+ optional field)
_DEST_REQUIRED = {
    "messaging": ("platform", "guild", "chatId"),
    "connector": ("connector", "connectionId", "account", "resource"),
}


def summary_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _norm_dest(destination: Mapping) -> Optional[dict]:
    """Validate + normalize a typed destination; None when malformed."""
    if not isinstance(destination, Mapping):
        return None
    shape = destination.get("shape")
    if shape not in _DEST_REQUIRED:
        shape = "messaging" if destination.get("chatId") else \
            "connector" if destination.get("connectionId") else None
        if shape is None:
            return None
    d = {"shape": shape}
    for f in _DEST_FIELDS:
        v = destination.get(f)
        if v is not None:
            if not isinstance(v, str):
                return None
            d[f] = v
    for f in _DEST_REQUIRED[shape]:
        if not d.get(f):
            return None
    if shape == "messaging" and "threadId" in d and d["threadId"] == "":
        d.pop("threadId")
    return d


def _same_dest(a: Mapping, b: Mapping) -> bool:
    return _norm_dest(a) == _norm_dest(b)


def _consents(reg: Mapping) -> list:
    cs = reg.get("sharingConsents", [])
    return cs if isinstance(cs, list) else []


def record_sharing_consent(proposal: Mapping, *, ctx: Optional[RequesterContext] = None) -> Decision:
    """Trusted control plane: the authenticated originating author approves.

    proposal: {sourceRef, authorDiscordUserId, summary, destination,
               approvedByDiscordUserId?, approvedAt?, status?}
    Only the authenticated originating author may approve their own private
    summary for one exact destination. Managers/owners cannot approve for
    someone else. status may only be 'approved' or 'revoked'.
    """
    try:
        if ctx is None:
            ctx = current_requester()
        # is_governed() is False on the owner's own control-plane surfaces;
        # consent recording is a control-plane action so we proceed either
        # way, but identity must be present and authenticated.
        author_id = str(proposal.get("authorDiscordUserId", ""))
        summary = proposal.get("summary")
        if not author_id:
            return Decision(False, "consent-author-missing")
        if not isinstance(summary, str) or not summary:
            return Decision(False, "consent-summary-missing")
        dest = _norm_dest(proposal.get("destination") or {})
        if dest is None:
            return Decision(False, "consent-destination-invalid")
        if ctx is None or not ctx.user_id:
            return Decision(False, "no-requester-context")
        # Only the originating author themself may record approval.
        if ctx.user_id != author_id:
            audit({"event": "sharing-consent-recorded", "decision": "denied",
                   "reason": "consent-author-mismatch"})
            return Decision(False, "consent-author-mismatch")
        if _provenance() != "transport" or ctx != current_requester():
            return Decision(False, "consent-provenance-unverified")
        if not is_governed(ctx) or resolve_principal(ctx).denied:
            return Decision(False, "consent-author-inactive")
        source = proposal.get("sourceRef")
        if not isinstance(source, str) or not source:
            return Decision(False, "consent-source-missing")
        # Model-supplied approvedBy is ignored entirely.
        status = str(proposal.get("status", "approved"))
        if status not in ("approved", "revoked"):
            return Decision(False, "consent-status-invalid")

        reg, err = _load_register()
        if reg is None:
            return Decision(False, err or "register-invalid")

        now = _utcnow().isoformat(timespec="seconds")
        entry = {
            "id": "shc_" + summary_digest(json_dumps([author_id, source, summary, dest]))[:24],
            "sourceRef": source,
            "authorDiscordUserId": author_id,
            "summary": summary,
            "summarySha256": summary_digest(summary),
            "destination": dest,
            "approvedByDiscordUserId": author_id,
            "provenance": "verified-author-transport",
            "approvedAt": now,
            "status": status,
        }
        consents = [c for c in _consents(reg)
                    if c.get("id") != entry["id"]]
        consents.append(entry)
        new_reg = dict(reg)
        new_reg["sharingConsents"] = consents
        reason = _validate_register(new_reg)
        if reason is not None:
            return Decision(False, f"invalid-result:{reason}")
        ev = {"event": "sharing-consent-recorded" if status == "approved" else
              "sharing-consent-revoked",
              "decision": "allowed", "reason": "ok", "approvalRef": entry["id"]}
        if not audit(ev):
            return Decision(False, "audit-failure")
        # BLOCK-2: consents append under the mutation lock with a freshness
        # re-check, so concurrent register writes cannot lose this consent.
        with _mutation_lock(register_path()):
            current, cur_err = _load_register()
            if current is None or json.dumps(current, sort_keys=True) != json.dumps(reg, sort_keys=True):
                return Decision(False, "register-conflict-retry")
            _atomic_write_json(register_path(), new_reg)
        return Decision(True, "ok", entry["id"])
    except Exception as exc:
        return Decision(False, f"policy-error:{type(exc).__name__}")


def authorize_sharing(consent_id: str, *, source: str, summary: str,
                      destination: Mapping, ctx: Optional[RequesterContext] = None) -> Decision:
    """Fail-closed exact consent check for publishing a private summary.

    The allowed publication is the conjunction of: active requester, consent
    exists, exact author/bytes/destination/status, ordinary authority for the
    destination (may_send_to), and audit append success. Never a cached
    allow decision: state is re-read from the register.
    """
    try:
        if not isinstance(consent_id, str) or not consent_id:
            return Decision(False, "consent-id-missing")
        if not isinstance(summary, str):
            return Decision(False, "consent-summary-missing")
        dest = _norm_dest(destination or {})
        if dest is None:
            return Decision(False, "consent-destination-invalid")

        from agent.team_authz import is_governed, resolve_principal, may_send_to

        if is_governed(ctx):
            principal = resolve_principal(ctx)
            if principal.denied:
                return Decision(False, principal.deny_reason)

        reg, err = _load_register()
        if reg is None:
            return Decision(False, err or "register-invalid")

        entry = next((c for c in _consents(reg)
                      if isinstance(c, Mapping) and c.get("id") == consent_id), None)
        if entry is None:
            return Decision(False, "consent-unknown")
        if entry.get("status") != "approved":
            return Decision(False, "consent-revoked")
        author = entry.get("authorDiscordUserId")
        if not author or entry.get("approvedByDiscordUserId") != author \
                or entry.get("provenance") != "verified-author-transport":
            return Decision(False, "consent-provenance-invalid")
        if not any(m.get("discordUserId") == author and m.get("status") == "active"
                   for m in reg["members"]):
            return Decision(False, "consent-author-inactive")
        if entry.get("summarySha256") != summary_digest(summary):
            return Decision(False, "consent-summary-mismatch")
        if not _same_dest(entry.get("destination") or {}, dest):
            return Decision(False, "consent-destination-mismatch")
        if not source or entry.get("sourceRef") != source:
            return Decision(False, "consent-source-mismatch")

        # Ordinary destination authority still applies. For messaging
        # destinations that is may_send_to (originating chat only). For
        # connector destinations (shared team records) may_send_to has no
        # chat target; the caller's connector call is separately authorized
        # (HTS-03), so consent here only gates the exact record shape.
        if dest["shape"] == "messaging":
            decision = may_send_to(dest, ctx)
            if not decision.allowed:
                return decision

        if not audit({"event": "sharing-check", "decision": "allowed", "reason": "ok",
                      "approvalRef": consent_id, "destination": dest.get("chatId") or
                      dest.get("connectionId")}):
            return Decision(False, "audit-failure")
        return Decision(True, "ok")
    except Exception as exc:
        return Decision(False, f"policy-error:{type(exc).__name__}")


def connector_publication_binding(tool_name: str, args: Mapping, row: Mapping,
                                  ctx: RequesterContext) -> tuple:
    """Trusted DM origin + exact complete payload, independent of model labels.

    A private turn cannot prove a payload is unrelated to its private input.
    Connector writes therefore require confirmation of the canonical payload;
    registered reads and work originating in shared channels stay ordinary.
    """
    reg, err = _load_register()
    if reg is None:
        raise ValueError(err or "register-invalid")
    connection = next((c for c in reg.get("connections", [])
                       if c.get("id") == row.get("connectionId")), None)
    if connection is None:
        raise ValueError("connector-unknown")
    consent_keys = {"sharing_consent_id", "sharingConsentId", "consentId"}
    payload = {k: v for k, v in args.items() if k not in consent_keys}
    summary = json_dumps({"tool": tool_name, "arguments": payload})
    origin = f"dm:{ctx.platform}:{ctx.user_id}:{ctx.chat_id}"
    dest = {"shape": "connector", "connector": connection.get("connector"),
            "connectionId": connection.get("id"),
            "account": str(args.get(row.get("accountArg"), connection.get("account", ""))),
            "resource": tool_name}
    return origin, summary, dest


def json_dumps(obj: Any) -> str:
    import json as _json
    return _json.dumps(obj, ensure_ascii=False, sort_keys=True)
