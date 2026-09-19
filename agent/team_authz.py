"""Team authorization core (mission hermes-team-security-20260917, HTS-01).

Per-member Discord authorization and conversation isolation enforced at
transport identity, independent of the model. Ships DISABLED by default:
with ``team_authz`` absent from config.yaml (or ``enabled: false``) every
entry point reports ungoverned and callers keep byte-identical base
behaviour.

Design contract (frozen, INITIAL_SPEC.md r1 + r2/r3 overlays):

- config: ``team_authz: {enabled: bool, governed_platforms: [discord]}``
  read at call time under the served profile home; never a module constant.
- register: ``<hermes_home>/team_authz/register.json`` (atomic replace),
  re-statted on every call so revocation binds mid-session.
- identity: principal = exact string match of the transport user_id to an
  ``active`` member; scope (guild) must be listed. Display names, role text,
  ``role_authorized`` and prompt claims are never inputs.
- default deny: unknown / inactive / revoked / malformed / error states all
  deny, owner included on governed surfaces.
- audit: ``<hermes_home>/team_authz/audit.jsonl`` — redacted metadata only.
  A required audit-append failure flips an allow into a deny.

This module owns policy only. Enforcement points (gateway, tools, memory,
history, delegation) live in their own files per the seam table and call in.
"""

from __future__ import annotations

import contextvars
import fnmatch
import hashlib
import itertools
import json
import math
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from hermes_constants import get_hermes_home

__all__ = [
    "Decision",
    "Principal",
    "RequesterContext",
    "TeamAuthzDenied",
    "bind_requester",
    "reset_requester",
    "current_requester",
    "requester_ref",
    "is_governed",
    "resolve_principal",
    "grant_digest",
    "authorize_tool",
    "filter_tool_names",
    "can_read_session",
    "memory_namespace",
    "may_send_to",
    "apply_register_change",
    "audit",
    "audit_verify",
    "log_inbound",
    "classify_protected",
    "classify_protected_call",
    "register_path",
    "DENY_NO_REQUESTER_CONTEXT",
]

DENY_NO_REQUESTER_CONTEXT = "no-requester-context"

# ---------------------------------------------------------------------------
# Context binding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RequesterContext:
    """Transport-supplied identity of whoever triggered this work.

    Populated exclusively from ``gateway.session.SessionSource`` fields (or a
    ``requester_ref`` dict minted from one). Nothing here is ever taken from
    model output.
    """

    platform: str
    user_id: Optional[str] = None
    scope_id: Optional[str] = None
    chat_id: Optional[str] = None
    chat_type: str = "dm"
    thread_id: Optional[str] = None
    session_key: Optional[str] = None


_REQUESTER: contextvars.ContextVar[Optional[RequesterContext]] = contextvars.ContextVar(
    "team_authz_requester", default=None
)
# "transport" = bound from a live SessionSource; "ref" = rebound from a
# persisted reference (child, queued job, cron replay). Owner-only control
# planes require transport provenance.
_REQUESTER_PROVENANCE: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "team_authz_requester_provenance", default=None
)

_IDENTITY_FIELDS = (
    "platform",
    "user_id",
    "scope_id",
    "chat_id",
    "chat_type",
    "thread_id",
    "session_key",
)


def bind_requester(source_or_ref: Any) -> object:
    """Bind the requester for this context from a SessionSource or a ref dict.

    Returns an opaque token for :func:`reset_requester`.
    """
    if isinstance(source_or_ref, Mapping):
        ref = {k: source_or_ref.get(k) for k in _IDENTITY_FIELDS}
        ctx = RequesterContext(
            platform=str(ref.get("platform") or ""),
            user_id=ref.get("user_id"),
            scope_id=ref.get("scope_id"),
            chat_id=ref.get("chat_id"),
            chat_type=str(ref.get("chat_type") or "dm"),
            thread_id=ref.get("thread_id"),
            session_key=ref.get("session_key"),
        )
        provenance = "ref"
    else:
        platform = getattr(source_or_ref, "platform", "")
        ctx = RequesterContext(
            platform=str(getattr(platform, "value", platform) or ""),
            user_id=getattr(source_or_ref, "user_id", None),
            scope_id=getattr(source_or_ref, "scope_id", None),
            chat_id=getattr(source_or_ref, "chat_id", None),
            chat_type=str(getattr(source_or_ref, "chat_type", "dm") or "dm"),
            thread_id=getattr(source_or_ref, "thread_id", None),
            session_key=None,
        )
        provenance = "transport"
    t1 = _REQUESTER.set(ctx)
    t2 = _REQUESTER_PROVENANCE.set(provenance)
    return (t1, t2)


def reset_requester(token: object) -> None:
    t1, t2 = token  # type: ignore[misc]
    _REQUESTER.reset(t1)  # type: ignore[arg-type]
    _REQUESTER_PROVENANCE.reset(t2)  # type: ignore[arg-type]


def current_requester() -> Optional[RequesterContext]:
    return _REQUESTER.get()


def requester_ref(ctx: Optional[RequesterContext] = None) -> dict:
    """Identity fields only — safe to persist for queued/child work.

    Never carries grants: consumers must re-resolve at execution time.
    """
    ctx = ctx or current_requester()
    if ctx is None:
        return {}
    return {k: getattr(ctx, k) for k in _IDENTITY_FIELDS}


def _provenance() -> Optional[str]:
    return _REQUESTER_PROVENANCE.get()


# ---------------------------------------------------------------------------
# Decisions / principals
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""
    action: Optional[str] = None
    # Flat, human-facing refusal shown to the requester on a deny. Never
    # suggests an approval route. Enforcement points surface this verbatim.
    message: Optional[str] = None


@dataclass(frozen=True)
class Principal:
    member_key: str = ""
    discord_user_id: str = ""
    role: str = ""
    status: str = "unknown"
    capabilities: tuple = ()
    policy_version: str = ""
    # populated only for denied principals
    deny_reason: str = ""

    @property
    def is_owner(self) -> bool:
        return self.role == "owner" and self.status == "active"

    @property
    def denied(self) -> bool:
        return (self.status not in ("active", "ungoverned")) or bool(self.deny_reason)


class TeamAuthzDenied(Exception):
    """Raised where a denied principal must stop the caller outright."""


# ---------------------------------------------------------------------------
# Frozen action vocabulary + built-in core tool table
# ---------------------------------------------------------------------------

ACTION_OWNER_HOST = "owner.host"
ACTION_TEAM_DEFAULT = "team.default"
ROLE_OWNER = "owner"
ROLE_MANAGER = "manager"

# Mission hermes-team-policy-simplify-20260918 (T1): the built-in owner-host
# tool table is gone. An unmapped tool is ordinary team work; the immutable
# protected classes below are the only name-based denials left.
#
# Actions every active member implicitly holds. Capabilities in the register
# stay additive grants for business (mapped) tools — never reductions.
_IMPLICIT_TEAM_ACTIONS = frozenset({ACTION_TEAM_DEFAULT})

# Connection classes that deny for every non-owner regardless of mapping.
_DENIED_CONNECTION_CLASSES = ("personal", "infrastructure", "billing")

# Immutable protected resource classes (r3). Checked BEFORE any mutable
# ``toolActions`` mapping; register changes cannot weaken these patterns.
# Mission hermes-team-policy-simplify-20260918 (T1): exactly two name-based
# classes remain — credentials and the owner's personal mailbox.
_PROTECTED_CLASSES: tuple = (
    ("credentials", re.compile(
        r"(vault|password|passwd|credential|token|cookie|keychain|secret|1password)",
        re.IGNORECASE)),
    ("personal-mailbox", re.compile(r"(^email_|^mail_|gmail|outlook)", re.IGNORECASE)),
)

# Charles' browser rule (2026-09-17): sessions are for eyes, not keys.
# Teammates may VIEW/TEST client-work surfaces in owner-authenticated
# sessions. Hard stops for non-owners, checked from live tool arguments:
#   1. credential entry on the owner's behalf (login/2FA/vault unlock)
#   2. machine-information reads (files, env, tokens, cookies off the host)
_BROWSER_GUARD_DENY = (
    ("browser-login", re.compile(
        r"\b(password|passwd|credential|two.?factor|otp|verification.?code|"
        r"authenticator|signin|sign.?in|login|log.?in|mfa|2fa|pin|passcode)\b",
        re.IGNORECASE)),
    ("browser-machine-info", re.compile(
        r"(file://|~/.|/users/|/home/|c:\\|c:/|\.env|\.ssh|id_rsa|private.?key|"
        r"keychain|cookies?\.(txt|db|json)|places\.sqlite|login.?data|"
        r"localstorage|sessionstorage|indexeddb|document\.cookie|get.?cookie|"
        r"\bbearer\b|api.?key|access.?token|auth.?token|refresh.?token)",
        re.IGNORECASE)),
)


def _browser_guard(tool_name: str, args: Optional[Mapping]) -> Optional[str]:
    """Return a deny reason when a browser call crosses the private perimeter.

    Ordinary browser execution is team work; credential entry and
    machine-info reads stay hard denials for non-owners.
    """
    if not args:
        return None
    from agent.team_authz_perimeter import strings, browser_payload_denial
    text = " ".join(strings(args))
    for reason, rx in _BROWSER_GUARD_DENY:
        if rx.search(text):
            return reason
    return "browser-machine-info" if browser_payload_denial(args) else None

# toolActions patterns matching these are protected-tool remaps: invalid for
# every actor, owner included (built-ins already cover legitimate owner use).
_PROTECTED_PATTERN_RE = re.compile(
    r"(vault|password|passwd|credential|token|cookie|keychain|secret|1password|"
    r"browser|terminal|shell|execute_code|process_manage|http_request|proxy|"
    r"email_|mail_|gmail)",
    re.IGNORECASE,
)

# toolActions mapping fields that must stay scalar + non-secret.
_TOOLACTION_FIELDS = (
    "pattern", "action", "connectionId", "accountArg", "amountArg", "currencyArg",
)

_VALID_STATUSES = ("active", "inactive", "revoked")
_VALID_PERIODS = ("day", "week", "month")


def classify_protected(tool_name: str, args: Optional[Mapping] = None) -> Optional[str]:
    """Return the immutable protected class for a tool, or ``None``.

    Purely name/metadata based; never consults the mutable register, so a
    register edit cannot weaken it.
    """
    name = str(tool_name or "")
    for cls, rx in _PROTECTED_CLASSES:
        if rx.search(name):
            return cls
    return None


def classify_protected_call(tool_name: str, args: Optional[Mapping] = None) -> Optional[str]:
    """Protected class including argument-level browser guard.

    Browser-family verbs carry the argument guard (credential entry /
    machine-info read patterns); everything else is decided by name alone.
    """
    base = classify_protected(tool_name)
    if base is not None:
        return base
    if str(tool_name).startswith(("browser_", "camofox_")):
        return _browser_guard(tool_name, args)
    return None


# ---------------------------------------------------------------------------
# Config + register state (read at call time, re-statted every call)
# ---------------------------------------------------------------------------

_REGISTER_CACHE: dict = {}
# Monotonic counter for unique temp-file names under concurrent writers.
_TMP_SEQ = itertools.count()
# Cross-process + cross-thread mutation lock for register/spend mutations.
# File-lock based so multiple Hermes processes on one host serialize too.
# RLock (reentrant): the spend path holds the lock while audit() — which
# locks the audit sentinel — runs inside the same thread.
_MUTATION_LOCK = threading.RLock()


class _FileLock:
    """Advisory exclusive lock via O_CREAT|O_EXCL sentinel file.

    Simple, dependency-free, and cross-process on POSIX and Windows. Not
    crash-safe against a host power-loss (a stale sentinel may remain and
    require manual removal); crashes inside our short critical sections are
    rare and the register itself is written atomically after the lock.
    """

    def __init__(self, path: Path, timeout: float = 5.0):
        self.path = path
        self.timeout = timeout

    def __enter__(self):
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._fd = os.open(str(self.path),
                                   os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                return self
            except FileExistsError:
                if time.monotonic() > deadline:
                    # Stale-lock recovery: a sentinel older than the timeout
                    # window is assumed abandoned and removed once.
                    try:
                        st = os.stat(str(self.path))
                        if time.time() - st.st_mtime > self.timeout * 2:
                            os.unlink(str(self.path))
                            continue
                    except OSError:
                        pass
                    raise TimeoutError(f"lock-timeout:{self.path.name}")
                time.sleep(0.01)

    def __exit__(self, *exc):
        try:
            os.close(self._fd)
        finally:
            try:
                os.unlink(str(self.path))
            except OSError:
                pass
        return False


def _mutation_lock(path: Path):
    """Serialize register/approval/consent mutations across threads and processes.

    Thread lock first (fast path, same process), then the file sentinel for
    cross-process safety. Both writes and the spend-cap check-then-audit
    sequence must hold this lock (BLOCK-1/BLOCK-2).
    """
    return _ChainedLock(_MUTATION_LOCK, _FileLock(
        path.parent / (path.name + ".lock")))


class _ChainedLock:
    def __init__(self, *locks):
        self.locks = locks

    def __enter__(self):
        self.held = []
        try:
            for lk in self.locks:
                lk.__enter__()
                self.held.append(lk)
        except BaseException:
            for lk in reversed(self.held):
                lk.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *exc):
        for lk in reversed(self.held):
            lk.__exit__(*exc)
        return False
_AUDIT_REDACTED_KEYS = {
    "ts", "policyVersion", "event", "memberKey", "discordUserId", "scope",
    "tool", "action", "connectionId", "account", "amount", "currency",
    "decision", "reason", "approvalRef", "destination",
    "platform", "chatId", "threadId", "sessionKey", "summaryHash", "summaryBytes",
}


def register_path() -> Path:
    return get_hermes_home() / "team_authz" / "register.json"


def _audit_path() -> Path:
    return get_hermes_home() / "team_authz" / "audit.jsonl"


def _read_config_state() -> tuple:
    """(state, team_authz_block) with state in disabled|malformed|enabled."""
    import yaml

    cfg_path = get_hermes_home() / "config.yaml"
    try:
        if cfg_path.exists():
            with open(cfg_path, encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            if not isinstance(raw, Mapping):
                return ("malformed", None)
            block = raw.get("team_authz")
        else:
            block = None
    except Exception:
        return ("malformed", None)
    if block is None:
        return ("disabled", None)
    if not isinstance(block, Mapping):
        return ("malformed", None)
    enabled = block.get("enabled")
    platforms = block.get("governed_platforms")
    if not isinstance(enabled, bool) or (
        platforms is not None
        and (not isinstance(platforms, list) or not all(isinstance(p, str) for p in platforms))
    ):
        return ("malformed", None)
    mode = block.get("mode", "enforce")
    if mode not in ("enforce", "shadow"):
        return ("malformed", None)
    if not enabled and mode != "shadow":
        return ("disabled", block)
    return ("enabled", block)


def authorization_mode() -> str:
    """Shadow is a non-executing policy rehearsal, never an allow bypass."""
    state, block = _read_config_state()
    return str((block or {}).get("mode", "enforce")) if state == "enabled" else state


def _stat_key(path: Path) -> Optional[tuple]:
    try:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def _validate_register(data: Any) -> Optional[str]:
    """Return None when valid, else a human reason. Fail closed on doubt."""
    if not isinstance(data, Mapping):
        return "register-not-object"
    if data.get("schemaVersion") != 1:
        return "schema-version"
    if not isinstance(data.get("policyVersion"), str) or not data.get("policyVersion"):
        return "policy-version"
    members = data.get("members")
    roles = data.get("roles")
    if not isinstance(members, list) or not members:
        return "members-empty"
    if not isinstance(roles, Mapping) or not roles:
        return "roles-empty"
    seen_ids, seen_keys = set(), set()
    for m in members:
        if not isinstance(m, Mapping):
            return "member-not-object"
        for k in ("discordUserId", "memberKey", "role", "status", "approvedBy", "approvedAt"):
            if not isinstance(m.get(k), str):
                return f"member-field:{k}"
        if m["status"] not in _VALID_STATUSES:
            return "member-status"
        if m["role"] not in roles:
            return "member-role-unknown"
        if not m["discordUserId"] or not m["memberKey"]:
            return "member-identity-empty"
        if m["discordUserId"] in seen_ids or m["memberKey"] in seen_keys:
            return "member-identity-duplicate"
        seen_ids.add(m["discordUserId"])
        seen_keys.add(m["memberKey"])
    for role_name, role_def in roles.items():
        if not isinstance(role_def, Mapping):
            return "role-not-object"
        caps = role_def.get("capabilities")
        if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
            return "role-capabilities"
        if ACTION_OWNER_HOST in caps and role_name != ROLE_OWNER:
            return "owner-host-grant-outside-owner"
    ta = data.get("toolActions")
    if not isinstance(ta, list):
        return "toolactions"
    for row in ta:
        if not isinstance(row, Mapping):
            return "toolaction-not-object"
        if not isinstance(row.get("pattern"), str) or not isinstance(row.get("action"), str):
            return "toolaction-fields"
        if _PROTECTED_PATTERN_RE.search(row["pattern"]):
            return "toolaction-protected-remap"
    conns = data.get("connections")
    if not isinstance(conns, list):
        return "connections"
    caps = data.get("spendingCaps")
    if not isinstance(caps, list):
        return "spendingcaps"
    for row in caps:
        if not isinstance(row, Mapping):
            return "cap-not-object"
        if row.get("period") not in _VALID_PERIODS:
            return "cap-period"
    oversight = data.get("oversight")
    if not isinstance(oversight, Mapping) or not isinstance(oversight.get("destinations"), list):
        return "oversight"
    return None


def _load_register() -> tuple:
    """(register_dict|None, error_reason|None). Missing/invalid ⇒ (None, reason)."""
    path = register_path()
    key = _stat_key(path)
    if key is None:
        return (None, "register-missing")
    cached = _REGISTER_CACHE.get(str(path))
    if cached is not None and cached[0] == key:
        return cached[1], cached[2]
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        _REGISTER_CACHE[str(path)] = (key, None, f"register-unreadable:{type(exc).__name__}")
        return (None, f"register-unreadable:{type(exc).__name__}")
    reason = _validate_register(data)
    if reason is not None:
        _REGISTER_CACHE[str(path)] = (key, None, f"register-invalid:{reason}")
        return (None, f"register-invalid:{reason}")
    _REGISTER_CACHE[str(path)] = (key, data, None)
    return (data, None)


def _atomic_write_json(path: Path, data: Mapping) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Unique temp name per call: PID + thread id + monotonic counter, so
    # concurrent writers never collide on the same temp file (BLOCK-2).
    tmp = path.with_name(
        f"{path.name}.tmp{os.getpid()}.{threading.get_ident()}.{next(_TMP_SEQ)}")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def audit(event: Mapping) -> bool:
    """Append one redacted, hash-chained audit row. Returns False on failure.

    Tamper-evident: each row carries the previous row's hash in ``prev`` and
    its own ``h`` = sha256 over the canonical row without ``h``. The
    read-prev + append pair runs under the mutation lock (thread + file) so
    concurrent writers cannot fork the chain (Opus review B2).
    """
    row = {k: v for k, v in event.items() if k in _AUDIT_REDACTED_KEYS}
    # Denied calls may contain arbitrary text in amount/currency fields.
    # Keep useful structured spend evidence, never the rejected raw value.
    if "amount" in row:
        value = row["amount"]
        try:
            number = float(value) if not isinstance(value, bool) else math.nan
        except (TypeError, ValueError, OverflowError):
            number = math.nan
        row["amount"] = number if math.isfinite(number) and number >= 0 else None
    if "currency" in row:
        currency = row["currency"]
        if not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency):
            row["currency"] = None
    row.setdefault("ts", datetime.now(timezone.utc).isoformat(timespec="seconds"))
    if row.get("event") == "authorize" and authorization_mode() == "shadow":
        row["event"] = "shadow"
        row["decision"] = "would-" + str(row.get("decision", "denied"))
    try:
        p = _audit_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        with _mutation_lock(p):
            valid, _, prev, count = _audit_state(p)
            if not valid:
                return False
            row["prev"] = prev
            row["h"] = hashlib.sha256(
                json.dumps({k: v for k, v in row.items() if k != "h"},
                           ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest()
            with open(p, "a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
            _atomic_write_json(p.with_suffix(".head.json"),
                               {"schemaVersion": 1, "count": count + 1, "hash": row["h"]})
        try:  # owner-only read on POSIX; best-effort on Windows
            os.chmod(p, 0o600)
        except Exception:
            pass
        return True
    except Exception:
        return False


def _audit_state(path: Path) -> tuple:
    """Validate chain AND durable head; caller holds the audit mutation lock.

    The separately replaced head detects tail/whole-log deletion. A crash
    between fsync and checkpoint replacement fails closed, never self-reseals.
    An administrator able to rewrite both files is outside this local threat
    model; external immutable storage is still required against that actor.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        head_path = path.with_suffix(".head.json")
        head = json.loads(head_path.read_text(encoding="utf-8")) if head_path.exists() else None
        prev = ""
        for i, line in enumerate(lines, 1):
            row = json.loads(line)
            if row.get("prev") != prev:
                return False, i, prev, i - 1
            expect = hashlib.sha256(json.dumps(
                {k: v for k, v in row.items() if k != "h"},
                ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
            if row.get("h") != expect:
                return False, i, prev, i - 1
            prev = row["h"]
        count = len(lines)
        if head is None:
            return not lines, 1 if lines else None, prev, count
        if head != {"schemaVersion": 1, "count": count, "hash": prev}:
            return False, count + 1, prev, count
        return True, None, prev, count
    except Exception:
        return False, 1, "", 0


def audit_verify() -> tuple:
    """(ok, first_broken_line_or_None), including deletion and truncation."""
    try:
        path = _audit_path()
        with _mutation_lock(path):
            valid, broken, _, _ = _audit_state(path)
            return valid, broken
    except Exception:
        return False, 1


def log_inbound(ctx: Optional[RequesterContext] = None,
                summary: str = "") -> bool:
    """Record WHO sent a message BEFORE any tool may run for it.

    Returns False when the append failed — callers must treat that as a deny
    (no tool executes without its trail entry).
    """
    ctx = ctx or current_requester()
    try:
        if not is_governed(ctx):
            return True  # ungoverned surfaces keep base behaviour
        principal = resolve_principal(ctx)
        # The audit identifies the request without copying its potentially
        # secret-bearing text into a second persistent store.
        summary_bytes = str(summary or "").encode("utf-8")
        return audit({
            "event": "message",
            "memberKey": principal.member_key,
            "discordUserId": ctx.user_id if ctx else None,
            "scope": ctx.scope_id if ctx else None,
            "platform": ctx.platform if ctx else None,
            "chatId": ctx.chat_id if ctx else None,
            "threadId": ctx.thread_id if ctx else None,
            "sessionKey": ctx.session_key if ctx else None,
            "decision": "received",
            "reason": "inbound-received",
            "summaryHash": hashlib.sha256(summary_bytes).hexdigest(),
            "summaryBytes": len(summary_bytes),
        })
    except Exception:
        return False


def _read_audit_rows() -> list:
    try:
        with open(_audit_path(), encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        return []


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _period_start(period: str, now: datetime) -> datetime:
    if period == "day":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "week":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return start - timedelta(days=start.weekday())
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


# ---------------------------------------------------------------------------
# Governed / principal resolution
# ---------------------------------------------------------------------------


def _env_platform() -> str:
    return str(os.environ.get("HERMES_SESSION_PLATFORM") or "").strip().lower()


def is_governed(ctx: Optional[RequesterContext] = None) -> bool:
    """True when this request is subject to team authorization.

    Malformed config counts as governed for any request that carries a
    platform (fail closed, never silently ungoverned).
    """
    try:
        state, block = _read_config_state()
        if state == "disabled":
            return False
        ctx = ctx or current_requester()
        platform = (ctx.platform if ctx else "") or _env_platform()
        if not platform:
            return False
        if state == "malformed":
            return True
        platforms = (block or {}).get("governed_platforms") or ["discord"]
        return platform.lower() in [str(p).lower() for p in platforms]
    except Exception:
        return True


def resolve_principal(ctx: Optional[RequesterContext] = None) -> Principal:
    """Never raises; failure returns a denied principal carrying the reason."""
    try:
        if not is_governed(ctx):
            return Principal(status="ungoverned", deny_reason="")
        ctx = ctx or current_requester()
        if ctx is None or not ctx.user_id:
            return Principal(deny_reason=DENY_NO_REQUESTER_CONTEXT)
        # Malformed config: every governed request denies, owner included.
        state, _block = _read_config_state()
        if state == "malformed":
            return Principal(deny_reason="config-malformed")
        reg, err = _load_register()
        if reg is None:
            return Principal(deny_reason=err or "register-invalid")
        member = None
        for m in reg["members"]:
            if m["discordUserId"] == ctx.user_id:
                member = m
                break
        if member is None:
            return Principal(deny_reason="unknown-identity", discord_user_id=ctx.user_id)
        if member["status"] != "active":
            return Principal(
                member_key=member["memberKey"],
                discord_user_id=member["discordUserId"],
                role=member["role"],
                status=member["status"],
                deny_reason=f"member-{member['status']}",
            )
        if ctx.scope_id and ctx.scope_id not in reg.get("guilds", []):
            return Principal(
                member_key=member["memberKey"],
                discord_user_id=member["discordUserId"],
                role=member["role"],
                status="active",
                policy_version=reg["policyVersion"],
                deny_reason="scope-not-listed",
            )
        caps = tuple(reg["roles"].get(member["role"], {}).get("capabilities", []))
        return Principal(
            member_key=member["memberKey"],
            discord_user_id=member["discordUserId"],
            role=member["role"],
            status="active",
            capabilities=caps,
            policy_version=reg["policyVersion"],
        )
    except Exception as exc:
        return Principal(deny_reason=f"policy-error:{type(exc).__name__}")


def grant_digest(ctx: Optional[RequesterContext] = None) -> str:
    """Stable digest of the effective grant; changes on revoke/role/policy bump."""
    p = resolve_principal(ctx)
    basis = "|".join([
        p.member_key, p.role, p.status, p.policy_version,
        ",".join(sorted(p.capabilities)),
    ])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Tool authorization
# ---------------------------------------------------------------------------


def _tool_action(tool_name: str, reg: Mapping, args: Optional[Mapping]) -> Optional[tuple]:
    """(action, toolActions_row|None) or None when unmapped. toolActions win."""
    for row in reg.get("toolActions", []):
        if fnmatch.fnmatchcase(tool_name, row["pattern"]):
            return row["action"], row
    return None


def _connection_check(action: str, row: Optional[Mapping], reg: Mapping,
                      principal: Principal, args: Mapping) -> Optional[str]:
    """None when OK, else deny reason. Personal/infra/billing deny non-owners."""
    if row is None or not row.get("connectionId"):
        return None
    conn = None
    for c in reg.get("connections", []):
        if c.get("id") == row["connectionId"]:
            conn = c
            break
    if conn is None:
        return "connection-unknown"
    if not principal.is_owner:
        if conn.get("ownerClass") != "business":
            return "connection-class-denied"
        if action not in conn.get("actions", []):
            return "connection-action-not-listed"
        if row.get("accountArg"):
            account = args.get(row["accountArg"])
            if not account or account != conn.get("account"):
                return "connection-account-mismatch"
    return None


def _cap_check(tool_name: str, row: Optional[Mapping], reg: Mapping, principal: Principal,
               args: Mapping) -> Optional[str]:
    if row is None or not row.get("amountArg"):
        return None
    # Caller (authorize_tool) holds _mutation_lock during the cap
    # check + audit append so two concurrent spends cannot both pass
    # against the same period aggregate (BLOCK-1 TOCTOU).
    amount_arg = row["amountArg"]
    if amount_arg not in args:
        return "cap-amount-missing"
    try:
        if isinstance(args[amount_arg], bool):
            return "cap-amount-unparsable"
        amount = float(args[amount_arg])
    except (TypeError, ValueError):
        return "cap-amount-unparsable"
    if not math.isfinite(amount) or amount < 0:
        return "cap-amount-unparsable"
    account = str(args.get(row["accountArg"], "")) if row.get("accountArg") else ""
    currency = str(args.get(row["currencyArg"], "")) if row.get("currencyArg") else ""
    if not account or not currency:
        return "cap-target-missing"
    cap = None
    for c in reg.get("spendingCaps", []):
        if (
            c.get("memberKey") == principal.member_key
            and c.get("connectionId") == row.get("connectionId")
            and c.get("account") == account
        ):
            cap = c
            break
    if cap is None:
        return "cap-missing"
    if cap.get("currency") != currency:
        return "cap-currency-mismatch"
    limit = float(cap["amount"])
    if isinstance(cap["amount"], bool) or not math.isfinite(limit) or limit < 0:
        return "cap-invalid"
    if amount > limit:
        return "cap-exceeded"
    # period aggregate of previously allowed amounts + this amount
    now = _utcnow()
    start = _period_start(cap["period"], now)
    total = amount
    for r in _read_audit_rows():
        if (
            r.get("memberKey") == principal.member_key
            and r.get("connectionId") == row.get("connectionId")
            and r.get("account") == account
            and r.get("currency") == currency
            and r.get("decision") == "allowed"
            and r.get("amount") is not None
        ):
            ts = datetime.fromisoformat(str(r.get("ts", "")))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= start:
                previous = float(r["amount"])
                if isinstance(r["amount"], bool) or not math.isfinite(previous) or previous < 0:
                    return "cap-audit-invalid"
                total += previous
    if total > limit:
        return "cap-exceeded"
    return None



# Deny reasons → what the requester actually sees. Mission
# hermes-team-policy-simplify-20260918 (T1): every refusal is a flat "I can't"
# sentence with no approval route (operator D1 resolution, 2026-09-18: unknown
# requesters keep the register identity boundary).
_DENY_MESSAGES: tuple = (
    ("protected:browser-login",
     "I can't log in as Charles or enter credentials on his behalf."),
    ("protected:browser-machine-info",
     "I can't read files or saved data from Charles' machine."),
    ("protected:",
     "I can't touch Charles' private accounts or resources."),
    ("unknown-identity",
     "I can't take requests from this account."),
)
_DENY_FALLBACK_MESSAGE = "I can't do that with the access this team surface has."


def _deny_message(reason: str) -> Optional[str]:
    r = str(reason or "")
    for prefix, msg in _DENY_MESSAGES:
        if r.startswith(prefix):
            return msg
    return _DENY_FALLBACK_MESSAGE


def _audit_event(principal: Principal, ctx: Optional[RequesterContext], **kw) -> dict:
    ev = {
        "event": kw.pop("event", "authorize"),
        "policyVersion": principal.policy_version or "",
        "memberKey": principal.member_key,
        "discordUserId": principal.discord_user_id,
        "scope": ctx.scope_id if ctx else None,
    }
    ev.update(kw)
    return ev


def authorize_tool(tool_name: str, args: Optional[Mapping] = None,
                   ctx: Optional[RequesterContext] = None, *, reserve: bool = True) -> Decision:
    """Private-perimeter-first authorization. Any exception ⇒ deny policy-error.

    Order (r3): governed → principal → protected owner resource (immutable
    built-ins, exact owner approval only) → action mapping (toolActions then
    built-ins) → role capability → connection class → spend cap → audit.
    """
    args = args or {}
    try:
        if not is_governed(ctx):
            return Decision(True, "ungoverned")
        principal = resolve_principal(ctx)
        base = {
            "tool": tool_name,
            "memberKey": principal.member_key,
            "discordUserId": principal.discord_user_id,
        }
        if principal.denied:
            audit({**_audit_event(principal, ctx, **base), "decision": "denied",
                   "reason": principal.deny_reason})
            return Decision(False, principal.deny_reason,
                            message=_deny_message(principal.deny_reason))

        reg, err = _load_register()
        if reg is None:
            audit({**_audit_event(principal, ctx, **base), "decision": "denied",
                   "reason": err or "register-invalid"})
            return Decision(False, err or "register-invalid")

        from agent.team_authz_owner import check_protected_for_tool

        protected = check_protected_for_tool(tool_name, args, principal, reg, ctx)
        if protected is not None:
            audit({**_audit_event(principal, ctx, **base), "decision": "denied",
                   "reason": protected, "action": "protected"})
            return Decision(False, protected, "protected",
                            message=_deny_message(protected))

        mapped = _tool_action(tool_name, reg, args)
        if mapped is None:
            # Default-open team lane (Charles 2026-09-17): unmapped tools are
            # ordinary work. Protected classes were already denied above.
            mapped = (ACTION_TEAM_DEFAULT, None)
        action, row = mapped

        # BLOCK-1: cap check reads the period aggregate from the audit trail
        # and the allow appends to it — serialize the whole tail (checks +
        # audit) under the mutation lock when a spend is involved, so two
        # concurrent spends cannot both pass against the same aggregate.
        cap_lock = row is not None and bool(row.get("amountArg"))
        if cap_lock:
            with _mutation_lock(register_path()):
                return _authorize_tail(
                    tool_name, args, ctx, principal, reg, action, row, base, reserve)
        return _authorize_tail(
            tool_name, args, ctx, principal, reg, action, row, base, reserve)
    except Exception as exc:
        try:
            audit({"event": "authorize", "tool": tool_name, "decision": "denied",
                   "reason": f"policy-error:{type(exc).__name__}"})
        except Exception:
            pass
        return Decision(False, f"policy-error:{type(exc).__name__}")


def _authorize_tail(tool_name: str, args: Mapping,
                    ctx: Optional[RequesterContext], principal: Principal,
                    reg: Mapping, action: str, row: Optional[Mapping],
                    base: dict, reserve: bool = True) -> Decision:
    if (
        not principal.is_owner
        and action not in principal.capabilities
        and action not in _IMPLICIT_TEAM_ACTIONS
    ):
        audit({**_audit_event(principal, ctx, **base), "decision": "denied",
               "reason": "role-missing-action", "action": action})
        return Decision(False, "role-missing-action", action,
                        message=_deny_message("role-missing-action"))

    conn_reason = _connection_check(action, row, reg, principal, args)
    if conn_reason:
        audit({**_audit_event(principal, ctx, **base), "decision": "denied",
               "reason": conn_reason, "action": action,
               "connectionId": (row or {}).get("connectionId")})
        return Decision(False, conn_reason, action,
                        message=_deny_message(conn_reason))

    cap_reason = _cap_check(tool_name, row, reg, principal, args)
    if cap_reason:
        audit({**_audit_event(principal, ctx, **base), "decision": "denied",
               "reason": cap_reason, "action": action,
               "connectionId": (row or {}).get("connectionId"),
               "account": (args.get(row["accountArg"]) if row and row.get("accountArg") else None),
               "amount": (args.get(row["amountArg"]) if row and row.get("amountArg") else None),
               "currency": (args.get(row["currencyArg"]) if row and row.get("currencyArg") else None)})
        return Decision(False, cap_reason, action,
                        message=_deny_message(cap_reason))

    ev = _audit_event(
        principal, ctx, tool=tool_name, action=action,
        connectionId=(row or {}).get("connectionId"),
        account=(args.get(row["accountArg"]) if row and row.get("accountArg") else None),
        amount=(args.get(row["amountArg"]) if row and row.get("amountArg") else None),
        currency=(args.get(row["currencyArg"]) if row and row.get("currencyArg") else None),
    )
    if not audit({**ev, "decision": "allowed" if reserve else "checked", "reason": "ok"}):
        return Decision(False, "audit-failure", action)
    return Decision(True, "ok", action)


def filter_tool_names(names: Iterable[str], ctx: Optional[RequesterContext] = None) -> set:
    """Discovery filter: names authorize_tool could allow for this role.

    Arg-dependent checks (connection/cap/protected) are NOT decided here —
    execution re-checks with real arguments.
    """
    out = set()
    try:
        if not is_governed(ctx):
            return set(names)
        principal = resolve_principal(ctx)
        if principal.denied:
            return set()
        reg, _err = _load_register()
        if reg is None:
            return set()
        for name in names:
            mapped = _tool_action(name, reg, None)
            # Default-open (T1): unmapped tools are ordinary team work —
            # visible; only the protected classes stay hidden.
            action = mapped[0] if mapped else ACTION_TEAM_DEFAULT
            if classify_protected(name) and not principal.is_owner:
                continue
            if (
                not principal.is_owner
                and action not in principal.capabilities
                and action not in _IMPLICIT_TEAM_ACTIONS
            ):
                continue
            out.add(name)
        return out
    except Exception:
        return set()


# ---------------------------------------------------------------------------
# History / memory / destinations
# ---------------------------------------------------------------------------


def _row_get(row: Mapping, key: str) -> Any:
    if isinstance(row, Mapping):
        return row.get(key)
    return getattr(row, key, None)


def can_read_session(session_row: Mapping, *, destination: Optional[Mapping] = None,
                     ctx: Optional[RequesterContext] = None) -> Decision:
    """Per-row history read decision. Denied rows are indistinguishable from absent."""
    try:
        if not is_governed(ctx):
            return Decision(True, "ungoverned")
        principal = resolve_principal(ctx)
        if principal.denied:
            return Decision(False, principal.deny_reason)

        reg, err = _load_register()
        if reg is None:
            return Decision(False, err or "register-invalid")

        row_platform = str(_row_get(session_row, "platform") or "")
        row_user = _row_get(session_row, "user_id") or _row_get(session_row, "userId")
        row_profile = _row_get(session_row, "profile")

        owner_ids = _owner_ids(reg)

        # Owner-class rows and explicit profile reads: owner only.
        if row_profile:
            return Decision(True, "owner") if principal.is_owner else Decision(False, "owner-only-profile")
        if not row_user:
            if principal.is_owner:
                return Decision(True, "owner-unknown-row")
            return Decision(False, "owner-only-unknown-owner")
        if row_user in owner_ids:
            return Decision(True, "owner") if principal.is_owner else Decision(False, "owner-only")
        platforms = (reg.get("_governed_platforms") or ["discord"])
        if row_platform and row_platform.lower() not in [p.lower() for p in platforms]:
            return Decision(True, "owner") if principal.is_owner else Decision(False, "owner-only-platform")

        # Own session.
        ctx = ctx or current_requester()
        if ctx and ctx.user_id == row_user and ctx.platform.lower() == row_platform.lower():
            return Decision(True, "own")

        # Current shared conversation.
        if ctx:
            row_chat = _row_get(session_row, "chat_id") or _row_get(session_row, "chatId")
            row_thread = _row_get(session_row, "thread_id") or _row_get(session_row, "threadId")
            if row_chat and row_chat == ctx.chat_id:
                if (row_thread or None) == (ctx.thread_id or None):
                    return Decision(True, "shared-conversation")

        # Another member's private session: oversight holders only.
        if principal.is_owner or "history.oversight" in principal.capabilities:
            dest_ok = False
            dest_chat = (destination or {}).get("chatId")
            if ctx and ctx.chat_type == "dm" and dest_chat and dest_chat == ctx.chat_id:
                dest_ok = True
            if dest_chat and any(
                d.get("chatId") == dest_chat for d in reg.get("oversight", {}).get("destinations", [])
            ):
                dest_ok = True
            if dest_ok:
                if audit(_audit_event(
                    principal, ctx, event="oversight",
                    decision="allowed", reason="oversight",
                    destination=dest_chat,
                )):
                    return Decision(True, "oversight")
                return Decision(False, "audit-failure")
            return Decision(False, "oversight-destination-denied")
        return Decision(False, "not-own-session")
    except Exception as exc:
        return Decision(False, f"policy-error:{type(exc).__name__}")


def _owner_ids(reg: Mapping) -> set:
    ids = set()
    oi = reg.get("ownerIdentity")
    if isinstance(oi, Mapping) and oi.get("discordUserId"):
        ids.add(oi["discordUserId"])
    for m in reg.get("members", []):
        if m.get("role") == ROLE_OWNER:
            ids.add(m.get("discordUserId"))
    return ids


def memory_namespace(ctx: Optional[RequesterContext] = None) -> Optional[str]:
    """None for ungoverned/owner (configured id stays); team-<memberKey> else.

    Denied principals raise TeamAuthzDenied — callers must not initialise
    recall.
    """
    if not is_governed(ctx):
        return None
    principal = resolve_principal(ctx)
    if principal.denied:
        raise TeamAuthzDenied(principal.deny_reason)
    if principal.is_owner:
        return None
    return f"team-{principal.member_key}"


def may_send_to(target: Mapping, ctx: Optional[RequesterContext] = None) -> Decision:
    """Non-owners may address only the originating chat/thread."""
    try:
        if not is_governed(ctx):
            return Decision(True, "ungoverned")
        principal = resolve_principal(ctx)
        if principal.denied:
            return Decision(False, principal.deny_reason)
        if principal.is_owner:
            return Decision(True, "owner")
        ctx = ctx or current_requester()
        if ctx is None:
            return Decision(False, DENY_NO_REQUESTER_CONTEXT)
        t_chat = (target or {}).get("chatId") or (target or {}).get("chat_id")
        t_thread = (target or {}).get("threadId") or (target or {}).get("thread_id")
        if t_chat and t_chat == ctx.chat_id and (t_thread or None) == (ctx.thread_id or None):
            return Decision(True, "originating-chat")
        return Decision(False, "destination-outside-origin")
    except Exception as exc:
        return Decision(False, f"policy-error:{type(exc).__name__}")


# ---------------------------------------------------------------------------
# Register change control
# ---------------------------------------------------------------------------


def _next_policy_version(current: str) -> str:
    try:
        base, _, n = current.rpartition(".")
        return f"{base}.{int(n) + 1}" if n.isdigit() else f"{current}.1"
    except Exception:
        return f"{current}.1"


def apply_register_change(change: Mapping, ctx: Optional[RequesterContext] = None) -> Decision:
    """Structured, audited register mutations. ``register.change`` holders only.

    Owner/manager boundaries (r1 §3.3 + r3): a manager cannot create/alter
    owner or manager members, grant ``owner.host``, or add a personal
    connection. Nobody can weaken protected classes, remap protected tools,
    relabel personal resources as business (non-owner), edit owner approvals
    or consents, or disable the guard through this API.
    """
    try:
        if not is_governed(ctx):
            return Decision(False, "ungoverned-no-changes")
        principal = resolve_principal(ctx)
        if principal.denied:
            return Decision(False, principal.deny_reason)
        reg, err = _load_register()
        if reg is None:
            return Decision(False, err or "register-invalid")

        if not principal.is_owner and "register.change" not in principal.capabilities:
            audit(_audit_event(principal, ctx, event="register-change",
                               decision="denied", reason="role-missing-action"))
            return Decision(False, "role-missing-action")

        from agent.team_authz_owner import check_register_change_protected

        guarded = check_register_change_protected(change, principal, reg)
        if guarded is not None:
            audit(_audit_event(principal, ctx, event="register-change",
                               decision="denied", reason=guarded,
                               action=change.get("kind")))
            return Decision(False, guarded)

        kind = change.get("kind")
        new_reg = json.loads(json.dumps(reg))  # deep copy without stdlib-less tricks
        action_label = kind

        if kind == "member.upsert":
            payload = change.get("payload", {})
            new_reg["members"] = [
                m for m in new_reg["members"]
                if m.get("discordUserId") != payload.get("discordUserId")
            ]
            new_reg["members"].append({
                "discordUserId": str(payload.get("discordUserId", "")),
                "memberKey": str(payload.get("memberKey", "")),
                "role": str(payload.get("role", "")),
                "status": str(payload.get("status", "active")),
                "approvedBy": principal.discord_user_id,
                "approvedAt": _utcnow().isoformat(timespec="seconds"),
            })
        elif kind == "member.remove":
            payload = change.get("payload", {})
            if payload.get("discordUserId") in _owner_ids(reg):
                audit(_audit_event(principal, ctx, event="register-change",
                                   decision="denied", reason="owner-immutable",
                                   action=kind))
                return Decision(False, "owner-immutable")
            new_reg["members"] = [
                m for m in new_reg["members"]
                if m.get("discordUserId") != payload.get("discordUserId")
            ]
        elif kind == "role.grant":
            payload = change.get("payload", {})
            role = str(payload.get("role", ""))
            cap = str(payload.get("capability", ""))
            if cap == ACTION_OWNER_HOST and role != ROLE_OWNER:
                audit(_audit_event(principal, ctx, event="register-change",
                                   decision="denied", reason="owner-host-grant-outside-owner",
                                   action=kind))
                return Decision(False, "owner-host-grant-outside-owner")
            caps = new_reg["roles"].setdefault(role, {"capabilities": []})["capabilities"]
            if cap and cap not in caps:
                caps.append(cap)
        elif kind == "toolaction.upsert":
            payload = dict(change.get("payload", {}))
            payload = {k: payload.get(k) for k in _TOOLACTION_FIELDS if payload.get(k) is not None}
            new_reg["toolActions"] = [
                t for t in new_reg["toolActions"] if t.get("pattern") != payload.get("pattern")
            ]
            new_reg["toolActions"].append(payload)
        elif kind == "connection.upsert":
            payload = dict(change.get("payload", {}))
            existing = next((c for c in new_reg["connections"]
                             if c.get("id") == payload.get("id")), None)
            if existing and existing.get("ownerClass") == "personal" \
                    and payload.get("ownerClass") == "business" and not principal.is_owner:
                audit(_audit_event(principal, ctx, event="register-change",
                                   decision="denied", reason="relabel-personal-denied",
                                   action=kind))
                return Decision(False, "relabel-personal-denied")
            if not existing and payload.get("ownerClass") == "personal" and not principal.is_owner:
                audit(_audit_event(principal, ctx, event="register-change",
                                   decision="denied", reason="personal-connection-denied",
                                   action=kind))
                return Decision(False, "personal-connection-denied")
            new_reg["connections"] = [
                c for c in new_reg["connections"] if c.get("id") != payload.get("id")
            ]
            new_reg["connections"].append({
                "id": str(payload.get("id", "")),
                "connector": str(payload.get("connector", "")),
                "account": str(payload.get("account", "")),
                "ownerClass": str(payload.get("ownerClass", "business")),
                "actions": list(payload.get("actions", [])),
            })
        elif kind == "cap.upsert":
            payload = change.get("payload", {})
            existing = next((c for c in new_reg["spendingCaps"]
                             if c.get("memberKey") == payload.get("memberKey")
                             and c.get("connectionId") == payload.get("connectionId")
                             and c.get("account") == payload.get("account")), None)
            try:
                new_amount = float(payload.get("amount", 0))
            except (TypeError, ValueError):
                return Decision(False, "cap-amount-unparsable")
            if existing and new_amount > float(existing.get("amount", 0)):
                if not principal.is_owner and "cap.increase" not in principal.capabilities:
                    audit(_audit_event(principal, ctx, event="register-change",
                                       decision="denied", reason="role-missing-action",
                                       action="cap.increase"))
                    return Decision(False, "role-missing-action")
                action_label = "cap.increase"
            new_reg["spendingCaps"] = [
                c for c in new_reg["spendingCaps"]
                if not (c.get("memberKey") == payload.get("memberKey")
                        and c.get("connectionId") == payload.get("connectionId")
                        and c.get("account") == payload.get("account"))
            ]
            new_reg["spendingCaps"].append({
                "memberKey": str(payload.get("memberKey", "")),
                "connectionId": str(payload.get("connectionId", "")),
                "account": str(payload.get("account", "")),
                "currency": str(payload.get("currency", "")),
                "period": str(payload.get("period", "month")),
                "amount": new_amount,
                "scope": str(payload.get("scope", "")),
                "approvedBy": principal.discord_user_id,
                "approvedAt": _utcnow().isoformat(timespec="seconds"),
            })
        elif kind == "oversight.destination.add":
            payload = change.get("payload", {})
            dests = new_reg.setdefault("oversight", {"destinations": []})["destinations"]
            dests.append({"chatId": str(payload.get("chatId", ""))})
        else:
            audit(_audit_event(principal, ctx, event="register-change",
                               decision="denied", reason="unknown-change-kind",
                               action=str(kind)))
            return Decision(False, "unknown-change-kind")

        reason = _validate_register(new_reg)
        if reason is not None:
            audit(_audit_event(principal, ctx, event="register-change",
                               decision="denied", reason=f"invalid-result:{reason}",
                               action=action_label))
            return Decision(False, f"invalid-result:{reason}")

        new_reg["policyVersion"] = _next_policy_version(reg["policyVersion"])
        # BLOCK-2: read→validate→write under the mutation lock so two
        # concurrent register changes cannot silently drop each other.
        with _mutation_lock(register_path()):
            current, cur_err = _load_register()
            if current is None or json.dumps(current, sort_keys=True) != json.dumps(reg, sort_keys=True):
                return Decision(False, "register-conflict-retry")
            _atomic_write_json(register_path(), new_reg)
            if not audit(_audit_event(
                principal, ctx, event="register-change", decision="allowed",
                reason="ok", action=action_label,
                connectionId=(change.get("payload", {}) or {}).get("connectionId"),
                account=(change.get("payload", {}) or {}).get("account"),
            )):
                _atomic_write_json(register_path(), reg)  # roll back; audit is required
                return Decision(False, "audit-failure")
        return Decision(True, "ok")
    except Exception as exc:
        try:
            audit({"event": "register-change", "decision": "denied",
                   "reason": f"policy-error:{type(exc).__name__}"})
        except Exception:
            pass
        return Decision(False, f"policy-error:{type(exc).__name__}")
