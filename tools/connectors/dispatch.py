"""Route connector calls through the normal dispatch policy pipeline."""

import json
from dataclasses import asdict

from tools.registry import tool_error
from tools.connectors.gateway.config import MAX_CALLS_PER_DISPATCH
from tools.connectors.gateway.merge import assemble_results, fill_remote_failure, partition_calls


def dispatch_connector_call(name, arguments, tool_call_id):
    from model_tools import team_authz_denied, team_authz_deny_text
    from tools.connectors.gateway.bridge import run_remote

    # Final protected-owner recheck at the real connector boundary (D1: owner
    # bit from verified provenance only; D3: approval audit precedes dispatch).
    # Batch entries re-enter handle_function_call per item; this covers direct
    # remote dispatch and any post-guard argument transformation. An unmapped
    # connector is ordinary team work (T1): no target-inventory denial here.
    denied = team_authz_denied(name, arguments if isinstance(arguments, dict) else {})
    if denied is not None:
        return json.dumps({"error": team_authz_deny_text(denied)}, ensure_ascii=False)

    partition = partition_calls([{"name": name, "arguments": arguments}])
    if not partition.remote:
        # Malformed connector tool name (base partitioning error): blocked
        # work, never retried through browser or login tools.
        detail = ""
        if partition.errors:
            first = partition.errors[0]
            detail = str((first.get("error") or {}).get("message") or first.get("error") or "")
        return json.dumps({"error": f"Connector call blocked: malformed connector target {name!r}."
                                    + (f" {detail}" if detail else "")}, ensure_ascii=False)
    denied = team_authz_denied(name, arguments, reserve=True)
    if denied is not None:
        return json.dumps({"error": team_authz_deny_text(denied)}, ensure_ascii=False)
    entries = run_remote(partition.remote, tool_call_id, availability=None, client_factory=None)
    entry = entries[0]
    return json.dumps({key: value for key, value in entry.items() if key in {"response", "error"}},
                      ensure_ascii=False)


def dispatch_connector_batch(calls, ids, *, user_task, enabled_tools,
                             middleware_trace, enabled_toolsets, disabled_toolsets):
    from model_tools import handle_function_call
    from tools.interrupt import is_interrupted

    if len(calls) > MAX_CALLS_PER_DISPATCH:
        return tool_error(f"too many calls: {len(calls)} > max {MAX_CALLS_PER_DISPATCH}. "
                          "Retry with fewer calls per batch.")
    partition = partition_calls(calls)
    if partition.local:
        from tools.tool_search_validation import local_batch_error
        return tool_error(local_batch_error(calls))
    entries = list(partition.errors)
    for offset, plan in enumerate(partition.remote):
        if is_interrupted():
            # Check before every entry so /stop prevents unstarted remote side effects.
            entries.extend(fill_remote_failure(
                partition.remote[offset:], "Stopped by the user before this call was made.",
                code="INTERRUPTED"))
            break
        # Each entry must run its own policy and middleware.
        payload = handle_function_call(
            plan.name, plan.arguments, **asdict(ids), user_task=user_task,
            enabled_tools=enabled_tools, tool_request_middleware_trace=list(middleware_trace),
            skip_pre_tool_call_hook=False, skip_tool_request_middleware=False,
            skip_tool_execution_middleware=False,
            enabled_toolsets=enabled_toolsets, disabled_toolsets=disabled_toolsets,
        )
        try:
            value = json.loads(payload) if isinstance(payload, str) else payload
        except ValueError:
            value = payload
        entry = {"index": plan.position, "name": plan.name}
        if isinstance(value, dict) and "error" in value:
            error = value["error"]
            entry["error"] = error if isinstance(error, dict) else {"code": "TOOL_ERROR", "message": str(error)}
        else:
            entry["response"] = value.get("response", value) if isinstance(value, dict) else value
        entries.append(entry)
    return json.dumps(assemble_results(len(calls), entries), ensure_ascii=False)
