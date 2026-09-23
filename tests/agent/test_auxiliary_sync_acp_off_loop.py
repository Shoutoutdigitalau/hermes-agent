"""A synchronous auxiliary shim must never run on the event loop.

ACP auxiliary clients drive an external CLI over stdio: ``create`` is a blocking, synchronous
function and the class declares ``HERMES_SKIP_ASYNC_WRAP`` so ``_to_async_client`` serves it
as-is. Every async auxiliary attempt goes through ``_acreate_with_progress``, so that shared seam
must run the shim in a worker thread. Awaiting it inline blocked the gateway event loop for the
whole ACP session (vision auto-analysis, gateway code-75 exits).
"""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

from agent import auxiliary_client as aux


def _chunk(text):
    return SimpleNamespace(
        id="r1", model="m", usage=None,
        choices=[SimpleNamespace(finish_reason=None, delta=SimpleNamespace(
            content=text, reasoning=None, reasoning_content=None, reasoning_details=None,
            tool_calls=None))],
    )


class _BlockingACPSyncShim:
    """Synchronous ACP shim: subprocess stdio, no HTTP pool, declared async-safe as-is."""

    HERMES_SKIP_TRANSPORT_WRAP = True
    HERMES_SKIP_ASYNC_WRAP = True
    api_key = "acp"
    base_url = "acp://copilot"

    def __init__(self, block_seconds: float = 0.2):
        self.block_seconds = block_seconds
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        # A real ACP session blocks its caller here (CopilotACPClient._run_prompt -> subprocess).
        time.sleep(self.block_seconds)
        if kwargs.get("stream"):
            return iter([_chunk("hello"), _chunk(" world")])
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="acp answer"), finish_reason="stop")],
            usage=None, model="m")


async def _drive_seam(factory):
    """Run ``factory()`` with a live ticker task; return (response, ticks during the call, error)."""
    ticks = [0]

    async def ticker():
        while True:
            ticks[0] += 1
            await asyncio.sleep(0.005)

    task = asyncio.create_task(ticker())
    while not ticks[0]:  # ticker is live before the seam is entered
        await asyncio.sleep(0.001)
    before = ticks[0]
    response = None
    error = None
    try:
        response = await factory()
    except Exception as exc:  # base awaits the sync shim directly: TypeError after the blocking call
        error = exc
    finally:
        task.cancel()
    return response, ticks[0] - before, error


def test_sync_acp_shim_create_runs_off_the_event_loop():
    shim = _BlockingACPSyncShim()
    response, ticks_during_call, error = asyncio.run(
        _drive_seam(lambda: aux._acreate_with_progress(
            shim, {"model": "m", "messages": []}, task="vision"))
    )
    assert ticks_during_call > 0, (
        f"the event loop did not tick while the synchronous ACP shim blocked for "
        f"{shim.block_seconds}s: the shim ran on the loop"
        + (f" ({error!r})" if error is not None else "")
    )
    assert error is None, error
    assert response.choices[0].message.content == "acp answer"


def test_sync_acp_shim_stream_stays_off_the_loop_under_a_progress_hook():
    shim = _BlockingACPSyncShim()
    hook_ticks = []

    async def scenario():
        with aux.aux_progress_hook(lambda: hook_ticks.append(1)):
            return await aux._acreate_with_progress(
                shim, {"model": "m", "messages": []}, task="compression")

    response, ticks_during_call, error = asyncio.run(_drive_seam(scenario))
    assert ticks_during_call > 0, (
        f"the event loop did not tick while the hooked synchronous ACP shim blocked for "
        f"{shim.block_seconds}s" + (f" ({error!r})" if error is not None else "")
    )
    assert error is None, error
    assert response.choices[0].message.content == "hello world"
    assert len(hook_ticks) >= 2  # one per substantive chunk, same as a real chunk stream
