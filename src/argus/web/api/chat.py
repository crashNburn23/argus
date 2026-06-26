"""WebSocket chat endpoint — streams orchestrator progress to the browser."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from argus.agents.orchestrator import CTIOrchestrator
from argus.models.case import CaseNote
from argus.storage.cases import CaseNotFoundError, CaseStore

log = logging.getLogger(__name__)
router = APIRouter()


def _visible_result_text(result: str) -> str:
    text = result.strip()
    if text:
        return text
    return (
        "Argus completed the request, but no response text was returned. "
        "Check server logs for the orchestrator run details."
    )


class _ProgressBridge:
    """Mutable callable — swap the destination queue between messages without
    recreating the orchestrator (preserving conversation history)."""

    def __init__(self) -> None:
        self._queue: asyncio.Queue[dict[str, Any]] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def arm(self, queue: asyncio.Queue[dict[str, Any]], loop: asyncio.AbstractEventLoop) -> None:
        self._queue = queue
        self._loop = loop

    def disarm(self) -> None:
        self._queue = None
        self._loop = None

    def __call__(self, text: str) -> None:
        if self._queue is not None and self._loop is not None:
            try:
                self._loop.call_soon_threadsafe(
                    self._queue.put_nowait, {"type": "progress", "text": text}
                )
            except Exception:
                pass


def _build_case_query(text: str, case_id: str) -> str:
    """Prepend case context to a user query for case-scoped chat."""
    try:
        case = CaseStore().get(case_id)
        obs_str = ", ".join(o.value for o in case.observables[:10]) or "none"
        pir_str = " | ".join(p.question for p in case.pirs[:3]) or "none"
        return (
            f"[Case context]\n"
            f"Title: {case.title}  Status: {case.status}\n"
            f"Description: {case.description or 'none'}\n"
            f"Observables ({len(case.observables)}): {obs_str}\n"
            f"PIRs: {pir_str}\n\n"
            f"Analyst question: {text}"
        )
    except CaseNotFoundError:
        return text


@router.websocket("/ws")
async def chat_ws(websocket: WebSocket) -> None:
    await websocket.accept()

    bridge = _ProgressBridge()
    orchestrator = CTIOrchestrator(persistent=True, progress=bridge)
    current_task: asyncio.Task[None] | None = None

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue

            msg_type = msg.get("type", "")

            if msg_type == "cancel":
                if current_task and not current_task.done():
                    current_task.cancel()
                continue

            if msg_type == "clear":
                orchestrator.clear_conversation()
                await websocket.send_json({"type": "cleared"})
                continue

            if msg_type != "message":
                continue

            text = str(msg.get("text", "")).strip()
            if not text:
                continue

            mode: str = msg.get("mode", "global")
            case_id: str | None = msg.get("case_id")

            query = _build_case_query(text, case_id) if mode == "case" and case_id else text

            loop = asyncio.get_event_loop()
            queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
            bridge.arm(queue, loop)

            async def _run(
                q: str = query,
                cid: str | None = case_id,
                m: str = mode,
                original_text: str = text,
            ) -> None:
                try:
                    result = _visible_result_text(await orchestrator.run(user_query=q))
                    if "no response text" in result:
                        log.warning("chat_ws.empty_result")
                    log.info(
                        "chat_ws.result result_bytes=%d mode=%s case_id=%s",
                        len(result), m, cid,
                    )
                    await queue.put({"type": "result", "text": result})

                    if m == "case" and cid:
                        try:
                            note = CaseNote(body=f"**Q:** {original_text}\n\n**A:**\n{result}")
                            CaseStore().update(
                                cid,
                                lambda c: c.model_copy(update={"notes": [*c.notes, note]}),
                            )
                        except Exception:
                            pass
                except asyncio.CancelledError:
                    await queue.put({"type": "cancelled", "text": "Cancelled."})
                except Exception as e:
                    log.exception("chat_ws orchestrator error")
                    await queue.put({"type": "error", "text": str(e)})
                finally:
                    bridge.disarm()

            current_task = asyncio.create_task(_run())

            while True:
                item = await queue.get()
                await websocket.send_json(item)
                if item["type"] in ("result", "error", "cancelled"):
                    break

            await current_task

    except WebSocketDisconnect:
        if current_task and not current_task.done():
            current_task.cancel()
