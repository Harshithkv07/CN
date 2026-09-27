"""Tiny in-process pub/sub for Server-Sent Events to the dashboard."""

from __future__ import annotations

import asyncio
import json
from typing import Any


class EventHub:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def publish(self, kind: str, payload: Any) -> None:
        """Thread-safe: worker threads call this; delivery hops onto the event loop."""
        msg = json.dumps({"kind": kind, "payload": payload})
        if self._loop is None:
            return
        self._loop.call_soon_threadsafe(self._fanout, msg)

    def _fanout(self, msg: str) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass
