"""In-process publish/subscribe used to stream live updates to the dashboard (SSE)."""
from __future__ import annotations

import asyncio
from typing import Any


class EventBus:
    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue] = []

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=2000)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        if q in self._subscribers:
            self._subscribers.remove(q)

    def publish(self, kind: str, data: Any) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait((kind, data))
            except asyncio.QueueFull:
                pass  # a stalled browser tab must never slow down enforcement

    @property
    def listeners(self) -> int:
        return len(self._subscribers)
