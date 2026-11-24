"""Real HTTP transport for the G1.5a streaming tests: uvicorn in a thread and an SSE reader.

The events endpoint is a stream, so `TestClient` is not the evidence a browser-like client needs:
these helpers serve the app on a loopback port with the real uvicorn/Starlette stack and read
`text/event-stream` incrementally, exactly as `EventSource` does (comment lines skipped, fields
split on the first `:`, one dispatch per blank line).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import httpx
import uvicorn

__all__ = ["SSE_HEADERS", "SseEvent", "SseStream", "open_sse", "serve"]

SSE_HEADERS = {"accept": "text/event-stream", "cache-control": "no-cache"}


@contextmanager
def serve(app: Any, *, startup_timeout: float = 15.0) -> Iterator[str]:
    """Run `app` under uvicorn on a free loopback port; yields its base URL."""
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning", lifespan="off")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="aegis-test-http", daemon=True)
    thread.start()
    deadline = time.monotonic() + startup_timeout
    while not server.started:
        if not thread.is_alive():
            raise RuntimeError("the test HTTP server stopped before it was ready")
        if time.monotonic() > deadline:
            raise RuntimeError("the test HTTP server did not start in time")
        time.sleep(0.02)
    try:
        sockets = server.servers[0].sockets
        port = int(sockets[0].getsockname()[1])
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        if thread.is_alive():
            raise RuntimeError("the test HTTP server did not stop in time")


@dataclass(frozen=True, slots=True)
class SseEvent:
    """One dispatched SSE message: `id`, `event` and the raw `data` payload."""

    id: str | None
    event: str | None
    data: str


class SseStream:
    """Sequential reader of one `text/event-stream` response."""

    def __init__(self, client: httpx.Client, response: httpx.Response) -> None:
        self._client = client
        self._response = response
        self._lines = response.iter_lines()

    def close(self) -> None:
        self._response.close()
        self._client.close()

    def __enter__(self) -> SseStream:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def next(self) -> SseEvent:
        """The next message; comment lines (e.g. the opening `: consumer ready`) are skipped."""
        fields: dict[str, str] = {}
        for line in self._lines:
            if line.startswith(":"):
                continue
            if line == "":
                if fields:
                    return SseEvent(
                        id=fields.get("id"),
                        event=fields.get("event"),
                        data=fields.get("data", ""),
                    )
                continue
            name, _, value = line.partition(":")
            fields[name.strip()] = value[1:] if value.startswith(" ") else value
        raise EOFError("the stream ended before the next message")

    def events(self, limit: int) -> list[SseEvent]:
        return [self.next() for _ in range(limit)]


def open_sse(
    url: str,
    *,
    last_event_id: str | None = None,
    read_timeout: float = 5.0,
    extra_headers: dict[str, str] | None = None,
) -> SseStream:
    """Open a stream and return once the server has sent its response head."""
    headers = dict(SSE_HEADERS)
    if last_event_id is not None:
        headers["last-event-id"] = last_event_id
    headers.update(extra_headers or {})
    client = httpx.Client(timeout=httpx.Timeout(10.0, read=read_timeout))
    request = client.build_request("GET", url, headers=headers)
    response = client.send(request, stream=True)
    if response.status_code != 200:
        body = response.read()
        response.close()
        client.close()
        raise AssertionError(f"SSE {url} answered {response.status_code}: {body[:400]!r}")
    if "text/event-stream" not in (response.headers.get("content-type") or ""):
        body = response.read()
        response.close()
        client.close()
        raise AssertionError(
            f"SSE {url} answered {response.headers.get('content-type')!r}: {body[:400]!r}"
        )
    return SseStream(client, response)
