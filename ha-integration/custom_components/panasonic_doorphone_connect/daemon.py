"""Thin async client for the viana-ha HTTP API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, AsyncIterator

import aiohttp


class DaemonError(Exception):
    """Anything went wrong talking to the daemon."""


class DaemonNotPaired(DaemonError):
    """Specifically: the daemon answered, but isn't paired yet."""


@dataclass
class DaemonState:
    paired: bool
    base: dict[str, Any] | None
    listen: str
    daemon_version: str


@dataclass
class DiscoverResult:
    found: bool
    base: dict[str, Any] | None
    accepting: bool


class DaemonClient:
    """Wraps the daemon's REST + SSE surface in async helpers HA can call.

    A new aiohttp ClientSession is created per instance and torn down by
    `close()`. The integration owns lifetime here.
    """

    def __init__(self, base_url: str, token: str | None) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10)
        )

    async def close(self) -> None:
        await self._session.close()

    def _headers(self, *, auth: bool = True) -> dict[str, str]:
        if auth and self._token:
            return {"Authorization": f"Bearer {self._token}"}
        return {}

    async def get_state(self) -> DaemonState:
        """`GET /state` — auth-free probe so we can confirm reachability
        before trying any authenticated endpoints."""
        async with self._session.get(
            f"{self._base_url}/state", headers=self._headers(auth=False)
        ) as resp:
            if resp.status != 200:
                raise DaemonError(f"GET /state returned {resp.status}")
            data = await resp.json()
            return DaemonState(
                paired=bool(data.get("paired")),
                base=data.get("base"),
                listen=data.get("listen", ""),
                daemon_version=data.get("daemon_version", ""),
            )

    async def discover(self) -> DiscoverResult:
        """`POST /discover` — one-shot tgdect probe. Used by the Config
        Flow to fail fast if no Panasonic base is on this LAN."""
        async with self._session.post(
            f"{self._base_url}/discover", headers=self._headers()
        ) as resp:
            if resp.status >= 400:
                raise DaemonError(
                    f"discover failed ({resp.status}): {await resp.text()}"
                )
            data = await resp.json()
            return DiscoverResult(
                found=bool(data.get("found")),
                base=data.get("base"),
                accepting=bool(data.get("accepting")),
            )

    async def pair(
        self,
        *,
        base_login_password: str,
        display_name: str | None,
        pair_window_secs: int = 60,
    ) -> dict[str, Any]:
        """`POST /pair` — drives the full pair handshake (tgdect → SIP
        MESSAGE → SIP REGISTER → CGI 107 → CGI 108) and persists the
        result. Returns the freshly-stored `base` block on success.

        Blocks until the user presses the pair button on the base or the
        window times out — set `pair_window_secs` and the underlying
        aiohttp client timeout accordingly."""
        body: dict[str, Any] = {
            "base_login_password": base_login_password,
            "pair_window_secs": pair_window_secs,
        }
        if display_name:
            body["display_name"] = display_name
        # Override the per-request timeout — the pair flow can take 60s
        # waiting for the user to push the button.
        timeout = aiohttp.ClientTimeout(total=pair_window_secs + 30)
        async with self._session.post(
            f"{self._base_url}/pair",
            headers=self._headers(),
            json=body,
            timeout=timeout,
        ) as resp:
            text = await resp.text()
            if resp.status >= 400:
                raise DaemonError(
                    f"pair failed ({resp.status}): {text}"
                )
            return await resp.json()

    async def start_monitor(self, media_dir: str, door_no: int | None = None) -> None:
        body: dict[str, Any] = {"media_dir": media_dir}
        if door_no is not None:
            body["door_no"] = door_no
        async with self._session.post(
            f"{self._base_url}/monitor", headers=self._headers(), json=body
        ) as resp:
            if resp.status >= 400:
                raise DaemonError(
                    f"start_monitor failed ({resp.status}): {await resp.text()}"
                )

    async def stop_monitor(self) -> None:
        async with self._session.delete(
            f"{self._base_url}/monitor", headers=self._headers()
        ) as resp:
            if resp.status >= 400:
                raise DaemonError(
                    f"stop_monitor failed ({resp.status}): {await resp.text()}"
                )

    async def stream_events(self) -> AsyncIterator[dict[str, Any]]:
        """`GET /events` — server-sent events of every structured daemon
        event (rings, monitor lifecycle, pair completion). Yields decoded
        JSON dicts. Caller is responsible for graceful cancellation."""
        timeout = aiohttp.ClientTimeout(total=None, sock_read=None)
        async with self._session.get(
            f"{self._base_url}/events",
            headers={**self._headers(), "Accept": "text/event-stream"},
            timeout=timeout,
        ) as resp:
            if resp.status != 200:
                raise DaemonError(f"GET /events returned {resp.status}")
            buffer: list[str] = []
            async for raw in resp.content:
                line = raw.decode("utf-8", errors="ignore").rstrip("\r\n")
                if line == "":
                    if not buffer:
                        continue
                    data = "\n".join(
                        l[len("data:") :].lstrip()
                        for l in buffer
                        if l.startswith("data:")
                    )
                    buffer.clear()
                    if not data:
                        continue
                    try:
                        import json

                        yield json.loads(data)
                    except json.JSONDecodeError:
                        continue
                else:
                    buffer.append(line)
