"""Panasonic Doorphone Connect (Unofficial) integration setup hooks.

Loads the daemon client, kicks off a long-lived task that consumes the
daemon's `/events` SSE stream, and forwards platform setup to
binary_sensor (Ring), camera (Door — video + intercom audio in one
MPEG-TS track) and button (Answer/Hangup). There's no separate
media_player: intercom audio is the camera's audio track, so opening the
camera in HA also surfaces the door audio.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_NAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo

from .const import CONF_AUTH_TOKEN, CONF_DAEMON_URL, DOMAIN
from .daemon import DaemonClient


def build_device_info(entry: ConfigEntry) -> DeviceInfo:
    """Single Device that all per-entry entities belong to.

    Sharing this device_info across binary_sensor, camera, media_player,
    and button entities makes HA group them in one device card AND
    surfaces them to Google Home as a single device with multiple
    capabilities — required for Nest Hub's built-in doorbell card UX
    (camera auto-shows when ring fires) since it pairs the doorbell
    sensor with a co-located camera by device.
    """
    name = entry.data.get(CONF_NAME, "Doorphone")
    return DeviceInfo(
        identifiers={(DOMAIN, entry.entry_id)},
        name=name,
        manufacturer="Panasonic",
        model="VL-MWD (via unofficial Doorphone Connect bridge)",
    )

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.CAMERA,
    Platform.BUTTON,
]


@dataclass
class DoorphoneRuntime:
    client: DaemonClient
    event_task: asyncio.Task[None]
    # Subscribers receive every parsed event dict. Entities push their
    # callbacks here in async_added_to_hass.
    listeners: list[Any]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Stand up the daemon connection + start the event pump."""
    client = DaemonClient(entry.data[CONF_DAEMON_URL], entry.data[CONF_AUTH_TOKEN])
    runtime = DoorphoneRuntime(
        client=client,
        event_task=asyncio.create_task(_pump_events(client, hass, entry)),
        listeners=[],
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = runtime
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Tear it back down on integration removal/reload."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        runtime: DoorphoneRuntime = hass.data[DOMAIN].pop(entry.entry_id)
        runtime.event_task.cancel()
        try:
            await runtime.event_task
        except asyncio.CancelledError:
            pass
        await runtime.client.close()
    return unloaded


async def _pump_events(
    client: DaemonClient, hass: HomeAssistant, entry: ConfigEntry
) -> None:
    """Forever-loop reading the daemon's event stream and fanning out to
    listeners. Reconnects on transient errors with capped backoff."""
    delay = 1.0
    while True:
        try:
            async for event in client.stream_events():
                runtime: DoorphoneRuntime | None = (
                    hass.data.get(DOMAIN, {}).get(entry.entry_id)
                )
                if runtime is None:
                    return
                for cb in list(runtime.listeners):
                    try:
                        cb(event)
                    except Exception:  # noqa: BLE001
                        _LOGGER.exception("listener raised on %s", event)
            # Graceful end-of-stream → reconnect after a short pause.
            delay = 1.0
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            _LOGGER.warning(
                "events stream dropped; reconnecting in %.1fs", delay
            )
        await asyncio.sleep(delay)
        delay = min(delay * 2, 30.0)
