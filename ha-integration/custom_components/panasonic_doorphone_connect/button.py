"""`button.<base>_answer` and `button.<base>_hangup` — control entry
points for the daemon's `/control/answer` and `/control/hangup` endpoints.

Per INTERCOM-DESIGN.md §C/§D: Answer mints a UUID and registers a
talker (no exclusion — multiple devices can answer); Hangup releases
this device's talker (last-out also ends the monitor session).

Note: a button entity itself can't capture the user's mic — that
requires either the HA Companion App (mic permission + push to a
webhook) or a custom Lovelace card with WebRTC. This phase just
provides the control plane; mic-input wiring is a follow-up.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import aiohttp
from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_NAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import DoorphoneRuntime, build_device_info
from .const import CONF_AUTH_TOKEN, CONF_DAEMON_URL, DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    runtime: DoorphoneRuntime = hass.data[DOMAIN][entry.entry_id]
    name = entry.data.get(CONF_NAME, "Doorphone")
    daemon_url = entry.data[CONF_DAEMON_URL]
    auth_token = entry.data[CONF_AUTH_TOKEN]
    device_info = build_device_info(entry)
    # Shared token holder so Answer/Hangup pair up.
    token_holder = TokenHolder()
    async_add_entities([
        AnswerButton(runtime, entry.entry_id, name, daemon_url, auth_token, token_holder, device_info),
        HangupButton(runtime, entry.entry_id, name, daemon_url, auth_token, token_holder, device_info),
    ])


class TokenHolder:
    """Holds the most recent Answer's talker_id so Hangup can reference it.

    Per-entity-instance, not shared across HA installs / users — each
    HA surface (dashboard tab, Companion App) creates its own buttons
    via the entity registry. A "shared" model where multiple users on
    the same HA call would each be a separate token would need a
    per-user button, out of scope here.
    """

    def __init__(self) -> None:
        self.current: uuid.UUID | None = None


class _DaemonButton(ButtonEntity):
    _attr_should_poll = False

    def __init__(
        self,
        runtime: DoorphoneRuntime,
        entry_id: str,
        name: str,
        daemon_url: str,
        auth_token: str,
        token_holder: TokenHolder,
        device_info,
    ) -> None:
        self._runtime = runtime
        self._daemon_url = daemon_url.rstrip("/")
        self._auth_token = auth_token
        self._tokens = token_holder
        self._entry_id = entry_id
        self._base_name = name
        self._attr_device_info = device_info

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self._daemon_url}{path}",
                json=body,
                headers={"Authorization": f"Bearer {self._auth_token}"},
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                resp.raise_for_status()
                return await resp.json()


class AnswerButton(_DaemonButton):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._attr_unique_id = f"{self._entry_id}_answer"
        self._attr_name = "Answer"

    async def async_press(self) -> None:
        token = uuid.uuid4()
        try:
            await self._post(
                "/control/answer",
                {"talker_id": str(token), "source": f"ha:{self._entry_id}"},
            )
            self._tokens.current = token
            _LOGGER.info("Answer succeeded: token=%s", token)
        except Exception as e:  # noqa: BLE001
            _LOGGER.error("Answer failed: %s", e)


class HangupButton(_DaemonButton):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._attr_unique_id = f"{self._entry_id}_hangup"
        self._attr_name = "Hangup"

    async def async_press(self) -> None:
        token = self._tokens.current
        if token is None:
            _LOGGER.info("Hangup: no active talker — sending StopMonitor instead")
            # No talker held by this surface — fall back to ending the
            # monitor session globally via the daemon's existing
            # /monitor DELETE endpoint.
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.delete(
                        f"{self._daemon_url}/monitor",
                        headers={"Authorization": f"Bearer {self._auth_token}"},
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        resp.raise_for_status()
            except Exception as e:  # noqa: BLE001
                _LOGGER.error("Hangup (fallback) failed: %s", e)
            return
        try:
            await self._post("/control/hangup", {"talker_id": str(token)})
            _LOGGER.info("Hangup succeeded: token=%s", token)
        except Exception as e:  # noqa: BLE001
            _LOGGER.error("Hangup failed: %s", e)
        finally:
            self._tokens.current = None
