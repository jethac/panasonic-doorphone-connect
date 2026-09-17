"""Config Flow for the Panasonic Doorphone Connect (Unofficial) integration.

The user's mental model is just "press the pair button on my base". The
viana-ha daemon is an implementation detail — HA reads its location and
auth token from a sidecar discovery file the deploy workflow drops into
the HA config dir. The user never sees a daemon URL or a token.

Flow:
  1. silent — read `<hass.config>/<DISCOVERY_FILENAME>`. If it's missing
     the integration isn't deployed yet → abort with `daemon_missing`.
  2. silent — `GET /state` to confirm the daemon is reachable.
     Already-paired? Done — re-create the entry from the persisted base.
  3. silent — `POST /discover` to confirm a Panasonic base is on the LAN.
     Nothing answered? → abort with `no_base_on_lan`.
  4. ask — base login password (set on the base's own menu) + display
     name. Submit advances to step 5.
  5. ask — show "press the pair button on the base" and `POST /pair`.
     Daemon blocks until the user presses the button (or 60s timeout).
  6. on success — create the entry; on timeout — show error + offer retry.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_NAME
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .const import (
    CONF_AUTH_TOKEN,
    CONF_BASE_LOGIN_PASSWORD,
    CONF_DAEMON_URL,
    CONF_DISPLAY_NAME,
    DEFAULT_DAEMON_URL,
    DISCOVERY_FILENAME,
    DOMAIN,
    PAIR_WINDOW_SECS,
)
from .daemon import DaemonClient, DaemonError

_LOGGER = logging.getLogger(__name__)


class DoorphoneConnectConfigFlow(ConfigFlow, domain=DOMAIN):
    """Config Flow that hides viana-ha behind a discovery file + pair button."""

    VERSION = 1

    def __init__(self) -> None:
        self._daemon_url: str | None = None
        self._auth_token: str | None = None
        self._discovered_base: dict[str, Any] | None = None
        self._display_name: str | None = None
        self._login_password: str | None = None

    # ------------------------------------------------------------------
    # Step 1 — entry point. The user clicked Add Integration → Doorphone
    # Connect. Read the discovery file synchronously (it's tiny), then
    # decide between "show pairing form" vs "abort with friendly error".
    # ------------------------------------------------------------------
    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        del user_input  # no form on this step
        info = await self.hass.async_add_executor_job(
            _read_discovery_file, self.hass.config.path(DISCOVERY_FILENAME)
        )
        if info is None:
            return self.async_abort(reason="daemon_missing")
        self._daemon_url = info.get("daemon_url", DEFAULT_DAEMON_URL).rstrip("/")
        self._auth_token = info.get("auth_token")
        if not self._auth_token:
            return self.async_abort(reason="daemon_missing")

        client = DaemonClient(self._daemon_url, self._auth_token)
        try:
            try:
                state = await client.get_state()
            except DaemonError as e:
                _LOGGER.warning("daemon /state probe failed: %s", e)
                return self.async_abort(reason="daemon_unreachable")

            if state.paired:
                # Daemon already knows about a base (someone re-added the
                # integration after a re-install, or pre-paired manually).
                # Make the entry from what's already persisted.
                base = state.base or {}
                name = base.get("display_name") or "Doorphone Connect"
                await self.async_set_unique_id(
                    base.get("viana_id") or self._daemon_url
                )
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=name,
                    data={
                        CONF_DAEMON_URL: self._daemon_url,
                        CONF_AUTH_TOKEN: self._auth_token,
                        CONF_NAME: name,
                    },
                )

            # Unpaired — make sure a base is at least on the LAN before
            # asking the user for credentials.
            try:
                discover = await client.discover()
            except DaemonError as e:
                _LOGGER.warning("daemon /discover failed: %s", e)
                return self.async_abort(reason="daemon_unreachable")
            if not discover.found:
                return self.async_abort(reason="no_base_on_lan")
            self._discovered_base = discover.base
            return await self.async_step_credentials()
        finally:
            await client.close()

    # ------------------------------------------------------------------
    # Step 2 — collect the base login password (the one the user set on
    # the base's own menu) and a display name. Synchronous form.
    # ------------------------------------------------------------------
    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            self._login_password = user_input[CONF_BASE_LOGIN_PASSWORD]
            self._display_name = (
                user_input.get(CONF_DISPLAY_NAME) or "Doorphone"
            )
            return await self.async_step_pair()

        default_name = "Front Gate"
        base = self._discovered_base or {}
        description_placeholders = {
            "base_ip": str(base.get("lan_ip") or "(unknown)"),
            "base_model": str(base.get("model") or "(unknown)"),
            "base_mac": str(base.get("mac") or "(unknown)"),
        }
        schema = vol.Schema(
            {
                vol.Required(CONF_BASE_LOGIN_PASSWORD): TextSelector(
                    TextSelectorConfig(type=TextSelectorType.PASSWORD)
                ),
                vol.Optional(CONF_DISPLAY_NAME, default=default_name): str,
            }
        )
        return self.async_show_form(
            step_id="credentials",
            data_schema=schema,
            errors=errors,
            description_placeholders=description_placeholders,
        )

    # ------------------------------------------------------------------
    # Step 3 — drive the actual pair handshake. The daemon's /pair blocks
    # waiting for the user to press the pair button on the base. We pass
    # the user the explicit "press the button now" prompt; on submit we
    # actually fire the request.
    # ------------------------------------------------------------------
    async def async_step_pair(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is None:
            # First entry into this step — show the "press the button" form
            # with a single "Done" button (no fields). HA renders an empty
            # vol.Schema as a confirmation prompt.
            return self.async_show_form(
                step_id="pair",
                data_schema=vol.Schema({}),
                errors=errors,
            )

        assert self._daemon_url and self._auth_token
        assert self._login_password is not None
        client = DaemonClient(self._daemon_url, self._auth_token)
        try:
            try:
                resp = await client.pair(
                    base_login_password=self._login_password,
                    display_name=self._display_name,
                    pair_window_secs=PAIR_WINDOW_SECS,
                )
            except DaemonError as e:
                msg = str(e).lower()
                if "pair button was not pressed" in msg or "408" in msg:
                    errors["base"] = "pair_timeout"
                elif "rejected login" in msg or "401" in msg:
                    errors["base"] = "wrong_password"
                elif "no panasonic base" in msg or "404" in msg:
                    errors["base"] = "no_base_on_lan"
                else:
                    errors["base"] = "pair_failed"
                _LOGGER.warning("pair failed: %s", e)
                return self.async_show_form(
                    step_id="pair",
                    data_schema=vol.Schema({}),
                    errors=errors,
                )

            base = resp.get("base") or {}
            await self.async_set_unique_id(
                base.get("viana_id") or self._daemon_url
            )
            self._abort_if_unique_id_configured()
            name = base.get("display_name") or self._display_name or "Doorphone"
            return self.async_create_entry(
                title=name,
                data={
                    CONF_DAEMON_URL: self._daemon_url,
                    CONF_AUTH_TOKEN: self._auth_token,
                    CONF_NAME: name,
                },
            )
        finally:
            await client.close()


def _read_discovery_file(path: str) -> dict[str, Any] | None:
    """Read the deploy-workflow-managed discovery JSON. Returns None on
    any failure — the Config Flow renders that as `daemon_missing`."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return None
        return data
    except (OSError, json.JSONDecodeError) as e:
        _LOGGER.warning("could not read %s: %s", path, e)
        return None
