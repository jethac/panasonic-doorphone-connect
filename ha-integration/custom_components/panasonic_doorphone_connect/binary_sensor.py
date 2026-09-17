"""`binary_sensor.<base>_ring` — true while the gate is being rung."""

from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_NAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import DoorphoneRuntime, build_device_info
from .const import DOMAIN


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    runtime: DoorphoneRuntime = hass.data[DOMAIN][entry.entry_id]
    name = entry.data.get(CONF_NAME, "Doorphone")
    device_info = build_device_info(entry)
    async_add_entities([RingBinarySensor(runtime, entry.entry_id, name, device_info)])


class RingBinarySensor(BinarySensorEntity):
    # `doorbell` device class makes this surface as a Nest-style doorbell
    # device when exposed to Google Assistant — Nest Hub fires its
    # built-in "Someone is at the door" UX (camera card pop-up + chime).
    # Requires HA 2023.x or newer; older HA: change to `OCCUPANCY`.
    _attr_device_class = BinarySensorDeviceClass.OCCUPANCY  # set below
    _attr_should_poll = False

    def __init__(
        self,
        runtime: DoorphoneRuntime,
        entry_id: str,
        name: str,
        device_info: Any,
    ) -> None:
        self._runtime = runtime
        self._attr_unique_id = f"{entry_id}_ring"
        # With device_info set, HA renders as "<Device> Ring" — drop
        # the redundant device prefix from the entity name itself.
        self._attr_name = "Ring"
        self._attr_device_info = device_info
        self._attr_is_on = False
        self._extra: dict[str, Any] = {}
        # Promote to DOORBELL if this HA version supports it.
        try:
            self._attr_device_class = BinarySensorDeviceClass.DOORBELL  # type: ignore[attr-defined]
        except AttributeError:
            pass  # leave as OCCUPANCY default

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return self._extra

    async def async_added_to_hass(self) -> None:
        self._runtime.listeners.append(self._handle_event)

    async def async_will_remove_from_hass(self) -> None:
        try:
            self._runtime.listeners.remove(self._handle_event)
        except ValueError:
            pass

    def _handle_event(self, event: dict[str, Any]) -> None:
        # Daemon emits `{"event": "doorphone.ring", "active": bool, ...}`.
        if event.get("event") != "doorphone.ring":
            return
        self._attr_is_on = bool(event.get("active"))
        self._extra = {
            k: event[k]
            for k in ("device_name", "device_no", "ring_counter", "ts")
            if k in event
        }
        self.schedule_update_ha_state()
