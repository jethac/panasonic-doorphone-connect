"""`camera.<base>_door` — live H264 stream from the door's gate camera.

Backed by the daemon's `GET /stream/video` endpoint. The daemon serves
raw H264 bytes (Annex-B format if the base sends in-band SPS/PPS).
HA's built-in `stream` integration (which uses ffmpeg) consumes this
via the `stream_source` URL.

The camera entity is **always present** even when no monitor session
is active — opening it in the HA UI triggers a stream consumer attach
which the daemon uses as a signal to keep the monitor session alive
(per INTERCOM-DESIGN.md §C "manual camera open also fires monitor").
"""

from __future__ import annotations

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_NAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import DoorphoneRuntime, build_device_info
from .const import CONF_AUTH_TOKEN, CONF_DAEMON_URL, DOMAIN


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
    async_add_entities([
        DoorCamera(runtime, entry.entry_id, name, daemon_url, auth_token, device_info)
    ])


class DoorCamera(Camera):
    _attr_supported_features = CameraEntityFeature.STREAM
    _attr_should_poll = False

    def __init__(
        self,
        runtime: DoorphoneRuntime,
        entry_id: str,
        name: str,
        daemon_url: str,
        auth_token: str,
        device_info,
    ) -> None:
        super().__init__()
        self._runtime = runtime
        self._daemon_url = daemon_url.rstrip("/")
        self._auth_token = auth_token
        self._attr_unique_id = f"{entry_id}_door_camera"
        # Renders as "<Device> Camera" in HA UI now that device_info is set.
        self._attr_name = "Camera"
        self._attr_device_info = device_info

    async def stream_source(self) -> str | None:
        # HA's stream component supports HTTP MJPEG, RTSP, HLS, and
        # arbitrary inputs ffmpeg can read. Raw H264 over HTTP qualifies
        # — ffmpeg's `h264` demuxer accepts it, plus we set
        # Content-Type: video/H264 on the daemon side.
        #
        # Token is embedded in the URL because HA's stream worker hands
        # the URL to ffmpeg, which can't carry a Bearer header. Daemon
        # accepts `?token=` for /stream/* endpoints (see
        # require_bearer in http.rs).
        return f"{self._daemon_url}/stream/video?token={self._auth_token}"

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        # Snapshot endpoint not implemented yet — HA will use a
        # last-frame from the stream. Returning None lets HA's stream
        # worker grab a still on demand.
        return None
