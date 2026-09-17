"""Constants for the Panasonic Doorphone Connect (Unofficial) integration."""

from __future__ import annotations

DOMAIN = "panasonic_doorphone_connect"

# Config-entry data keys.
CONF_DAEMON_URL = "daemon_url"
CONF_AUTH_TOKEN = "auth_token"
CONF_DISPLAY_NAME = "display_name"
CONF_BASE_LOGIN_PASSWORD = "base_login_password"

# How HA finds the daemon. Write this file into HA's config dir after
# viana-ha is up; the Config Flow reads it instead of asking the user.
# If it's missing the flow tells the user pairing isn't ready.
DISCOVERY_FILENAME = ".viana-ha-discovery.json"

# Default daemon URL for the discovery-file-missing fallback. Same box as HA.
DEFAULT_DAEMON_URL = "http://127.0.0.1:7878"

# Pair window — has to be > the base's ~30s pair-accept window so the user
# has time to walk to the base and press the button.
PAIR_WINDOW_SECS = 60
