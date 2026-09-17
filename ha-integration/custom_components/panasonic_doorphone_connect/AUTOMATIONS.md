# Automation snippets for the Panasonic Doorphone Connect integration

Drop these into your HA `automations.yaml` (or build via the UI; the YAML is the canonical form). All entity ids assume your pair name was "Door" — adjust to match yours.

## Ring → broadcast on Google Home speakers

```yaml
- alias: Doorphone — announce ring on speakers
  trigger:
    platform: state
    entity_id: binary_sensor.door_ring
    to: "on"
  action:
    - service: tts.google_translate_say
      target:
        entity_id: media_player.living_room_speaker  # your Google Home / Nest Hub
      data:
        message: "Someone is at the door"
        language: en
```

## Ring → push notification with camera snapshot to your phone

```yaml
- alias: Doorphone — phone notification on ring
  trigger:
    platform: state
    entity_id: binary_sensor.door_ring
    to: "on"
  action:
    - service: notify.mobile_app_<your_phone_name>
      data:
        title: "Doorbell"
        message: "Someone is at the door"
        data:
          image: /api/camera_proxy/camera.door_door  # snapshot from the live stream
          actions:
            - action: VIEW_DOORPHONE
              title: "View"
            - action: ANSWER_DOORPHONE
              title: "Answer"
```

## Phone notification action → Answer / Hang up

```yaml
- alias: Doorphone — answer from notification
  trigger:
    platform: event
    event_type: mobile_app_notification_action
    event_data:
      action: ANSWER_DOORPHONE
  action:
    - service: button.press
      target:
        entity_id: button.door_answer

- alias: Doorphone — hang up from notification
  trigger:
    platform: event
    event_type: mobile_app_notification_action
    event_data:
      action: HANGUP_DOORPHONE
  action:
    - service: button.press
      target:
        entity_id: button.door_hangup
```

## Lovelace card — picture-glance with answer/hangup

Add to your dashboard's raw config:

```yaml
type: picture-glance
title: Front door
camera_image: camera.door_door
entities:
  - entity: button.door_answer
    icon: mdi:phone
    tap_action:
      action: call-service
      service: button.press
      service_data:
        entity_id: button.door_answer
  - entity: button.door_hangup
    icon: mdi:phone-hangup
    tap_action:
      action: call-service
      service: button.press
      service_data:
        entity_id: button.door_hangup
camera_view: live
```

## Exposing entities to Google Home

For the Nest doorbell card UX on Nest Hub, you need:

1. **HA Cloud (Nabu Casa)** — easiest. In HA UI: Settings → Cloud → Google Assistant → expose:
   - `binary_sensor.door_ring` (will surface as a Doorbell device)
   - `camera.door_door` (will surface as a Camera device, linked automatically to the Doorbell)
   - `media_player.door_intercom` (so audio routes through HA, not Google's own paths)

2. **Self-hosted Google Assistant integration** — same exposure, just configured in `configuration.yaml`. See HA docs.

Once exposed, ringing the doorbell triggers the Nest Hub's built-in "Someone is at the door" UX — full-screen camera card pop-up. No additional automation needed for that part.

## Known limitations

- **Mic-back-from-Nest-Hub**: Google does not expose Nest Hub's microphone to third-party media surfaces, including HA. You can SEE and HEAR through the Nest Hub but you can't TALK back from it. Use the HA Companion App on your phone, or a tablet with the HA dashboard, when audio response is needed.

- **Mic capture wiring**: the `button.door_answer` press currently registers a talker token with the daemon, but no UI yet streams Companion App or browser mic input into `POST /stream/audio/in`. You can verify the outbound RTP path with curl or a script that posts PCM 16-bit 8 kHz mono chunks. Production-grade mic capture from HA needs either a custom Lovelace card with WebRTC or a Companion App webhook helper — both follow-ups, not blockers for the camera + listen UX.

- **Multiple talkers**: the daemon supports N concurrent mic streams (1/√N attenuated mix). If two talkers join from different rooms with both speaker+mic active, you will get a feedback loop — wear headphones or stay one-device-per-room.
