# Protocol notes

This is the interoperability surface the daemon implements. It is not a dump of a private research notebook.

## Roles

- **Base** — indoor master (e.g. VL-MWD505). Talks DECT to the door station, SIP/UDP and HTTPS CGI on the LAN, and VIANA in the cloud.
- **Wi-Fi handset** — official app, or this bridge. Terminal numbers **21–28**.
- **VIANA** — Panasonic cloud rendezvous (`dipapp.bb-cygnus.jp` mint, `mcn.s2.vianaaws.jp` bootstrap, `NN-mcn.s2.vianaaws.jp` persistent WSS).

Call *setup* is not local SIP INVITE. The base (and/or a registered handset) signals through VIANA; RTP then flows LAN-direct.

## Pairing

1. **LAN discovery.** UDP broadcast `tgdect,<tcp_port>,00:00:00:00:00:00` to `255.255.255.255:50006`. Bind both the TCP listener and the UDP sender on ports in `60000..=65000`. The base opens TCP to the advertised port and sends `ip,mac,model,status\0`. Status `1` means the pair button is down.
2. **Mint.** HTTPS GET `dipapp.bb-cygnus.jp/servlet/getid?CMD=GETID&TYPE=RESET` with the three headers the official app derives (`User-agent`, `X-DAC`, `X-PW`). Response is a `kiki.dat` body plus a 16-digit `dispID`. See `viana_protocol::mint`.
3. **SIP MESSAGE** on UDP/5060: `Register:MAC=<12 lowercase hex>;Name="..."`. The MAC is synthetic, not the host NIC. Password later is `md5(mac).hexdigest().upper()`. The To-URI the official app sends has a stray `>` (`sip:Server@<ip>>`); the base accepts it.
4. **SIP REGISTER**, Digest MD5, realm `PSNPhoneSystem`, username = assigned terminal, URI `sip:<base>;transport=udp`, `Expires: 30`, re-REGISTER every 15 s.
5. **Local CGI** on the base HTTPS port: request 107 (`loginPassword`) then 108 (plant our `vianaID` + cert). Some bases ack 108 with an empty body; set `[base].viana_id` in `config.toml` if kick targeting needs it.

## Steady state

- Base NOTIFY `Event: wifi-terminal-event-notify` ~15 s, full roster. Answer 200 OK.
- Persistent WSS to the partition ELB. HTTP Basic on the upgrade, then an inner XML `auth` frame with the same `signatureDeviceId` (Base64 of `kiki.dat` plaintext `<USER_HEX>:<PW_HEX>`).
- `kickId` must be uppercase hex. Lowercase gets `resultCode=102` and a disconnect.
- Inbound ring is a kick `notifyState` JSON with `callStateArray[].mainCall.isRingSetting = true`.
- Monitor: kick `connect` with JSON + phone SDP. Base replies with SDP containing RTP ports and XOR material.
- Speak-on: `connectChange` with `connectKind: 1` (no new SDP). Hangup: `disconnect`.

## Media

- Audio: RTP PT=8, PCMA 8 kHz, 20 ms, 160-byte payload.
- Video: RTP PT=97, H.264, observed 640×480 @ 15 fps, RFC 6184 (single NAL / STAP-A / FU-A).
- Unwrap: leave the 12-byte RTP header; XOR the rest with the 8-byte `xorData`, `body[i] ^= key[i & 7]`. Same key both directions. `pairingId` / `xorAuthA` / `xorAuthB` are not used on the media hot path; A/B are for a 0x28-byte challenge packet.

`viana-media` implements the unwrap, depacketizer, and challenge response.

## TLS

`*.s2.vianaaws.jp` presents an X.509 **v1** chain that rustls/webpki will not parse. The daemon uses OS-native TLS and trusts `assets/panasonic-ca.pem` (the CA the official app pins). The official app does **not** use the Android system store for this channel.
