# Panasonic Doorphone Connect（非公式）

パナソニック「ドアホンコネクト」の非公式 Home Assistant 連携です。公式 Android アプリが引退したあとでも、親機を仮想 Wi-Fi 子機として Home Assistant に載せ、呼び鈴・ライブ映像・通話をスマートホーム側で扱えるようにします。

Unofficial Home Assistant integration for Panasonic Doorphone Connect. After the official Android app was retired, this registers as a virtual Wi-Fi handset so the base can expose ring, live video, and talk-back inside Home Assistant.

**パナソニック公式ではありません。無保証です。壊れること、クラウド側が拒否すること、将来のファームウェアで動かなくなることを想定してください。**

**Not affiliated with Panasonic. Provided as-is. Expect breakage, cloud-side refusal, and firmware drift.**

## これは何か / What this is

呼び出しボタンを押しても、宅内 LAN に「誰かが来た」という通知は出ません。親機はパナソニックの VIANA クラウド（東京 AWS）へ HTTPS で知らせ、音声と映像は宅内 RTP のまま流れます。A 接点をリレーで拾う必要はありません。ネットワークに載っているなら、ネットワークで完結できます。

The doorbell press does not show up as a LAN notification. The base tells Panasonic's VIANA cloud (Tokyo AWS) over HTTPS; audio and video stay on LAN RTP. You do not need to wire the analog A-contact. If the unit is already on the network, the event can stay on the network.

このリポジトリは、引退した公式アプリがやっていたことを再現します。一度だけ VIANA 上に端末身分を発行し、親機の Wi-Fi 子機スロット（21〜28）へペアし、クラウドのキックチャネルを常時接続したまま、RTP を復号して Home Assistant のカメラと呼び鈴センサに載せます。

This repository reproduces what the retired official app did. It mints a VIANA identity once, pairs into a Wi-Fi handset slot (21–28), holds the cloud kick channel open, unwraps RTP, and publishes a camera plus a doorbell sensor in Home Assistant.

## できること / What works

- 呼び鈴を `binary_sensor`（`device_class: doorbell`）として Home Assistant に出す
- 玄関カメラのライブ映像（H.264）とインターホン音声（G.711 PCMA）を 1 本の MPEG-TS カメラエンティティにする
- モニタ開始、応答、切断
- Google Home / Nest Hub へ呼び鈴とカメラを出す（Nest の「誰かが玄関にいます」カード。Nest Hub マイクからの応答は不可）

- Ring as a Home Assistant `binary_sensor` with `device_class: doorbell`
- Live gate camera (H.264) plus intercom audio (G.711 PCMA) on one MPEG-TS camera entity
- Monitor, answer, hang up
- Expose ring + camera to Google Home / Nest Hub (Nest “someone is at the door” card; no talk-back from the Nest Hub mic)

**実機確認:** Panasonic **VL-MWD505**（AU/NZ）。日本市場の VL-MWD701 など、同じ `com.panasonic.psn.android.doorphoneconnect` アプリを使う兄弟機種はおそらく同じ経路です。未確認機種は issue で報告してください。

**Confirmed hardware:** Panasonic **VL-MWD505** (AU/NZ). Japanese-market siblings such as VL-MWD701 that share the `com.panasonic.psn.android.doorphoneconnect` app almost certainly use the same path. Report untested models in issues.

## できないこと / What this is not

- 公式アプリの代替サポート契約ではない
- Nest Hub のマイクで応答する機能はない（Google がサードパーティにマイクを出していない）
- 録画・電気錠・宅配ボックス・センサカメラは未実装
- この公開ツリーにキャプチャ、分解 APK、個人の身分情報は含めていない

- Not an official support contract for the retired app
- No talk-back from a Nest Hub microphone (Google does not expose that mic to third-party surfaces)
- Recorded video, e-lock, delivery box, and sensor cameras are out of scope
- This public tree does not include packet captures, a decompiled APK, or anyone's identity material

## 仕組み / How it works

```
[玄関子機] --DECT/独自--> [親機] --LAN RTP (XOR 付き PCMA/H.264)--> [viana-ha]
                              |                                         |
                              +-- HTTPS/WSS VIANA (東京) <--------------+
                                                                        |
                                                              [Home Assistant]
```

シグナリングはクラウド、メディアは宅内、というハイブリッドです。同じ Wi-Fi にいても INVITE は UDP/5060 に出ません。SIP は登録と 15 秒ごとの NOTIFY だけです。メディアの「暗号」は RTP ヘッダ直後から始まる 8 バイト繰り返し XOR で、セッション鍵は接続キックの SDP `a=key-mgmt:` に載っています。

Signaling is cloud; media is LAN. Even on the same Wi-Fi there is no SIP INVITE on UDP/5060. SIP is registration plus a 15-second NOTIFY heartbeat. Media “encryption” is an 8-byte repeating XOR starting after the RTP header; session keys arrive in the connect-kick SDP as `a=key-mgmt:` lines.

詳細は [`docs/PROTOCOL.md`](docs/PROTOCOL.md) です。

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the protocol notes.

## リポジトリ構成 / Layout

| パス | 役割 |
|---|---|
| `crates/viana-protocol` | 身分発行、キック XML、SIP、SDP、LAN 発見 |
| `crates/viana-media` | XOR、RTP、H.264、PCMA、チャレンジ応答 |
| `crates/viana-ha` | 常駐デーモン。VIANA に繋がり、`127.0.0.1:7878` に HTTP/SSE を出す |
| `ha-integration/custom_components/panasonic_doorphone_connect` | 薄い Home Assistant カスタムコンポーネント |
| `assets/panasonic-ca.pem` | `*.s2.vianaaws.jp` 検証用のパナソニック CA（アプリ同梱の公開証明書） |
| `deploy/systemd/viana-ha.service` | systemd ユニット例 |

| Path | Role |
|---|---|
| `crates/viana-protocol` | Identity mint, kick XML, SIP, SDP, LAN discovery |
| `crates/viana-media` | XOR, RTP, H.264, PCMA, challenge-response |
| `crates/viana-ha` | Long-running daemon: VIANA client + HTTP/SSE on `127.0.0.1:7878` |
| `ha-integration/custom_components/panasonic_doorphone_connect` | Thin Home Assistant custom component |
| `assets/panasonic-ca.pem` | Panasonic CA shipped in the official app, used to verify `*.s2.vianaaws.jp` |
| `deploy/systemd/viana-ha.service` | Example systemd unit |

プロトコル実装は Rust、Home Assistant 側は Python の薄いシムです。キャプチャや Ghidra 作業メモはこの公開リポジトリにはありません。

Protocol work lives in Rust. The Home Assistant side is a thin Python shim. Captures and reverse-engineering notebooks are not in this public repository.

## 動かし方 / Running it

前提: Home Assistant と同じ LAN に親機があること。デーモンは HA と同じホストで動かす想定です（`network_mode: host` の Docker なら `127.0.0.1:7878` で届きます）。

Requirement: the base is on the same LAN as Home Assistant. The daemon is meant to run on the HA host (`127.0.0.1:7878` works if HA uses `network_mode: host`).

```bash
# 1. デーモン
cp assets/panasonic-ca.pem /opt/viana-ha/identity/ca.pem
cp config.toml.example /opt/viana-ha/config.toml
cargo build --release -p viana-ha
install -m 0755 target/release/viana-ha /opt/viana-ha/bin/viana-ha
# systemd の User= を実アカウントに合わせてから:
sudo systemctl enable --now viana-ha

# 2. HA カスタムコンポーネント
# ha-integration/custom_components/panasonic_doorphone_connect を
# <config>/custom_components/panasonic_doorphone_connect へコピーし、HA を再起動

# 3. 発見ファイル（Config Flow が URL とトークンを聞かないようにする）
# /opt/viana-ha/config.toml の auth_token を使って:
# <config>/.viana-ha-discovery.json
# { "daemon_url": "http://127.0.0.1:7878", "auth_token": "<token>" }

# 4. HA で「Doorphone Connect (Unofficial)」を追加し、親機のログインパスワードを入れ、
#    親機のペアボタンを押す
```

```bash
# 1. Daemon
cp assets/panasonic-ca.pem /opt/viana-ha/identity/ca.pem
cp config.toml.example /opt/viana-ha/config.toml
cargo build --release -p viana-ha
install -m 0755 target/release/viana-ha /opt/viana-ha/bin/viana-ha
# Point the systemd User= at a real account, then:
sudo systemctl enable --now viana-ha

# 2. HA custom component
# Copy ha-integration/custom_components/panasonic_doorphone_connect
# to <config>/custom_components/panasonic_doorphone_connect and restart HA

# 3. Discovery file so Config Flow never asks for a URL or token
# Using auth_token from /opt/viana-ha/config.toml:
# <config>/.viana-ha-discovery.json
# { "daemon_url": "http://127.0.0.1:7878", "auth_token": "<token>" }

# 4. Add “Doorphone Connect (Unofficial)” in HA, enter the base login
#    password, press the pair button on the base
```

自動化の例は [`ha-integration/custom_components/panasonic_doorphone_connect/AUTOMATIONS.md`](ha-integration/custom_components/panasonic_doorphone_connect/AUTOMATIONS.md) です。

Automation snippets live in [`ha-integration/custom_components/panasonic_doorphone_connect/AUTOMATIONS.md`](ha-integration/custom_components/panasonic_doorphone_connect/AUTOMATIONS.md).

## セキュリティ / Security

メディア経路の XOR は暗号ではありません。鍵は呼び出しごとに変わりますが、鍵を知っていれば RTP をその場で解けます。このブリッジは自分のセッション鍵だけを使います。他人のドアホンを遠隔から乗っ取る手順ではありません。

The media XOR is not cryptography. Keys rotate per call, but anyone who has the key can unwrap RTP on the wire. This bridge uses the keys of *its own* session. It is not a remote-takeover recipe for someone else's doorphone.

VIANA の身分発行には、公式アプリのネイティブライブラリに埋め込まれていたエコシステム秘密が必要です。パナソニックがそれを回すと、公式残存クライアントもこのブリッジも同時に止まります。

Minting a VIANA identity uses an ecosystem secret that shipped in the official app's native library. If Panasonic rotates it, leftover official clients and this bridge break together.

`kiki.dat` と `config.toml` は端末秘密です。リポジトリに入れないでください。

`kiki.dat` and `config.toml` are device secrets. Do not commit them.

## ライセンス / License

[MIT](LICENSE)。現状有姿、無保証。

[MIT](LICENSE). As-is, no warranty.

パナソニック、ドアホンコネクト、VIANA、Home Assistant、Google Home は各権利者の商標です。このソフトウェアはそれらと無関係です。

Panasonic, Doorphone Connect, VIANA, Home Assistant, and Google Home are trademarks of their owners. This software is independent of them.
