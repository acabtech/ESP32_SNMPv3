# ESP32-SNMPv3-Agent

SNMPv3 (**USM, authPriv**) agent for **ESP32 / ESP32-S2 / ESP32-S3** sensor
telemetry over Wi-Fi. v3-only, hardware-accelerated security, GPL-3.0.

![CI](https://img.shields.io/github/actions/workflow/status/alatcerdas/esp32-snmpv3-agent/ci.yml?label=lint%2Ftests)
![License](https://img.shields.io/badge/license-GPL--3.0-blue)

## What it does

The device becomes a managed SNMPv3 node:

- **Managers poll it** (Zabbix, Home Assistant, PRTG, net-snmp…) with
  `Get` / `GetNext` / `GetBulk` / `Set` over UDP :161 — this is how sensor
  readings get collected and graphed.
- **It notifies managers** with v3 traps and informs on UDP :162 (reboots,
  alarms, threshold crossings).
- **Security in every byte**: USM *authPriv only* — HMAC-SHA-256
  authentication (RFC 7860) + AES-128 CFB privacy (RFC 3826), using the
  ESP32 family **hardware-accelerated SHA-256 and AES engines** via
  ESP-IDF's mbedtls layer. No plaintext community strings, ever.

Deliberately, **v0.1 is SNMPv3-only** (no v1/v2c) — pick a community-string
library if that's what a deployment needs. See `docs/DESIGN.md` for the full
scope lock, and `docs/SNMPV3-BACKGROUND.md` for the protocol primer.

## Status

| Milestone | Content | State |
|-----------|---------|-------|
| M0 | Repo scaffold, API surface, CI (lint), interop runbooks | ✅ this rev |
| M1 | BER codec + USM keys/crypto core (host-tested vs RFC vectors) | ⏳ next |
| M2 | Agent engine: dispatch, MIB tree, Get/GetNext/GetBulk/Set | ⏳ |
| M3 | v3 traps + informs, NVS engine state | ⏳ |
| M4 | Zabbix + Home Assistant integration proof, registry submission | ⏳ |

Roadmap & exit criteria: [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Getting started

1. Install the library from the Arduino Library Manager
   (search *ESP32-SNMPv3-Agent*), or copy this repo into
   `~/Arduino/libraries/esp32-snmpv3-agent`.
2. Open an example — `dht22_telemetry` is the flagship:

   ```bash
   arduino-cli compile --fqbn esp32:esp32:esp32 examples/dht22_telemetry
   arduino-cli upload -p /dev/ttyUSB0 examples/dht22_telemetry
   ```

3. Poll the board:

   ```bash
   snmpget -v3 -l authPriv -u telemetry -a SHA-256 -A auth-passphrase \
           -x AES -X priv-passphrase udp:192.168.1.50:161 \
           1.3.6.1.4.1.99999.1.1.0
   ```

### Hardware

- Board: ESP32, ESP32-S2 or ESP32-S3 (arduino-esp32 **v3.x** core).
- Flagship example: **DHT22 → pin 4**.
- No PSRAM required; the agent runs inside the chip's SRAM.

## Interop (day one targets)

- [**Zabbix**](docs/interop/zabbix.md) — the project is dogfooded against the
  PT Alat Cerdas Adikarya Bersama Zabbix 8 deployment.
- [**Home Assistant**](docs/interop/home-assistant.md) — `snmp` sensor
  integration, v3 authPriv.
- [**net-snmp**](docs/interop/net-snmp.md) — the engineering toolchain:
  `snmpget/walk/bulk/set`, `snmptrapd`, engine-cache troubleshooting.
- [**pysnmp**](tests/interop/pysnmp_check.py) — scripted interop checks for CI.

## Security notes

- USM passes SHA-256 + AES-128 in **both directions**; the localized keys
  (RFC 3414) are derived once at `addUser()` time.
- `engineBoots`/`engineTime` are persisted to NVS so reboots don't trip
  manager timeliness checks; `msgID` replays are dropped.
- Change the demo passphrases *before* exposing a board to any network you
  don't fully control.

## License

GPL-3.0 (see [LICENSE](LICENSE)) — © 2026 PT Alat Cerdas Adikarya Bersama. Contributions
welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).