# ESP32-SNMPv3-Agent

SNMPv3 (**USM, authPriv**) agent for **ESP32 / ESP32-S2 / ESP32-S3** sensor
telemetry over Wi-Fi.

Supports SNMPv3-only (no v1/v2c), hardware-accelerated security, GPL-3.0.

If you need SNMP v1/v2c there are other alternative libraries to use:
- https://github.com/0neblock/Arduino_SNMP
- https://github.com/syntax1269/SNMP_Embedded

![CI](https://img.shields.io/github/actions/workflow/status/acabtech/esp32-snmpv3-agent/ci.yml?label=lint%2Ftests)
![License](https://img.shields.io/badge/license-GPL--3.0-blue)
![Arduino Library Manager](https://img.shields.io/badge/Arduino-Library%20Manager-00979D?logo=arduino)
![SNMPv3](https://img.shields.io/badge/SNMPv3-authPriv%20only-informational)

## What it does

Turn any ESP32 board into an SNMPv3 agent that:

- **Answers polls** from Zabbix, Home Assistant, PRTG, net-snmp, or any SNMPv3
  manager with `Get` / `GetNext` / `GetBulk` / `Set` over UDP :161 — this is how
  sensor readings get collected and graphed.
- **Sends traps and informs** to a configured manager over UDP :162 (reboots,
  alarms, threshold crossings).
- **Secures every byte** with USM *authPriv only* — HMAC-SHA-256 authentication
  (RFC 7860) + AES-128 CFB privacy (RFC 3826), using the ESP32 family
  **hardware-accelerated SHA-256 and AES engines** via ESP-IDF's mbedtls layer.

## Why SNMPv3 authPriv?

SNMPv1/v2c send community strings in plaintext — anyone on the network can read
them. SNMPv3 authPriv adds:

- **Authentication** (HMAC-SHA-256) — proves the message came from this device
  and wasn't tampered with.
- **Privacy** (AES-128 CFB) — encrypts the payload so only the manager can read it.
- **Replay protection** — message IDs and engine boots/time prevent captured
  traffic from being reused.

An `authPriv` message is *both* authenticated *and* encrypted — the only mode
this library implements. See [SNMPv3 in 10 minutes](docs/SNMPV3-BACKGROUND.md)
for the no-jargon primer.

## Status

| Milestone | Content | State |
|-----------|---------|-------|
| M0 | Repo scaffold, API surface, CI (lint), interop runbooks | ✅ |
| M1 | BER codec + USM keys/crypto core (host-tested vs RFC vectors) | ✅ |
| M2 | Agent engine: dispatch, MIB tree, Get/GetNext/GetBulk/Set; NVS engine state | ✅ |
| M3 | v3 traps + informs (code + host tests); on-device soak | 🟡 code landed, soak pending |
| M4 | Docs pass, CONTRIBUTING, changelog, registry submission, capstone kit | 🟡 repo-side landed, submission pending |

> **New here?** Read the [Getting Started guide](docs/GETTING-STARTED.md) — the
> single end-to-end walkthrough: flash → poll → Zabbix → Home Assistant → traps
> → troubleshooting.

## Install & quick start

1. Install the library from the Arduino Library Manager
   (search *ESP32-SNMPv3-Agent*), or copy this repo into
   `~/Arduino/libraries/esp32-snmpv3-agent`:

   ```bash
   arduino-cli lib install ESP32-SNMPv3-Agent
   ```

2. The whole API is three calls:

   ```cpp
   #include <SnmpV3Agent.h>

   SNMPv3.begin();
   SNMPv3.addUser("telemetry", "auth-passphrase", "priv-passphrase");
   SNMPv3.registerScalar("1.3.6.1.4.1.67018.1.1.0", getTemperature);
   ```

3. Flash the flagship example and poll it:

   ```bash
   arduino-cli compile --fqbn esp32:esp32:esp32 examples/dht22_telemetry
   arduino-cli upload -p /dev/ttyUSB0 examples/dht22_telemetry

   snmpget -v3 -l authPriv -u telemetry -a SHA-256 -A auth-passphrase \
           -x AES -X priv-passphrase udp:192.168.1.50:161 \
           1.3.6.1.4.1.67018.1.1.0
   ```

   Full walkthrough (Zabbix, Home Assistant, traps): [Getting Started](docs/GETTING-STARTED.md).

### Hardware

| Board | Core | PSRAM needed? |
|-------|------|---------------|
| ESP32 | arduino-esp32 v3.x | No |
| ESP32-S2 | arduino-esp32 v3.x | No |
| ESP32-S3 | arduino-esp32 v3.x | No |

Flagship example: **DHT22 → pin 4**. The entire agent runs in the chip's SRAM.

## Interop (day one targets)

- [**Zabbix**](docs/interop/zabbix.md) — the project is dogfooded against the
  PT Alat Cerdas Adikarya Bersama Zabbix 8 deployment.
- [**Home Assistant**](docs/interop/home-assistant.md) — `snmp` sensor
  integration, v3 authPriv.
- [**net-snmp**](docs/interop/net-snmp.md) — the engineering toolchain:
  `snmpget/walk/bulk/set`, `snmptrapd`, engine-cache troubleshooting.
- [**pysnmp**](tests/interop/pysnmp_check.py) — scripted interop checks for CI.
- [**Mock agent**](tests/interop/mock_agent.py) — a pysnmp agent that mimics the
  board's OIDs, so you can validate Zabbix/HA configs **without hardware**.

## Security notes

- USM passes SHA-256 + AES-128 in **both directions**; the localized keys
  (RFC 3414) are derived once at `addUser()` time.
- `engineBoots`/`engineTime` are persisted to NVS so reboots don't trip
  manager timeliness checks; `msgID` replays are dropped.
- Change the demo passphrases *before* exposing a board to any network you
  don't fully control.

## Documentation

| Doc | What's in it |
|-----|--------------|
| [Getting Started](docs/GETTING-STARTED.md) | End-to-end: flash → poll → Zabbix → HA → traps → troubleshooting |
| [Interop runbooks](docs/interop/) | Per-manager deep dives (Zabbix, Home Assistant, net-snmp) |
| [SNMPv3 in 10 minutes](docs/SNMPV3-BACKGROUND.md) | No-jargon background for reviewers/customers |
| [Design](docs/DESIGN.md) | Architecture, scope lock, memory budget |
| [Roadmap](docs/ROADMAP.md) | Milestones + exit criteria |
| [src/README](src/README.md) | Module layout + API reference |
| [tests/host/README](tests/host/README.md) | Host test suite |
| [CONTRIBUTING](CONTRIBUTING.md) | Workflow, testing, release process |

## License

GPL-3.0 (see [LICENSE](LICENSE)) — © 2026 PT Alat Cerdas Adikarya Bersama.
Contributions welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
