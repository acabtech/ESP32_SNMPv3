# Changelog

All notable changes to ESP32-SNMPv3-Agent. Format: Keep a Changelog 1.1.

## [Unreleased] — 0.1.0

### Added (M0 — repository scaffold)
- Public API surface (`src/SnmpV3Agent.h`): begin/loop, addUser (authPriv,
  SHA-256 + AES-128), setEngineId, registerScalar (RO/RW), registerTable
  (experimental), setTrapManager, sendTrap/sendInform, engineBoots.
- Module interfaces: `ber/BER.h` (ASN.1 BER), `usm/USM.h` (RFC 3414/7860/3826
  keys + crypto + timeliness), `mib/MIB.h` (managed-object tree).
- Examples: `dht22_telemetry`, `minimal_authpriv`, `trap_notification`.
- Interop runbooks: Zabbix, Home Assistant, net-snmp; `pysnmp_check.py`
  checker script; host-test plan.
- CI: `arduino-lint` (specification compliance) on push/PR; gated
  `compile-examples` workflow (esp32/esp32s3/esp32s2).
- Metapackage: library.properties, LICENSE (GPL-3.0), keywords, README,
  DESIGN/ROADMAP/BACKGROUND docs.

### Security model (v0.1, locked)
- SNMPv3 only, agent role only, USM authPriv only (HMAC-SHA-256 + AES-128).
- engineBoots/engineTime persisted via NVS; replay msgID cache; RFC 3414
  discovery report exchange.