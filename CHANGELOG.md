# Changelog

All notable changes to ESP32-SNMPv3-Agent. Format: Keep a Changelog 1.1.

## [Unreleased] — 0.1.0

### Added (M2 — agent engine, this rev)
- `src/agent/AgentCore.c`: request gate + dispatch — discovery reports, and
  Get/GetNext/GetBulk/Set with RFC 3412 error/exception OIDs.
- MIB tree (`src/mib/MIB.c`): SNMPv2-MIB + SNMPv3-MIB subsets, app OIDs,
  lexicographic instance ordering (`mibArcCmp`).
- NVS persistence (`src/usm/store.h` + `store_esp32.cpp`): snmpEngineBoots
  and the engineID override survive reboots via the ESP32 `Preferences`
  wrapper (RFC 3414 §2.3).
- `tests/host`: agent + store suites (boot counter, engineID round-trip,
  dispatch error paths).

### Added (M1 — BER codec + USM core, host-tested)
- `src/ber/BER.c`: full codec (lengths, INTEGER, OID, varbinds, PDU,
  scopedPDU, v3 message envelope) — bounds-checked encode + decode.
- `src/usm/USM.c`: SHA-256 passphrase hashing & key localization
  (RFC 7860 §9.3), HMAC-SHA-256 (RFC 2104/7860), AES-128-CFB with
  RFC 3826 IV (boots‖time‖salt), securityParameters serialization,
  timeliness ±150 s window.
- `src/usm/crypto.h` crypto seam + `crypto_esp32.c` mbedtls backend
  (hardware SHA-256/AES on ESP32/S2/S3; on-device cross-check in M2).
- Host test suite (`tests/host`): 2600+ checks passing — SHA-256/AES
  primitives, BER fuzz + known answers, USM vectors against
  pysnmp 6.2.6 / hashlib / cryptography oracles, full authPriv message
  verify (MAC + decrypt + dispatch). CI `host-tests` job enabled.
- `tests/host/vgen/gen_vectors.py` oracle generator (K-tables, S-boxes,
  vectors, wire samples) with self-checking BER encoder.

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

### Fixed (this rev — CI compile gate + warnings)
- `src/usm/store_esp32.c` → `store_esp32.cpp`: the NVS store uses the C++
  `Preferences` API and failed the ESP-side compile gate as C
  (`Preferences.h: error: unknown type name 'class'`). Renamed so the
  Arduino build compiles it as C++ (linkage stays `extern "C"` via store.h).
- `src/mib/MIB.c`: removed unused `properPrefix` (`-Wunused-function`).
- `src/SnmpV3Agent.cpp`: `WiFiUDP::flush()` → `clear()` (deprecated in
  arduino-esp32 v3.x).