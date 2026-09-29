# Changelog

All notable changes to ESP32-SNMPv3-Agent. Format: Keep a Changelog 1.1.

## [Unreleased] — 0.1.0

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