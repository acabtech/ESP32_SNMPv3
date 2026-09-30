# Roadmap

Milestones with exit criteria. Current position: **M2 code landed**
(2026-09-30, `store_esp32.cpp` NVS store; on-device net-snmp exit pending,
see below).

## M0 — Scaffold (✅)
- Repo structure per Arduino library spec, `library.properties`, GPL-3.0
  LICENSE, keywords.txt, README, CONTRIBUTING, CHANGELOG.
- Public API surface (`src/SnmpV3Agent.h`) — **final for v0.1**.
- Module interfaces: `ber/BER.h`, `usm/USM.h`, `mib/MIB.h`.
- Example sketches: `dht22_telemetry`, `minimal_authpriv`, `trap_notification`.
- CI: `arduino-lint` (specification compliance) green.
- Interop runbooks: Zabbix, Home Assistant, net-snmp, pysnmp checker.

Exit: `arduino-lint` passes; examples compile against stub API
(compile-examples job is gated on workflow_dispatch until M1 lands).

## M1 — Codec + USM core (host-tested) ✅
- **BER codec** (`src/ber/BER.c`): lengths, INTEGER, OID, varbind, PDU,
  scopedPDU, full v3 message envelope — decode + encode.
- **USM layer** (`src/usm/USM.c`): SHA-256 passwordToKey/key localization
  (RFC 7860 §9.3), HMAC-SHA-256 with 24-octet MAC (RFC 7860), AES-128-CFB
  with boots‖time‖salt IV (RFC 3826), msgFlags/securityParameters,
  timeliness ±150 s.
- **Crypto seam** (`src/usm/crypto.h` + `crypto_esp32.c` mbedtls backend;
  host tests use the `tests/host/soft` reference).
- **Oracle suite**: pysnmp 6.2.6 localkey + Python hmac/cryptography + a
  self-checking BER encoder; vectors + wire samples in `tests/host/vec`.
  Covers key localization, HMAC, CFB (incl. partial tail + chaining), and a
  full authPriv GetRequest (MAC verify + decrypt + dispatch parse).
- `tests/host/run_host_tests.sh` green: 2600+ checks, 0 failures; wired
  into CI (`host-tests` job).

Exit: PASSED — host suite green on a bare PC with a C compiler only;
vectors match RFC + pysnmp. Remaining on-device item: cross-check the
mbedtls backend against `crypto_soft` on real silicon (deferred to M2 per
maintainer — hardware access lands later).

## M2 — Agent engine
- UDP :161 pump (non-blocking), discovery reports, dispatch
  Get/GetNext/GetBulk/Set with correct error/exception oids
  (noSuchObject, noSuchInstance, endOfMibView, genErr, wrongValue…).
- MIB tree implementation; SNMPv2-MIB + SNMPv3-MIB subsets; app OIDs.
- NVS engine state (boots, time anchor, engineID override).
- Replay cache (msgID window).
- Enable CI `compile-examples` on `esp32`, `esp32s3`, `esp32s2`.

Exit: net-snmp walk/bulk/set against a real board, authPriv only.

## M3 — Notifications + soak
- v3 traps (fire-and-forget) and informs (RFC 3416 §3.2.5 ack/retry/until
  confirm, max 3 retries / 5 s total).
- 48 h Zabbix soak, power-cycle ×50, trap storm.
- Site: flash/PSRAM decision review for v0.2.

Exit: Zabbix + Home Assistant graphs live for 48 h with zero errors.

## M4 — Ship
- Docs pass "grandchild test"; CONTRIBUTING final; changelog; semver tag.
- Registry submission (Arduino Library Manager) + badge.
- Capstone demo kit: DHT22 → SNMPv3 authPriv → Zabbix dashboard,
  plus HA card. Marketing one-pager + license/permissions review.

Exit: `arduino-cli lib install ESP32-SNMPv3-Agent` works for a stranger.