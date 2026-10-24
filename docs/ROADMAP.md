# Roadmap

Milestones with exit criteria. Current position: **M4 repo-side landed**
(2026-10-23, docs pass + CONTRIBUTING + changelog + registry metadata +
capstone kit + pysnmp mock agent; the Library Manager submission, semver tag,
and the M3 on-device soak remain maintainer/hardware-gated, see below).

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
vectors match RFC + pysnmp. On-device cross-check **DONE** (2026-10-24,
ESP32-S3 N16R8): the mbedtls backend was validated against pysnmp 6.2.6
over the wire — this surfaced and fixed a missing `mbedtls_sha256_starts()`
in `crypto_esp32.c` (see CHANGELOG).

## M2 — Agent engine
- UDP :161 pump (non-blocking), discovery reports, dispatch
  Get/GetNext/GetBulk/Set with correct error/exception oids
  (noSuchObject, noSuchInstance, endOfMibView, genErr, wrongValue…).
- MIB tree implementation; SNMPv2-MIB + SNMPv3-MIB subsets; app OIDs.
- NVS engine state (boots, time anchor, engineID override).
- Replay cache (msgID window).
- Enable CI `compile-examples` on `esp32`, `esp32s3`, `esp32s2`.

Exit: PASSED (2026-10-24) — pysnmp 6.2.6 authPriv get/walk against a real
ESP32-S3 board (net-snmp CLI was not installed on the test host; the pysnmp
checker is the equivalent oracle).

## M3 — Notifications + soak
- **v3 traps** (fire-and-forget) and **informs** (RFC 3416 §3.2.5 ack/retry,
  max 3 retries / 5 s total) — ✅ **code landed** (2026-10-22):
  `agentBuildNotification()` + the `AgentInform` retry state machine in
  `src/agent/AgentCore.c`; `sendTrap()`/`sendInform()` wired in
  `src/SnmpV3Agent.cpp`; host tests in `tests/host/test_notify.c`.
- 48 h Zabbix soak, power-cycle ×50, trap storm — ⏳ **hardware-gated**
  (requires a real board + NMS; not runnable in CI).
- Site: flash/PSRAM decision review for v0.2.

Exit: Zabbix + Home Assistant graphs live for 48 h with zero errors.
Remaining: the on-device soak (hardware-gated) — the notification code and
its host tests are complete.

## M4 — Ship
- Docs pass "grandchild test" — ✅ `docs/GETTING-STARTED.md`, the single
  end-to-end guide (flash → poll → Zabbix → HA → traps → troubleshooting),
  with the capstone demo folded in; interop runbooks remain the per-manager
  deep dives.
- CONTRIBUTING final — ✅ testing, PR checklist, release process, license.
- Changelog — ✅ `[0.1.0]` dated 2026-10-23 with the M4 section.
- Semver tag — ⏳ maintainer action (`git tag v0.1.0`).
- Registry submission (Arduino Library Manager) + badge — 🟡 badge added to
  README; `library.properties` registry-ready; submission is a maintainer
  action (`arduino-cli lib publish`).
- Capstone demo kit — ✅ folded into `docs/GETTING-STARTED.md` (DHT22 →
  SNMPv3 authPriv → Zabbix dashboard + HA card, wiring + BOM + firmware).
- Marketing one-pager — ✅ folded into the README ("What it does" +
  "Why SNMPv3 authPriv?").
- License/permissions review — ✅ GPL-3.0-only confirmed; SPDX in
  `library.properties`; attribution in README/CONTRIBUTING.
- Integration proof without hardware — ✅ `tests/interop/mock_agent.py`
  (pysnmp CommandResponder mimicking the board's OIDs + authPriv user).

Exit: `arduino-cli lib install ESP32-SNMPv3-Agent` works for a stranger.
Repo-side prerequisites are complete; the submission + tag are the only
remaining maintainer actions.