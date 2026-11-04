# Changelog

All notable changes to ESP32-SNMPv3-Agent. Format: Keep a Changelog 1.1.

## [Unreleased]

### Added (documentation site)
- Searchable MkDocs Material documentation site at
  <https://acabtech.github.io/ESP32_SNMPv3/>, deployed to GitHub Pages by
  `.github/workflows/docs.yml`.
- `scripts/docs.py` stages `docs/` plus the root, `src/`, and `tests/` READMEs
  into one tree and rewrites cross-repo links, so the site and GitHub stay in
  sync without duplicated Markdown.
- `docs/interop/index.md`: landing page for the Zabbix, Home Assistant, and
  net-snmp runbooks.

## [0.1.2] — 2026-11-01

### Fixed (Arduino Library Manager submission)
- `library.properties`: `url=` now points at the actual repository
  (`https://github.com/acabtech/ESP32_SNMPv3`). The previous value
  (`.../esp32-snmpv3-agent`) returned 404 to arduino-lint (LP042), which would
  have blocked Library Manager acceptance. This is the reason for the 0.1.2
  release: the v0.1.1 tag carried the broken URL.
- Added [`src/ESP32-SNMPv3-Agent.h`](src/ESP32-SNMPv3-Agent.h), a forwarding
  header whose filename matches `name=` in `library.properties`, clearing the
  arduino-lint LS008 best-practice warning.
- `library.properties`: added `includes=SnmpV3Agent.h` so IDEs resolve the
  public API header explicitly.

### Added (submission tooling + docs)
- `docs/SUBMISSION.md`: the end-to-end Library Manager checklist — registry
  requirements, pre-flight lint/tests, release tagging, the exact
  `arduino/library-registry` pull request, post-acceptance verification, and
  common rejection causes.
- CI lint job now runs `arduino-lint --library-manager submit` instead of
  `--library-manager false`, so the Library Manager acceptance rules (including
  the `url=` check) gate every push/PR.
- Corrected the release process in `CONTRIBUTING.md` and `docs/ROADMAP.md`:
  there is no `arduino-cli lib publish` subcommand; submission is a pull
  request (or web form) against `arduino/library-registry`.

### Fixed (examples)
- `examples/dht22_telemetry` and `examples/trap_notification` now guard
  their Wi-Fi credentials / trap-manager IP with `#ifndef`, matching
  `minimal_authpriv`, so the documented `priv/flash.sh` `-D` build-time
  injection works without macro-redefinition warnings.
- Removed stale "(M0 scaffold)" / "core not built yet" startup messages from
  the examples; a `begin()` failure now reports "check Wi-Fi/NVS".

### Documentation (this rev)
- `README.md`: install section now states that the Library Manager
  submission is pending and offers `arduino-cli lib install --git-url` as the
  works-today path; documents both `<SnmpV3Agent.h>` and
  `<ESP32-SNMPv3-Agent.h>` as equivalent public headers.
- `docs/GETTING-STARTED.md`: same install guidance and the
  `ESP32-SNMPv3-Agent` library-folder name.
- `src/README.md`: module table includes the new forwarding header and links
  the submission guide.
- `docs/DESIGN.md`: open item now confirms the public repository
  (`acabtech/ESP32_SNMPv3`) and lists the registry PR / soak as the only
  outstanding work.
- `docs/ROADMAP.md`: M4 exit criteria reflect the local `v0.1.2` tag and the
  remaining push + registry PR.
- `tests/host/README.md`: documents the current 2,783-check suite.

## [0.1.1] — 2026-10-24

### Added (hardware test tooling, 2026-10-24)
- `tests/hardware/serial_capture.py`: configurable USB-serial console
  capture (port/baud/duration/expect, optional reset) for on-device tests.
- `priv/` (gitignored): machine-local secrets + scripts. `priv/secrets.env`
  holds Wi-Fi, SNMPv3, board, and Zabbix credentials; `priv/flash.sh`
  injects the Wi-Fi SSID/passphrase at build time via `-D` (the example now
  guards `WIFI_SSID`/`WIFI_PASS` with `#ifndef`), `priv/poll.sh` drives the
  pysnmp checker, and `priv/zbx_setup.py` registers the host + items in
  Zabbix 8.0 via the API (Bearer-token auth, SNMP interface `interfaceid`).

### Verified (Zabbix 8.0 interop, 2026-10-24)
- ESP32-S3 (N16R8) answers SNMPv3 authPriv (SHA-256 + AES-128) from both the
  build host and the Zabbix VM across the IoT VLAN boundary; Zabbix 8.0
  collects `app.uptime` / `app.freeheap` with no errors.

### Fixed (on-device hardware validation, 2026-10-24)
- `src/usm/crypto_esp32.c`: `crypto_sha256_init()` called
  `mbedtls_sha256_init()` but never `mbedtls_sha256_starts()`, so the
  incremental SHA-256 ran from a zeroed state (no IV loaded). Every
  localized key and HMAC computed on real silicon was therefore wrong, and
  the agent rejected all authenticated requests with `usmStatsWrongDigests`
  (surfaced to the manager as "Wrong SNMP PDU digest"). Found by the first
  on-device interop test (ESP32-S3 N16R8, pysnmp 6.2.6 authPriv); fixed by
  calling `mbedtls_sha256_starts(m, 0)` in `crypto_sha256_init()`. The host
  suite (which links `crypto_soft`) could not catch this — the device-only
  crypto seam is now validated on hardware.

## [0.1.0] — 2026-10-23

### Changed
- Example and app OIDs now live under the granted **IANA PEN 67018**
  (`enterprises.67018` = `1.3.6.1.4.1.67018`, PT Alat Cerdas Adikarya
  Bersama) — the placeholder enterprise number is gone from src, examples,
  docs, and tests; the wire oracles were regenerated accordingly.

### Added (M3 — notifications, this rev)
- `src/agent/AgentCore.c`: `agentBuildNotification()` builds authPriv v3
  Trap/Inform messages (varbind list = sysUpTime.0, snmpTrapOID.0, payload);
  the `AgentInform` retry state machine (`agentInformStart`/`Tick`/`Ack`)
  implements RFC 3416 §3.2.5 ack/retry — max 3 retries within a 5 s budget.
- `src/SnmpV3Agent.cpp`: `sendTrap()` (fire-and-forget) and `sendInform()`
  (bounded blocking wait for the manager Response) wired to the UDP :162
  notification socket; `setTrapManager()` target honoured.
- `tests/host/test_notify.c`: trap/inform construction (MAC + CFB verify),
  retry timing, and acknowledgement matching (matching / wrong request-id /
  tampered MAC).

### Added (M2 — agent engine)
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

### Removed (this rev — ESP32 compile gate)
- `src/SNMPv3.cpp` (corrupted JSON, not C++) and `src/SNMPv3.h` (unused
  alternate API) — abandoned "First attempt" leftovers that broke the
  arduino-cli ESP32 build. All three examples now compile on
  `esp32`, `esp32s3`, and `esp32s2`.

### Fixed (this rev — CI compile gate + warnings)
- `src/usm/store_esp32.c` → `store_esp32.cpp`: the NVS store uses the C++
  `Preferences` API and failed the ESP-side compile gate as C
  (`Preferences.h: error: unknown type name 'class'`). Renamed so the
  Arduino build compiles it as C++ (linkage stays `extern "C"` via store.h).
- `src/mib/MIB.c`: removed unused `properPrefix` (`-Wunused-function`).
- `src/SnmpV3Agent.cpp`: `WiFiUDP::flush()` → `clear()` (deprecated in
  arduino-esp32 v3.x).

### Added (M4 — ship)
- `docs/GETTING-STARTED.md`: the single end-to-end guide — flash → poll
  (net-snmp) → Zabbix → Home Assistant → traps → troubleshooting, with the
  DHT22 capstone demo (BOM, wiring, OIDs) folded in. Links to the interop
  runbooks for per-manager deep dives.
- `tests/interop/mock_agent.py`: a runnable pysnmp `CommandResponder` that
  mimics the board's OIDs (`1.3.6.1.4.1.67018.*`) with the same authPriv
  user, so Zabbix/Home Assistant configs can be validated **without
  hardware**.
- `CONTRIBUTING.md`: finalized with testing instructions, PR checklist,
  release process, and license note.
- `README.md`: Library Manager badge, "Why SNMPv3 authPriv?" rationale,
  hardware table, three-call quick example, and a documentation index;
  status table updated (M4 marked 🟡 repo-side landed).
- `library.properties`: registry-ready metadata verified (name, version,
  author, sentence, paragraph, category, url, architectures, license).
- `docs/DESIGN.md`: scope lock items 7–9 updated (SPDX `GPL-3.0-only`,
  capstone kit, registry standards).

### Fixed (M4 — docs + tooling)
- `docs/ROADMAP.md`: M4 exit criteria clarified; M3 soak noted as
  hardware-gated and deferred.
- `README.md`: fixed the "SMTPv3" typo; consolidated the scattered
  getting-started/one-pager/capstone content into `docs/GETTING-STARTED.md`.
- `tests/interop/pysnmp_check.py`: ported to the pysnmp 6.2.6 asyncio API
  (`pysnmp.hlapi.asyncio`) — the synchronous `pysnmp.hlapi` facade the script
  used no longer exists in the pinned version, so every command failed at
  import. Walk/bulk are now subtree-bounded, and client-side errors exit 2
  with a clean message instead of a traceback.
- `tests/interop/README.md`: documented the mock agent and the asyncio-based
  checker, including the mock's OID table and run instructions.
- Python tooling now uses a **test-scoped `tests/.venv/`** (already covered
  by the `.venv/` gitignore rule) instead of the ephemeral `/tmp/pv` scratch
  path, so the documented commands survive a reboot: `tests/interop/README.md`,
  `tests/interop/mock_agent.py`, `tests/interop/pysnmp_check.py`,
  `tests/host/README.md`, and `tests/host/Makefile`
  (`PY ?= ../.venv/bin/python`).
- `tests/host/vgen/gen_vectors.py`: dropped the hardcoded
  `/tmp/pv/lib/python3.13/site-packages` `sys.path` hack (ephemeral *and*
  version-pinned — wrong on Python 3.14). The generator now relies on being
  run with the venv interpreter, as documented; regenerated vectors are
  byte-identical.