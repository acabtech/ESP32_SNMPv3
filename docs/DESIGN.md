# Design — ESP32-SNMPv3-Agent

Status: **M0 scaffold**. Interfaces below are drafting ground; the numbered
"scope lock" reflects decisions approved by the maintainer (2026-09-29).

## 1. Scope lock (v0.1)

| # | Decision | Detail |
|---|----------|--------|
| 1 | **Agent role only** | Responds to manager requests on UDP :161 (Get/GetNext/GetBulk/Set) **and** sends v3 traps/informs to a configured manager on UDP :162. No manager-role client code (we never initiate requests to other agents). |
| 2 | **Security = authPriv only** | USM (RFC 3414). **HMAC-SHA-256** auth (RFC 7860) + **AES-128 CFB** privacy (RFC 3826). All other auth/priv combos are out of scope for v0.1. |
| 3 | **SNMPv3 only** | No v1/v2c support at all; users pick a community-string library if needed. |
| 4 | **Day-one interop** | Zabbix 8 (dogfood target, PT Alat Cerdas Adikarya Bersama homelab) + Home Assistant `snmp` integration; net-snmp is the engineering tool. |
| 5 | **arduino-esp32 v3.x only** | IDF 5.x line. No backport to v2.x. CI matrix: `esp32`, `esp32s3`, `esp32s2`. |
| 6 | **No PSRAM** | All state in SRAM. Fixed buffers, bounded allocations. PSRAM-only features are deferred. |
| 7 | **GPL-3.0** | SPDX `GPL-3.0`. Public repo, Arduino Library Manager distribution. |
| 8 | **Flagship demo** | Bare board + DHT22 on pin 4 (default), caching pattern in the example. |
| 9 | **Registry standards** | `arduino-lint` (compliance: specification), GitHub Actions `compile-examples` on 3 FQBNs, semver tags, `library.properties` at root. |

## 2. Architecture

```
SnmpV3Agent (public API, singleton)
  └─ Agent core        state machine, UDP :161 pump, dispatch, error codes
       └─ USM          engineID, boots/time + timeliness, msgID replay cache,
       │               discovery reports (RFC 3414 §4 / §5)
       │    └─ crypto  HMAC-SHA-256 (RFC 7860) · AES-128-CFB (RFC 3826)
       │                → mbedtls → HW engines (ESP32 family)
       └─ MIB          tree: SNMPv2-MIB subset, SNMPv3-MIB subset, app OIDs
       └─ BER          ASN.1 codec (message, scopedPDU, varbinds)
       └─ Transport    LwIP UDP (WiFiUDP), trap socket :162
       └─ Persistence  NVS: engineBoots, engineID override, engineTime anchor
```

### Message flow on a fresh manager

1. Manager sends a request with **empty security parameters**.
2. Agent answers `Report(unknownEngineID)` carrying its engineID + boots/time
   (unauthenticated — this is the protocol's discovery round, not a "noAuth"
   security level).
3. Manager computes localized keys and re-sends with full authPriv security
   parameters; agent validates timeliness (`usmStatsNotInTimeWindows` flows
   handle boots/time drift), authenticates, decrypts, dispatches, and answers
   an authPriv Response.
4. Subsequent traffic is authPriv end-to-end; engineTime is kept by the agent
   and the *manager* keeps the boots/time pair authoritative per its cache.

### Engine state & NVS layout

| NVS slot | Type | Notes |
|----------|------|-------|
| `snmpEngineBoots` | u32 | Incremented on begin(); persisted monotonic counter |
| `snmpEngineTime` anchor | u32 | Wall-ish clock basis; maintained from `millis()` after boot |
| `engineID` override | up to 32 B | Optional; default is RFC 3411 §4: 0x80 `||` enterprise `||` hash(MAC) |

Boots **must** change on each restart (RFC 3414 §3.1.4) or NMS caches reject
the node; NVS persistence is therefore a correctness feature, not a nicety.

### Memory/CPU budget (SRAM-only, no PSRAM)

| Item | Budget |
|------|--------|
| RX buffer | 1536 B fixed (accepts msgMaxSize ≤ 1472; minimum 484 per RFC 3416) |
| TX buffer | 1536 B fixed |
| MIB tree | static/`mibRegister*`-allocated at setup, no runtime growth |
| Users | max 4 × (32+64+64 B) credentials + localized keys (SHA-256 32 B + AES-128 16 B each) |
| Replay cache | 32-entry ring of received msgIDs (16 B each) |
| Crypto working set | mbedtls context reused, no per-request malloc |
| Stack guard | encrypt+dispatch path profiled in M2; target < 4 kB stack |

Per-request CPU: ~2× HMAC-SHA-256 + AES-128 CFB over the PDU — comfortably
sub-millisecond on the hardware engines, non-blocking in `loop()`.

## 3. Testing strategy

1. **Host unit tests** (`tests/host/`) — no hardware, no Arduino SDK:
   BER round-trips, RFC 7860 HMAC-SHA-256 vectors, RFC 3826 AES-CFB vectors,
   RFC 3414 §A.3 key-localization vectors, GETNEXT/GETBULK walk correctness,
   timeliness state machine. The crypto interface has a software reference
   backend so these run anywhere.
2. **Interop** (`tests/interop/`) — `pysnmp_check.py` (get/walk/bulk/set over
   real UDP against a device or a pysnmp mock agent), net-snmp CLI sessions,
   Zabbix host + items, Home Assistant configuration.
3. **On-device soak** — 48 h uptime with Zabbix polling every 30 s, trap
   storm test, power-cycle ×50 verifying boots persistence.

## 4. Open items

- [x] **IANA PEN** — application filed (in progress); OID root below
      `enterprises.<PEN>` to be swapped in when granted. Not highlighted in
      code per maintainer direction.
- [x] GPL **`only`** confirmed (SPDX `GPL-3.0`).
- [x] pysnmp oracle pinned to **6.2.6** (SHA-2 auth protocol via
      `pysnmp.proto.secmod.rfc7860`; hlapi sync facade retained).
- [ ] Confirm GitHub org/account for the public repo
      (currently `acabtech/esp32-snmpv3-agent`, private; pushes via the
      `hamoodify` gh account).
- [ ] Verify net-snmp SHA-256 availability on Debian's build (must be ≥ 5.8
      with SHA-2 enabled) — affects the interop runbook, not the library.