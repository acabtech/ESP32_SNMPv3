# src/ — ESP32-SNMPv3-Agent library source

Module layout (M0 scaffold — interfaces are drafted, implementations land
per docs/ROADMAP.md):

| Path            | Responsibility                                      |
|-----------------|-----------------------------------------------------|
| `SnmpV3Agent.h` | Public API (final for v0.1) + Arduino-style singleton. |
| `SnmpV3Agent.cpp` | Agent state machine, UDP transport, dispatch (stub). |
| `ber/BER.h`     | ASN.1 BER codec primitives (host-compilable).       |
| `usm/USM.h`     | RFC 3414/7860/3826: keys, HMAC-SHA-256, AES-128-CFB, timeliness. |
| `usm/crypto.h`  | Crypto seam: SHA-256 + AES-128 block primitives.      |
| `usm/crypto_esp32.c` | mbedtls/HW-accelerated backend (device-only; host tests link `tests/host/soft` instead). |
| `mib/MIB.h`     | Managed-object tree (scalars, RW scalars, tables).   |

Design constraints (see docs/DESIGN.md):

- **Host-compilable core.** `ber/`, `usm/`, `mib/` must NOT pull in the
  Arduino SDK, so `tests/host/` can exercise BER round-trips, RFC 3414 key
  localization and the AES-CFB vectors on a plain PC with zero hardware.
  Only `SnmpV3Agent.*` touches Arduino/ESP-IDF types.
- **No dynamic allocation in the hot path.** Fixed 1536-byte rx/tx buffers,
  a pre-allocated MIB tree and a bounded user table. The `loop()` path must
  never `malloc`; only `addUser`/`register*` (setup time) may allocate.
- **Non-blocking everywhere.** Getter callbacks run synchronously while a
  varbind is encoded — sketches must return cached sensor values, not read
  the sensor from inside the getter (see the DHT22 example for the pattern).
- **No PSRAM assumption** (v0.1). All state lives in the chip's SRAM.