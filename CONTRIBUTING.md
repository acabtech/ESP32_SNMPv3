# Contributing

Thanks for your interest in ESP32-SNMPv3-Agent (GPL-3.0, © 2026
PT Alat Cerdas Adikarya Bersama).

## Ground rules

- **GPL-3.0 licensed** — all contributions are GPL-3.0 by default.
- Focus on the v0.1 scope lock (`docs/DESIGN.md` §1): agent role, authPriv
  only (SHA-256 + AES-128), SNMPv3 only, arduino-esp32 v3.x.
- Milestones and exit criteria: `docs/ROADMAP.md`.

## Workflow

1. Open an issue first for anything non-trivial (esp. protocol behavior).
2. `main` is always green: `arduino-lint` must pass (specification
   compliance), example sketches must not rely on undefined behavior.
3. PRs need: a changelog entry, tests for protocol changes (`tests/host/`
   for host-testable logic; interop runbook updates for manager-specific
   caveats), and a reference to the RFC for any USM behavior.
4. Keep `ber/`, `usm/`, `mib/` free of Arduino/ESP-IDF includes
   (host-testable core). Only `src/SnmpV3Agent.*` touches the SDK.

## Coding style

- 2-space indent, Allman braces, 80-column, `snake_case` for non-API
  internals, `CamelCase` only for the public Arduino-facing types.
- No dynamic allocation on the hot path (`loop()` / dispatch / crypto).
- Comments cite RFC numbers + section for every security rule.