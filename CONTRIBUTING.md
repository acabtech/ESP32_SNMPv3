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

## Testing

- **Host tests** (no hardware): `cd tests/host && ./run_host_tests.sh`
  Must be green before any PR is opened.
- **Interop checks**: `tests/interop/pysnmp_check.py` against a device
  or mock agent; run manually before merging protocol changes.
- **Compile examples**: `arduino-cli compile --fqbn esp32:esp32:esp32`
  (and `esp32s3`, `esp32s2`) must pass on every PR.

## PR checklist

- [ ] Host test suite passes (`run_host_tests.sh` green).
- [ ] Examples compile for all three FQBNs (`esp32`, `esp32s3`, `esp32s2`).
- [ ] Changelog entry added under the appropriate milestone.
- [ ] RFC reference cited for any USM behavior change.
- [ ] No Arduino/ESP-IDF includes in `ber/`, `usm/`, `mib/` (host-testable core).
- [ ] No dynamic allocation on the hot path.

## Coding style

- 2-space indent, Allman braces, 80-column, `snake_case` for non-API
  internals, `CamelCase` only for the public Arduino-facing types.
- No dynamic allocation on the hot path (`loop()` / dispatch / crypto).
- Comments cite RFC numbers + section for every security rule.

## Release process (maintainer)

1. Update `CHANGELOG.md` — move `[Unreleased]` to `[0.1.0]` (or next semver).
2. Verify `arduino-lint` passes (specification compliance).
3. Tag the release: `git tag v0.1.0 && git push --tags`.
4. Submit to the Arduino Library Manager:
   `arduino-cli lib publish --library .` (requires a Library Manager account).
5. Update the README status table and badge URLs if needed.
6. Push to the `acabtech/esp32-snmpv3-agent` GitHub repo.

## License

All contributions are GPL-3.0 by default. See [LICENSE](LICENSE).