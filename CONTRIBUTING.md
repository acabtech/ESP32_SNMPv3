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

## Documentation site

The docs are published with MkDocs Material at
<https://acabtech.github.io/ESP32_SNMPv3/>. The canonical sources are `docs/`
plus the READMEs in the repository root, `src/`, `tests/host/` and
`tests/interop/`; `scripts/docs.py` stages them into one tree and rewrites
cross-repo links before building.

Local preview (Python 3.10+):

```bash
python3 -m venv .venv-docs
. .venv-docs/bin/activate
pip install -r requirements-docs.txt
python scripts/docs.py serve     # http://127.0.0.1:8000/
```

`python scripts/docs.py build` runs the same strict build CI uses. Add new
pages to the `nav:` in `mkdocs.yml`; `--strict` fails on pages that are missing
from the nav or contain broken links.

## Coding style

- 2-space indent, Allman braces, 80-column, `snake_case` for non-API
  internals, `CamelCase` only for the public Arduino-facing types.
- No dynamic allocation on the hot path (`loop()` / dispatch / crypto).
- Comments cite RFC numbers + section for every security rule.

## Release process (maintainer)

The canonical, step-by-step checklist is [`docs/SUBMISSION.md`](docs/SUBMISSION.md).

1. Update `CHANGELOG.md` — move `[Unreleased]` to the next semver section.
2. Bump `version=` in `library.properties` to the same semver.
3. Run the gates locally:
   - `tests/host/run_host_tests.sh` (host suite green);
   - `arduino-cli compile` for `esp32`, `esp32s2`, `esp32s3` on every example;
   - `arduino-lint --compliance specification --library-manager submit
     --project-type library <copy-of-repo-named-ESP32-SNMPv3-Agent>`.
4. Commit, then tag and push: `git tag vX.Y.Z && git push origin main --tags`.
5. Submit to the Arduino Library Manager by opening a pull request against
   [`arduino/library-registry`](https://github.com/arduino/library-registry)
   that adds the repository URL (`https://github.com/acabtech/ESP32_SNMPv3`)
   to `repositories.txt` — or use the form at
   <https://librarymanager.arduino.cc/>. There is **no** `arduino-cli lib
   publish` subcommand; the registry PR (or form) is the submission.
6. After the registry bot's `arduino-lint` check passes and the PR is merged,
   the nightly index update makes the library installable:
   `arduino-cli lib update-index && arduino-cli lib search ESP32-SNMPv3-Agent`.
7. Update the README status table and badge URLs if needed.

## License

All contributions are GPL-3.0 by default. See [LICENSE](LICENSE).