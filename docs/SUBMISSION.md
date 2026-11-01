# Arduino Library Manager submission

This is the maintainer checklist for publishing **ESP32-SNMPv3-Agent** through
the official Arduino Library Manager. Everything that can live in the
repository is implemented; only the registry pull request (which needs the
maintainer's GitHub account) remains.

## What Library Manager requires

| Requirement | Where it lives | Status |
|-------------|----------------|--------|
| Public Git repository reachable over HTTPS | `https://github.com/acabtech/ESP32_SNMPv3` | ✅ |
| `library.properties` at the repository root | [`library.properties`](../library.properties) | ✅ |
| `url=` points at the repository root (not a fork/redirect) | `url=https://github.com/acabtech/ESP32_SNMPv3` | ✅ |
| `name`, `version` (semver), `author`, `maintainer`, `sentence`, `paragraph`, `category`, `architectures`, `license` | `library.properties` | ✅ |
| SPDX license identifier + `LICENSE` at root | `GPL-3.0-only`, [`LICENSE`](../LICENSE) | ✅ |
| `architectures` supported by a registered platform | `esp32` (arduino-esp32) | ✅ |
| Primary header matching the library name | [`src/ESP32-SNMPv3-Agent.h`](../src/ESP32-SNMPv3-Agent.h) | ✅ |
| `keywords.txt` | [`keywords.txt`](../keywords.txt) | ✅ |
| Examples inside `examples/<name>/<name>.ino` | 3 examples | ✅ |
| No sketches outside `examples/` / `extras/` | checked in CI | ✅ |
| Release tag matching `version=` | `v0.1.2` | ✅ (push the tag) |
| `arduino-lint --library-manager submit` clean | CI lint job | ✅ |
| Library compiles for every advertised architecture | `compile-examples` CI matrix (esp32 / s2 / s3) | ✅ |

> `arduino-cli` has **no** `lib publish` subcommand. The submission is a pull
> request (or the web form, which opens the same PR) against
> [`arduino/library-registry`](https://github.com/arduino/library-registry).

## Pre-flight (local)

The repository name must match `name=` for arduino-lint rule LS003, so lint a
copy under the declared name:

```bash
rm -rf /tmp/arduino-lint && mkdir -p /tmp/arduino-lint/ESP32-SNMPv3-Agent
tar --exclude=.git --exclude=.venv --exclude=dist \
    -cf - . | tar -xf - -C /tmp/arduino-lint/ESP32-SNMPv3-Agent

arduino-lint --compliance specification \
             --library-manager submit \
             --project-type library \
             /tmp/arduino-lint/ESP32-SNMPv3-Agent
```

Expected: `Linter results for projects: no errors or warnings`.

Also run the other gates:

```bash
tests/host/run_host_tests.sh

for fqbn in esp32:esp32:esp32 esp32:esp32:esp32s2 esp32:esp32:esp32s3; do
  for sketch in examples/*/; do
    arduino-cli compile --fqbn "$fqbn" --library "$PWD" "$sketch"
  done
done
```

## Release the version the registry will fetch

Library Manager reads the latest **tag**, not `main`, so the metadata fix must
be in a tag:

```bash
# library.properties version= and CHANGELOG must already agree
git commit -am "release: v0.1.2 — Library Manager submission metadata"
git tag -a v0.1.2 -m "ESP32-SNMPv3-Agent v0.1.2"
git push origin main --tags
```

Confirm the tag carries the corrected URL:

```bash
git show v0.1.2:library.properties | grep '^url='
# url=https://github.com/acabtech/ESP32_SNMPv3
```

## Submit

1. Fork <https://github.com/arduino/library-registry>.
2. In the fork, append **one line** — the repository URL — to
   `repositories.txt`, keeping the file's existing ordering:

   ```text
   https://github.com/acabtech/ESP32_SNMPv3
   ```

3. Commit on a branch, e.g. `add-ESP32-SNMPv3-Agent`, and open a pull request
   against `arduino/library-registry:main`.

   Suggested PR title: `Add ESP32-SNMPv3-Agent`
   Suggested PR body:

   > ESP32-SNMPv3-Agent is an SNMPv3 agent for ESP32 / ESP32-S2 / ESP32-S3
   > using the USM authPriv security model (HMAC-SHA-256 + AES-128 CFB) with
   > hardware-accelerated crypto, plus v3 traps/informs. SNMPv3 only (no
   > v1/v2c). GPL-3.0-only. `arduino-lint --library-manager submit` is clean,
   > examples compile for esp32, esp32s2 and esp32s3, and the repository has a
   > matching `v0.1.2` release tag.

   Alternatively use the web form at <https://librarymanager.arduino.cc/>;
   it opens an equivalent registry pull request.

4. The registry's CI bot runs `arduino-lint` against the submitted URL and
   comments on the PR. Address any findings, then a maintainer merges the PR.
5. The Library Manager index is regenerated nightly. After the merge, verify:

   ```bash
   arduino-cli lib update-index
   arduino-cli lib search ESP32-SNMPv3-Agent
   arduino-cli lib install ESP32-SNMPv3-Agent
   ```

## After acceptance

- Swap the lint invocation in [`CONTRIBUTING.md`](../CONTRIBUTING.md) and the
  CI job from `--library-manager submit` to `--library-manager update` (the
  rule set that applies to *new releases* of an already-indexed library).
- Run the release steps in [`CONTRIBUTING.md`](../CONTRIBUTING.md) for every
  subsequent tag; the registry picks up new tags automatically. A version
  change that does not satisfy the *update* rules will not be published.
- Update the README status table and the Library Manager badge.

## Common rejection causes (and how this repo avoids them)

| Cause | Avoided by |
|-------|------------|
| `url=` returns 404 or points at another repo | `url=` is the real repository root (was the v0.1.1 blocker, fixed in v0.1.2) |
| Latest tag missing/mismatched `version=` | `library.properties` and the tag are released together |
| Header name does not match `name=` | `src/ESP32-SNMPv3-Agent.h` forwarding header |
| Sketches outside `examples/` | `dist/`, `build/` and `.venv/` are gitignored; CI lints a clean checkout |
| License not in the SPDX list | `GPL-3.0-only` |
| Architecture not installed from a registered package index | `esp32` via the Espressif board index |
| `arduino-cli lib publish` used | That command does not exist; this document uses the registry PR |
