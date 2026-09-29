# tests/host — host-side unit tests (no hardware, no Arduino SDK)

Green since **M1** (2026-09-29): `./run_host_tests.sh` → all checks pass.

| Suite | Covers |
|-------|--------|
| `crypto_soft` | Reference SHA-256 + AES-128 (FIPS-197/180-4 vectors) |
| `test_ber.c` | 2561 checks: lengths, INTEGER/OID known answers, round-trip fuzz, varbind/PDU/scopedPDU assembly, v3-message decode + byte-exact re-encode of a discovery Report, authPriv message header decode |
| `test_usm.c` | 58 checks: SHA-256 key localization (pysnmp oracle), HMAC-SHA-256 24-octet MAC, AES-128-CFB with RFC 3826 IV construction (incl. partial tail + chaining), securityParameters byte-compare vs wire sample, timeliness ±150 s window, and a **full authPriv message**: MAC verify + CFB decrypt + request dispatch parse |

## Layout

    soft/            self-contained SHA-256/AES-128 reference backend
    soft/*.inc       generated constants (SHA-256 K, AES S-boxes)
    vec/vectors.h    generated test vectors + wire samples
    vgen/gen_vectors.py   vector generator (the "oracle")
    test_soft.c test_ber.c test_usm.c main.c
    Makefile run_host_tests.sh

## Regenerating vectors

    /tmp/pv/bin/python tests/host/vgen/gen_vectors.py     # or: make vectors

Requires a venv with `pysnmp==6.2.6` and `cryptography` (see
tests/interop/README.md). Generated files are checked in so the test suite
runs on a bare machine with just a C compiler.

## How the oracles work

- Key localization: pysnmp's own `localkey` (independent of our C).
- HMAC / AES-CFB: Python `hmac`+`hashlib` and `cryptography.modes.CFB`
  (RFC 3826 IV = boots||time||salt construction implemented in the generator).
- Wire samples: a small independent BER encoder in the generator, which is
  itself validated by re-encoding checks before its bytes ship to the C tests.
- If a fix changes wire behavior, regenerate + rerun; both sides must agree.