# tests/host — host-side unit tests (no hardware, no Arduino SDK)

The `ber/`, `usm/`, `mib/` modules must stay Arduino-free so this suite runs
on a plain PC (and in CI) with a **software reference crypto backend**
(implemented in M1 alongside the mbedtls/HW backend).

Planned suites (all land with M1/M2):

| Suite | Covers |
|-------|--------|
| `ber_roundtrip` | TLV/length/int/OID encode→decode identity, fuzz with random lengths, truncated-input handling |
| `usm_passphrase` | RFC 3414 §A.2 passphrase limiting vectors |
| `usm_password_to_key` | RFC 3414 §A.2.2 known-answer test (Appendix A.3) |
| `usm_localize` | Localization: known Ku given engineID (A.3 two-step) |
| `usm_hmac_sha256` | RFC 7860 §3 HMAC-SHA-256 known-answer vectors |
| `usm_aes_cfb` | RFC 3826 §5 AES-128-CFB encryption/decryption vectors |
| `mib_walk` | Get/GetNext/GetBulk traversal incl. tables & endOfMibView |
| `timeliness` | boots/time window accept/reject, replay msgID ring |

## Running

    # full suite
    tests/host/run_host_tests.sh

    # or directly
    gcc -Isrc tests/host/ber_roundtrip.c src/ber/ber.c -o /tmp/t && /tmp/t

Runner script + source layout will be added in M1 (the warm-up suite is
`ber_roundtrip`). Frameworks are intentionally avoided — plain C asserts
keep the toolchain trivial for contributors.