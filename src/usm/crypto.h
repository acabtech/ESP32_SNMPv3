// crypto.h — cryptographic primitives used by the USM layer.
//
// Two interchangeable backends:
//   • src/usm/crypto_esp32.c   — shipped with the library; ESP32 mbedtls
//                                (hardware-accelerated SHA-256/AES on classic
//                                ESP32, S2, S3 through the IDF5 mbedtls glue).
//   • tests/host/soft/crypto_soft.c — self-contained reference (host tests).
//
// Everything above these primitives — HMAC, CFB framing, IV construction,
// key localization — lives in src/usm/USM.c so the *same* framing code is
// exercised on the host and shipped on the device.
//
// SPDX-License-Identifier: GPL-3.0
#ifndef SNMPV3_CRYPTO_H
#define SNMPV3_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// Opaque incremental SHA-256 state. Sized to fit both backends
// (soft: 112 B, mbedtls 3.x context: < 160 B). Bump if a backend outgrows it.
#define CRYPTO_SHA256_CTX_BYTES 192

typedef struct {
  uint8_t blob[CRYPTO_SHA256_CTX_BYTES];
} CryptoSha256Ctx;

// Incremental SHA-256 (FIPS 180-4 / RFC 6234).
void crypto_sha256_init(CryptoSha256Ctx* ctx);
void crypto_sha256_update(CryptoSha256Ctx* ctx, const uint8_t* in, size_t len);
void crypto_sha256_final(CryptoSha256Ctx* ctx, uint8_t out[32]);

// One-shot convenience.
void crypto_sha256(const uint8_t* in, size_t len, uint8_t out[32]);

// AES-128 single block (ECB), FIPS-197 algorithm.
void crypto_aes128_enc(const uint8_t key[16], const uint8_t in[16],
                       uint8_t out[16]);
void crypto_aes128_dec(const uint8_t key[16], const uint8_t in[16],
                       uint8_t out[16]);

#endif  // SNMPV3_CRYPTO_H