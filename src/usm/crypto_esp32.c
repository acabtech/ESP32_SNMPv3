// crypto_esp32.c — ESP32 backend: mbedtls over the IDF5 crypto layer.
//
// The arduino-esp32 v3.x core (ESP-IDF 5.x) links mbedtls with the
// CONFIG_MBEDTLS_* hardware driver settings for classic ESP32 / S2 / S3, so
// these calls reach the on-chip AES / SHA-256 engines. Everything else in
// the library (HMAC, CFB framing, key localization) is backend-independent
// (src/usm/USM.c) and host-tested.
//
// NOTE: this file IS the device-only seam; it is never built by the host
// test suite (tests/host/Makefile links tests/host/soft/crypto_soft.c
// instead). Cross-check of this backend against the software reference
// happens on real hardware in M2 (see docs/ROADMAP.md).
//
// SPDX-License-Identifier: GPL-3.0
#include "crypto.h"

#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"

// --- SHA-256 ---------------------------------------------------------------
// mbedtls 3.x context fits within the opaque blob; compile-time guard.
typedef char sha256_ctx_fits[sizeof(mbedtls_sha256_context)
                             <= CRYPTO_SHA256_CTX_BYTES ? 1 : -1];

void crypto_sha256_init(CryptoSha256Ctx* ctx) {
  mbedtls_sha256_context* m =
      (mbedtls_sha256_context*)&ctx->blob[0];
  mbedtls_sha256_init(m);
  // mbedtls_sha256_init() only zeroes the context; mbedtls_sha256_starts()
  // is what loads the SHA-256 IV into state[]. Without it every incremental
  // hash (key localization + HMAC) runs from a zeroed state and produces a
  // wrong digest — the agent then rejects all authenticated requests with
  // usmStatsWrongDigests. is224 = 0 selects SHA-256.
  mbedtls_sha256_starts(m, 0);
}

void crypto_sha256_update(CryptoSha256Ctx* ctx, const uint8_t* in, size_t len) {
  mbedtls_sha256_context* m =
      (mbedtls_sha256_context*)&ctx->blob[0];
  mbedtls_sha256_update(m, in, len);
}

void crypto_sha256_final(CryptoSha256Ctx* ctx, uint8_t out[32]) {
  mbedtls_sha256_context* m =
      (mbedtls_sha256_context*)&ctx->blob[0];
  mbedtls_sha256_finish(m, out);
  mbedtls_sha256_free(m);
}

void crypto_sha256(const uint8_t* in, size_t len, uint8_t out[32]) {
  // One-shot convenience (mbedtls 3.x deprecated-style but present).
  mbedtls_sha256(in, len, out, 0);
}

// --- AES-128 block ---------------------------------------------------------
// Single-block ECB wrapper over the mbedtls AES context (deprecated but
// stable in 3.x; the CFB framing stays in USM.c so both backends share it).
static void aes128_block(const uint8_t key[16], const uint8_t in[16],
                         uint8_t out[16], int mode) {
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  if (mode == MBEDTLS_AES_ENCRYPT) mbedtls_aes_setkey_enc(&ctx, key, 128);
  else                             mbedtls_aes_setkey_dec(&ctx, key, 128);
  mbedtls_aes_crypt_ecb(&ctx, mode, in, out);
  mbedtls_aes_free(&ctx);
}

void crypto_aes128_enc(const uint8_t key[16], const uint8_t in[16],
                       uint8_t out[16]) {
  aes128_block(key, in, out, MBEDTLS_AES_ENCRYPT);
}

void crypto_aes128_dec(const uint8_t key[16], const uint8_t in[16],
                       uint8_t out[16]) {
  aes128_block(key, in, out, MBEDTLS_AES_DECRYPT);
}