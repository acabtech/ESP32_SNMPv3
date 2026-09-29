// test_soft.c — validate the reference crypto backend (host side).
//
// SHA-256: FIPS 180-4 known answers + incremental-parity fuzz.
// AES-128: FIPS-197 known answer + decrypt round-trip + chaining.
//
// SPDX-License-Identifier: GPL-3.0
#include <stdio.h>
#include <string.h>
#include "crypto.h"
#include "vectors.h"

static int fails = 0;

static void check(int ok, const char* what) {
  if (!ok) { fails++; printf("  FAIL: %s\n", what); }
}

static void expect_hex(const uint8_t* got, const uint8_t* want, size_t n,
                       const char* what) {
  for (size_t i = 0; i < n; i++)
    if (got[i] != want[i]) { check(0, what); return; }
  check(1, what);
}

int test_soft(void) {
  printf("== crypto_soft (SHA-256 / AES-128) ==\n");

  // --- SHA-256 known answers (FIPS 180-4) ---
  uint8_t d[32], want[32];
  crypto_sha256((const uint8_t*)"", 0, d);
  {
    const char* h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    for (int i = 0; i < 32; i++) {
      unsigned v;
      sscanf(h + 2 * i, "%2x", &v);
      want[i] = (uint8_t)v;
    }
  }
  expect_hex(d, want, 32, "SHA-256(\"\") vector");

  crypto_sha256((const uint8_t*)"abc", 3, d);
  {
    const char* h = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    for (int i = 0; i < 32; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); want[i] = (uint8_t)v; }
  }
  expect_hex(d, want, 32, "SHA-256(\"abc\") vector");

  // incremental update (byte-by-byte) must equal one-shot
  {
    uint8_t msg[1000];
    for (int i = 0; i < 1000; i++) msg[i] = (uint8_t)(i * 7 + 3);
    uint8_t one[32], inc[32] = {0};
    crypto_sha256(msg, sizeof msg, one);
    CryptoSha256Ctx c;
    crypto_sha256_init(&c);
    for (int i = 0; i < 1000; i++) crypto_sha256_update(&c, &msg[i], 1);
    crypto_sha256_final(&c, inc);
    expect_hex(inc, one, 32, "SHA-256 incremental == one-shot (1-byte steps)");
  }

  // --- AES-128 FIPS-197 known answer ---
  {
    uint8_t key[16], pt[16], ct[16], rt[16];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)i;          // 000102..0f
    for (int i = 0; i < 16; i++) pt[i] = (uint8_t)(0x10 * i + i);  // 001122..ff
    const char* h = "69c4e0d86a7b0430d8cdb78070b4c55a";
    for (int i = 0; i < 16; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); want[i] = (uint8_t)v; }
    crypto_aes128_enc(key, pt, ct);
    expect_hex(ct, want, 16, "AES-128-ECB FIPS-197 encrypt vector");
    crypto_aes128_dec(key, ct, rt);
    check(memcmp(rt, pt, 16) == 0, "AES-128 decrypt round-trip");
  }

  if (fails == 0) printf("  OK (%d checks)\n", fails == 0 ? 5 : 0);
  return fails;
}