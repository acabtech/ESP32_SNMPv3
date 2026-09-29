// USM.c — USM layer implementation (RFC 3414 / 7860 / 3826).
//
// Implements, above the crypto backend (src/usm/crypto.h):
//   • passphrase handling and SHA-256 key localization (RFC 7860 §9.3),
//   • HMAC-SHA-256 (RFC 2104) with RFC 7860 24-octet MAC semantics,
//   • AES-128-CFB privacy framing (RFC 3826 §3.1.3/.4) — IV = boots||time||salt,
//   • msgFlags and securityParameters serialization (RFC 3412 §6),
//   • engine timeliness window (RFC 3414 §2.2.3).
//
// The CFB/HMAC/framing logic here is backend-independent and fully covered
// by tests/host (pysnmp/cryptography-generated vectors). The only
// hardware-dependent pieces are the three primitives in crypto_esp32.c.
//
// SPDX-License-Identifier: GPL-3.0
#include "USM.h"
#include "crypto.h"
#include "ber/BER.h"
#include <string.h>

// --- Passphrase limiting (RFC 3414 §A.1) -----------------------------------
// The RFC bounds passphrases at 2^31-1 octets; like net-snmp and pysnmp we
// validate and pass through (the ring-buffer loop consumes as-is, and never
// materializes the 1 MiB string). Empty/oversized -> error.
int usmLimitPassphrase(const uint8_t* phrase, size_t len,
                       uint8_t* out, size_t* outLen) {
  if (phrase == NULL || len == 0 || len > 1024) return USM_ERR_BAD_USERNAME;
  if (out != NULL && out != phrase) memcpy(out, phrase, len);
  if (outLen != NULL) *outLen = len;
  return USM_ERR_OK;
}

// digest1 = SHA-256( passphrase repeated to 1,048,576 octets )
// (RFC 3414 §A.2.2 / RFC 7860 §9.3), computed in 64-octet ring steps with
// constant memory — mirrors pysnmp's localkey.hashPassphrase exactly
// (16384 iterations x 64 octets).
static void usmHashPassphrase(const uint8_t* pass, size_t plen,
                              uint8_t out[32]) {
  // RFC 3414 §A.2.2 / RFC 7860 §9.3: hash the virtual ring of the passphrase
  // repeated to 1,048,576 octets, in 64-octet windows (16384 iterations),
  // constant memory. Mirrors pysnmp's localkey.hashPassphrase exactly — the
  // wrap is per-byte, so short passphrases are handled too.
  CryptoSha256Ctx c;
  crypto_sha256_init(&c);
  uint8_t win[64];
  size_t mark = 0;
  for (int cnt = 0; cnt < 16384; cnt++) {
    for (int i = 0; i < 64; i++) win[i] = pass[(mark + (size_t)i) % plen];
    crypto_sha256_update(&c, win, 64);
    mark += 64;
  }
  crypto_sha256_final(&c, out);
}

// Ku = SHA-256( digest1 || engineId || digest1 )  -> 32 octets
int usmKeyLocalize(const uint8_t* passphrase, size_t passLen,
                   const uint8_t* engineId, size_t engineIdLen,
                   uint8_t kuOut[SNMPV3_SHA256_KEY]) {
  if (passphrase == NULL || passLen == 0 || passLen > 1024)
    return USM_ERR_BAD_USERNAME;
  uint8_t d1[32];
  usmHashPassphrase(passphrase, passLen, d1);
  CryptoSha256Ctx c;
  crypto_sha256_init(&c);
  crypto_sha256_update(&c, d1, sizeof d1);
  crypto_sha256_update(&c, engineId, engineIdLen);
  crypto_sha256_update(&c, d1, sizeof d1);
  crypto_sha256_final(&c, kuOut);
  return USM_ERR_OK;
}

// --- HMAC-SHA-256 (RFC 2104) -----------------------------------------------
int usmHmacSha256(const uint8_t* key, size_t keyLen,
                  const uint8_t* msg, size_t msgLen,
                  uint8_t out[SNMPV3_SHA256_KEY]) {
  uint8_t k[64];
  if (keyLen > 64) {
    crypto_sha256(key, keyLen, k);
    memset(k + 32, 0, 32);
  } else {
    memcpy(k, key, keyLen);
    memset(k + keyLen, 0, 64 - keyLen);
  }

  uint8_t ipad[64], opad[64];
  for (int i = 0; i < 64; i++) { ipad[i] = (uint8_t)(k[i] ^ 0x36); opad[i] = (uint8_t)(k[i] ^ 0x5c); }

  uint8_t inner[32];
  CryptoSha256Ctx c;
  crypto_sha256_init(&c);
  crypto_sha256_update(&c, ipad, 64);
  crypto_sha256_update(&c, msg, msgLen);
  crypto_sha256_final(&c, inner);

  crypto_sha256_init(&c);
  crypto_sha256_update(&c, opad, 64);
  crypto_sha256_update(&c, inner, sizeof inner);
  crypto_sha256_final(&c, out);
  return USM_ERR_OK;
}

// --- AES-128 CFB (RFC 3826 §3.1.3 / §3.1.4) --------------------------------
// CFB with full 16-octet feedback: keystream_i = E(feedback_i);
// ciphertext_i = plaintext_i XOR keystream_i; feedback_{i+1} = ciphertext_i
// (the ciphertext side varies: `out` when encrypting, `in` when decrypting).
// A final partial block XORs the r leading keystream octets; no padding.
static int usmAesCfb(const uint8_t key[16], uint8_t iv[16],
                     const uint8_t* in, uint8_t* out, size_t len,
                     int ciphertextIsOut) {
  uint8_t feedback[16];
  memcpy(feedback, iv, 16);
  size_t off = 0;
  while (off < len) {
    uint8_t ks[16];
    crypto_aes128_enc(key, feedback, ks);
    size_t chunk = (len - off < 16) ? (len - off) : 16;
    for (size_t i = 0; i < chunk; i++) out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
    if (chunk == 16) {   // full block: next feedback = this ciphertext block
      const uint8_t* ct = ciphertextIsOut ? (out + off) : (in + off);
      memcpy(feedback, ct, 16);
    }
    off += chunk;
  }
  memcpy(iv, feedback, 16);  // running state for chained messages
  return USM_ERR_OK;
}

void usmAesMakeIv(uint8_t iv[SNMPV3_AES_IV], uint32_t boots, uint32_t time,
                  const uint8_t salt[SNMPV3_PRIV_SALT]) {
  iv[0] = (uint8_t)(boots >> 24); iv[1] = (uint8_t)(boots >> 16);
  iv[2] = (uint8_t)(boots >> 8);  iv[3] = (uint8_t)(boots);
  iv[4] = (uint8_t)(time >> 24);  iv[5] = (uint8_t)(time >> 16);
  iv[6] = (uint8_t)(time >> 8);   iv[7] = (uint8_t)(time);
  memcpy(iv + 8, salt, SNMPV3_PRIV_SALT);
}

int usmAesCfbEncrypt(const uint8_t key[SNMPV3_AES128_KEY], uint8_t iv[SNMPV3_AES_IV],
                     const uint8_t* in, uint8_t* out, size_t len) {
  return usmAesCfb(key, iv, in, out, len, 1 /* ciphertext = out */);
}

int usmAesCfbDecrypt(const uint8_t key[SNMPV3_AES128_KEY], uint8_t iv[SNMPV3_AES_IV],
                     const uint8_t* in, uint8_t* out, size_t len) {
  return usmAesCfb(key, iv, in, out, len, 0 /* ciphertext = in */);
}

// --- Message flags (RFC 3412 §6.10) ----------------------------------------
uint8_t usmMsgFlags(bool auth, bool priv) {
  return (uint8_t)((auth ? 0x01 : 0x00) | (priv ? 0x02 : 0x00));
}

// --- USM securityParameters SEQUENCE (RFC 3414 §6) -------------------------
int usmBuildSecurityParams(uint8_t* out, size_t cap,
                           const uint8_t* engineId, size_t engineIdLen,
                           uint32_t boots, uint32_t time,
                           const uint8_t* username, size_t usernameLen,
                           const uint8_t* authParams,
                           const uint8_t* privParams,
                           size_t* outLen) {
  uint8_t body[512];
  size_t n = 0;

  int r = berEncodeOctetString(body + n, sizeof body - n, engineId, engineIdLen);
  if (r < 0) return r;
  n += (size_t)r;
  r = berEncodeInt32(body + n, sizeof body - n, (int32_t)boots);
  if (r < 0) return r;
  n += (size_t)r;
  r = berEncodeInt32(body + n, sizeof body - n, (int32_t)time);
  if (r < 0) return r;
  n += (size_t)r;
  r = berEncodeOctetString(body + n, sizeof body - n, username, usernameLen);
  if (r < 0) return r;
  n += (size_t)r;
  r = berEncodeOctetString(body + n, sizeof body - n,
                           authParams, SNMPV3_SHA256_MAC);
  if (r < 0) return r;
  n += (size_t)r;
  r = berEncodeOctetString(body + n, sizeof body - n,
                           privParams, SNMPV3_PRIV_SALT);
  if (r < 0) return r;
  n += (size_t)r;

  r = berEncodeTlv(out, cap, BER_TAG_SEQUENCE, body, n);
  if (r < 0) return r;
  if (outLen != NULL) *outLen = (size_t)r;
  return USM_ERR_OK;
}

// --- Timeliness (RFC 3414 §2.2.3) ------------------------------------------
uint32_t usmTimeNow(const UsmEngineClock* clock, uint32_t nowMs) {
  uint32_t elapsed = (uint32_t)((uint32_t)(nowMs - (uint32_t)clock->monotonicMs) / 1000u);
  return clock->time + elapsed;
}

int usmTimelinessCheck(const UsmEngineClock* authoritative,
                       uint32_t boots, uint32_t time, uint32_t nowMs) {
  if (boots != authoritative->boots) return USM_ERR_NOT_IN_TIME;
  uint32_t now = usmTimeNow(authoritative, nowMs);
  int32_t delta = (int32_t)(time - now);
  if (delta < -150 || delta > 150) return USM_ERR_NOT_IN_TIME;
  return USM_ERR_OK;
}