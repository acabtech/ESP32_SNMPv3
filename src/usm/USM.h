// USM.h — SNMPv3 User-based Security Model (RFC 3414) interface (M0 scaffold).
//
// v0.1 scope (locked): HMAC-SHA-256 authentication (RFC 7860) and AES-128
// CFB privacy (RFC 3826) ONLY. No MD5, no SHA-1, no DES, no AES-192/256,
// no noAuth/noPriv users (discovery reports are still generated per RFC 3414
// §4 "unavailable" flows — that is protocol machinery, not a security level).
//
// Crypto engine: the ESP32 family hardware AES/SHA-256 engines via the
// mbedtls layer shipped with arduino-esp32 v3.x. A software reference
// implementation of the SAME interface is used by the host test harness.
//
// Host-compilable: no Arduino types here.
//
// SPDX-License-Identifier: GPL-3.0
#ifndef SNMPV3_USM_H
#define SNMPV3_USM_H

#include <stdint.h>
#include <stddef.h>

#define SNMPV3_SHA256_DIGEST   32   // RFC 7860, HMAC-SHA-256 output
#define SNMPV3_AES128_KEY      16   // RFC 3826
#define SNMPV3_AES_IV          16   // 16-byte IV: 8-byte salt + 8-byte zero pad? no — see RFC 3826 §5
#define SNMPV3_PRIV_SALT       8    // 4-byte engineBoots || 4-byte engineTime
#define SNMPV3_AUTH_PARAMS_LEN SNMPV3_SHA256_DIGEST

typedef enum {
  USM_ERR_OK           = 0,
  USM_ERR_UNKNOWN_USER = -1,
  USM_ERR_BAD_USERNAME = -2,
  USM_ERR_AUTH_FAIL    = -3,
  USM_ERR_PRIV_FAIL    = -4,
  USM_ERR_NOT_IN_TIME  = -5,
  USM_ERR_BAD_ENGINE   = -6,   // unknownEngineID / wrongEngineID
  USM_ERR_DROPPED      = -7    // msgID replay / maxSize / internal
} UsmError;

// --- Key derivation (RFC 3414 §11, RFC 7860 §3) ----------------------------
// Passphrase length limit: RFC 3414 §A.2.1 (max 2^31-1 — practically capped
// at 64 here; the 1 MB iterate loop in passwordToKey uses 32 iterations of
// 32 KB chunks internally, NOT 1 MB of RAM).
int usmLimitPassphrase(const uint8_t* phrase, size_t len,
                       uint8_t* out, size_t* outLen);

// passwordToKey (RFC 3414 §A.2.2) + localized key (RFC 3414 §A.3) in one
// step, for the auth (SHA-256) and priv (AES) key slots.
//   kuOut : localized key (32 bytes auth / 16 bytes priv slot)
int usmKeyLocalize(const uint8_t* passphrase, size_t passLen,
                   const uint8_t* engineId, size_t engineIdLen,
                   uint8_t* kuOut, size_t kuLen);

// --- Auth (HMAC-SHA-256-192 per RFC 7860 — keyed SHA-256, truncated) ------
// Computes HMAC-SHA-256( key, msg ) and writes the first 24 bytes into
// authOut (RFC 7860 §3 specifies a 24-byte MAC). Zero-pads nothing.
int usmHmacSha256(const uint8_t* key, size_t keyLen,
                  const uint8_t* msg, size_t msgLen,
                  uint8_t authOut[SNMPV3_SHA256_DIGEST]);

// --- Privacy (AES-128 CFB per RFC 3826) ------------------------------------
// IV = 16 bytes: [ msgAuthoritativeEngineBoots (4) || msgAuthoritativeEngineTime (4)
//                  || 8 zero bytes ]; the 8-byte salt (boots||time) is carried
// in the message's privParams; the pre-IV (tail of the localized key) is NOT
// used as IV in v0.1 — verify against RFC 3826 §5 + net-snmp during M1.
// (Note: net-snmp/pysnmp treat the local pre-IV as key material only.)
int usmAesCfbEncrypt(const uint8_t* key /*16*/, uint8_t* iv /*16*/,
                     const uint8_t* in, uint8_t* out, size_t len);
int usmAesCfbDecrypt(const uint8_t* key /*16*/, uint8_t* iv /*16*/,
                     const uint8_t* in, uint8_t* out, size_t len);

// --- Message flags / USM securityParams (RFC 3414 §6) ----------------------
uint8_t usmMsgFlags(bool auth, bool priv);
void usmBuildSecurityParams(uint8_t* out, size_t cap,
                            const uint8_t* engineId, size_t engineIdLen,
                            uint32_t boots, uint32_t time,
                            const uint8_t* username, size_t usernameLen,
                            const uint8_t* authParams,  // 32 bytes
                            const uint8_t* privParams,  // 8 bytes (salt)
                            size_t* outLen);

// --- Engine timeliness ------------------------------------------------------
// Boots/time window check (RFC 3414 §2.2.3): remote boots must equal the
// cached authoritative value and remote time must be within ±150 s of the
// authoritative engineTime. Implemented (not stubbed) in M1.
typedef struct {
  uint32_t boots;
  uint32_t time;       // seconds since last boots
  uint64_t monotonic;  // local ms basis (millis()*1000 + uptime anchor)
} UsmEngineClock;
int usmTimelinessCheck(const UsmEngineClock* authoritative, uint32_t boots,
                       uint32_t time);
uint32_t usmTimeNow(const UsmEngineClock* clock);  // authoritative time now

#endif  // SNMPV3_USM_H