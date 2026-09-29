// USM.h — SNMPv3 User-based Security Model (RFC 3414) interface.
//
// v0.1 scope (locked): HMAC-SHA-256 authentication (RFC 7860) and AES-128
// CFB privacy (RFC 3826) ONLY. No MD5, no SHA-1, no DES, no AES-192/256,
// no noAuth/noPriv users (discovery reports are still generated per RFC 3414
// §4 "unavailable" flows — that is protocol machinery, not a security level).
//
// Wire-relevant constants verified against pysnmp 6.2.6 reference sources
// (rfc7860/auth/hmacsha2.py, rfc3826/priv/aes.py) and the RFCs:
//
//   usmHMAC192SHA256AuthProtocol  key M = 32 octets (SHA-256-derived),
//                                 MAC   = 24 octets (RFC 7860 §4.2)
//   usmAesCfb128Protocol          key = first 16 octets of the localized
//                                 priv key (RFC 3826 §3.1.2.1),
//                                 IV  = boots(4) || time(4) || salt(8)
//
// Host-compilable: no Arduino types here (unit-tested in tests/host).
//
// SPDX-License-Identifier: GPL-3.0
#ifndef SNMPV3_USM_H
#define SNMPV3_USM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define SNMPV3_SHA256_KEY      32   // localized auth key length (hash size)
#define SNMPV3_SHA256_MAC      24   // RFC 7860 §4.2: truncated HMAC output
#define SNMPV3_AES128_KEY      16   // RFC 3826: first half of local. priv key
#define SNMPV3_AES_IV          16   // boots(4) || time(4) || salt(8)
#define SNMPV3_PRIV_SALT       8    // RFC 3826 §3.1.2.1

// Auth/priv protocol service IDs (SNMP-FRAMEWORK-MIB snmpAuthProtocols /
// snmpPrivProtocols; needed by the MIB later, kept here as documentation):
//   usmHMAC192SHA256AuthProtocol = 1.3.6.1.6.3.10.1.1.5
//   usmAesCfb128Protocol         = 1.3.6.1.6.3.10.1.2.4

typedef enum {
  USM_ERR_OK           = 0,
  USM_ERR_UNKNOWN_USER = -1,
  USM_ERR_BAD_USERNAME = -2,
  USM_ERR_AUTH_FAIL    = -3,
  USM_ERR_PRIV_FAIL    = -4,
  USM_ERR_NOT_IN_TIME  = -5,
  USM_ERR_BAD_ENGINE   = -6,   // unknownEngineID / wrongEngineID
  USM_ERR_DROPPED      = -7,   // msgID replay / maxSize / internal
  USM_ERR_CRYPTO       = -8,   // backend failure (never on mbedtls/HW)
} UsmError;

// --- Passphrase & key derivation (RFC 3414 §A, RFC 7860 §9.3) --------------
// RFC 3414 §A.1 bounds passphrases at 2^31-1 octets; like net-snmp and
// pysnmp we accept the passphrase as-is (ring-buffer loop below consumes it
// without materializing the 1 MiB string). Empty/oversized -> error.
// Copies the (validated) passphrase to out and sets *outLen.
int usmLimitPassphrase(const uint8_t* phrase, size_t len,
                       uint8_t* out, size_t* outLen);

// Localized key (RFC 7860 §9.3 == RFC 3414 §A.2.2 + §A.3 with H=SHA-256):
//   digest1 = SHA-256( passphrase repeated to 1,048,576 octets )
//   Ku      = SHA-256( digest1 || engineId || digest1 )      -> 32 bytes
// The AES private key is the first 16 bytes of the same construction applied
// to the privacy passphrase (RFC 3826 §3.1.2). Returns USM_ERR_OK / error.
int usmKeyLocalize(const uint8_t* passphrase, size_t passLen,
                   const uint8_t* engineId, size_t engineIdLen,
                   uint8_t kuOut[SNMPV3_SHA256_KEY]);

// --- Auth: HMAC-SHA-256 (RFC 2104 + RFC 7860) ------------------------------
// Full 32-byte HMAC-SHA-256. The USM auth protocol uses the localized key
// (32 B) and places the FIRST 24 bytes of the digest into
// msgAuthenticationParameters (RFC 7860 §4.2.1 step 3/4); during
// computation the parameters field must contain 24 zero octets.
int usmHmacSha256(const uint8_t* key, size_t keyLen,
                  const uint8_t* msg, size_t msgLen,
                  uint8_t out[SNMPV3_SHA256_KEY]);

// --- Privacy: AES-128 CFB (RFC 3826 §3.1.3/§3.1.4) -------------------------
// CFB with full 16-octet feedback segments; the final partial block is
// XORed with the r most significant octets of the output block (no padding).
// `iv` is the running feedback value: pass IV = boots||time||salt for the
// first call; both functions consume/update it block-by-block (decrypt and
// encrypt are the same byte operation — XOR with E(feedback)).
void usmAesMakeIv(uint8_t iv[SNMPV3_AES_IV], uint32_t boots, uint32_t time,
                  const uint8_t salt[SNMPV3_PRIV_SALT]);
int usmAesCfbEncrypt(const uint8_t key[SNMPV3_AES128_KEY],
                     uint8_t iv[SNMPV3_AES_IV],
                     const uint8_t* in, uint8_t* out, size_t len);
int usmAesCfbDecrypt(const uint8_t key[SNMPV3_AES128_KEY],
                     uint8_t iv[SNMPV3_AES_IV],
                     const uint8_t* in, uint8_t* out, size_t len);

// --- Message flags / securityParameters (RFC 3412 §6, RFC 3414 §6) ---------
// bit0 = auth, bit1 = priv, bit2 = reportable.
uint8_t usmMsgFlags(bool auth, bool priv);

// Serialize the USM securityParameters SEQUENCE content per RFC 3412 §6
// (msgAuthoritativeEngineID, boots, time, userName, authParams, privParams).
// `authParams` = 24 zero octets while computing the MAC (RFC 7860 §4.2.1);
// `privParams` = the 8-octet salt (RFC 3826 §3.1.2.1). Writes the SEQUENCE
// bytes; the message encoder wraps them in the OCTET STRING field.
int usmBuildSecurityParams(uint8_t* out, size_t cap,
                           const uint8_t* engineId, size_t engineIdLen,
                           uint32_t boots, uint32_t time,
                           const uint8_t* username, size_t usernameLen,
                           const uint8_t* authParams,   // SHA256_MAC bytes
                           const uint8_t* privParams,   // PRIV_SALT bytes
                           size_t* outLen);

// --- Engine timeliness (RFC 3414 §2.2.3) ------------------------------------
// The agent keeps an authoritative engine clock (boots, time-in-seconds,
// and a ms anchor for computing "time now" without wall-clock RTC).
typedef struct {
  uint32_t boots;
  uint32_t time;        // seconds since last boots
  uint64_t monotonicMs; // ms anchor (e.g., millis()) captured when `time` set
} UsmEngineClock;

uint32_t usmTimeNow(const UsmEngineClock* clock, uint32_t nowMs);

// Accept iff boots matches and |remoteTime - authoritativeTime| <= 150 s.
// `nowMs` is the caller's monotonic ms source (e.g., millis()).
int usmTimelinessCheck(const UsmEngineClock* authoritative,
                       uint32_t boots, uint32_t time, uint32_t nowMs);

#endif  // SNMPV3_USM_H