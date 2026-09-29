// BER.h — ASN.1 BER codec interface for SNMP messages (M0 scaffold).
//
// Host-compilable: no Arduino/types dependency so the codec runs in the
// host unit-test harness (tests/host) and inside the ESP32.
//
// Conventions:
//   • Return values >= 0 are byte counts; negative values are errors
//     (see BerError below).
//   • Decoder functions advance the caller's position cursor by reference
//     (like `pp`/`ph` in RFCs).
//   • All encoding is big-endian (network order), per BER.
//
// SPDX-License-Identifier: GPL-3.0
#ifndef SNMPV3_BER_H
#define SNMPV3_BER_H

#include <stdint.h>
#include <stddef.h>

// Universal tags used by SNMP (RFC 3416 / X.690).
typedef enum {
  BER_TAG_INTEGER       = 0x02,
  BER_TAG_OCTET_STRING  = 0x04,
  BER_TAG_NULL          = 0x05,
  BER_TAG_OID           = 0x06,
  BER_TAG_SEQUENCE      = 0x30,
  // varbind / PDU tags (context-specific, constructed):
  BER_TAG_VARBIND_SEQ   = 0x30,             // same wire encoding as SEQUENCE
  BER_TAG_GET_REQ       = 0xA0,
  BER_TAG_GET_NEXT_REQ  = 0xA1,
  BER_TAG_RESPONSE      = 0xA2,
  BER_TAG_SET_REQ       = 0xA3,
  BER_TAG_GET_BULK      = 0xA5,
  BER_TAG_INFORM_REQ    = 0xA6,
  BER_TAG_TRAP_V2       = 0xA7,
  BER_TAG_REPORT        = 0xA8,
  // Message-wrapping tags (RFC 3412 §6):
  BER_TAG_MSG_SEQ       = 0x30,
  BER_TAG_MSG_SECPARAMS = 0x30,
  BER_TAG_SCOPED_PDU    = 0x30
} BerTag;

// Negative error codes (positive = bytes written/consumed).
typedef enum {
  BER_OK            = 0,
  BER_ERR_TRUNCATED = -1,   // buffer too small / input exhausted
  BER_ERR_LENGTH    = -2,   // length > 127 (indefinite/long-form) unsupported
  BER_ERR_OVERFLOW  = -3,   // value does not fit target type
  BER_ERR_OID       = -4,   // OID malformed (leading arcs)
  BER_ERR_TYPE      = -5    // tag mismatch vs expected
} BerError;

// --- TLV primitives --------------------------------------------------------
int berEncodeLength(uint8_t* out, size_t cap, size_t len);
int berDecodeLength(const uint8_t* in, size_t max, size_t* pos, size_t* len);
int berEncodeTlv(uint8_t* out, size_t cap, uint8_t tag,
                 const uint8_t* val, size_t len);
int berDecodeTlv(const uint8_t* in, size_t max, size_t* pos,
                 uint8_t* tag, size_t* len);

// --- Universal types -------------------------------------------------------
int berEncodeInt32(uint8_t* out, size_t cap, int32_t v);
int berDecodeInt32(const uint8_t* in, size_t max, size_t* pos, int32_t* v);
int berEncodeOctetString(uint8_t* out, size_t cap,
                         const uint8_t* s, size_t len);
int berEncodeNull(uint8_t* out, size_t cap);

// OIDs: arrays of 32-bit arcs (first two arcs already combined per BER
// 8.19: 1.3 => 43). Sub-identifiers > 2^31 not supported (fine for SNMP
// OIDs as assigned by IANA).
int berEncodeOid(uint8_t* out, size_t cap, const uint32_t* arcs, size_t nArcs);
int berDecodeOid(const uint8_t* in, size_t max, size_t* pos,
                 uint32_t* arcs, size_t* nArcs);

// --- SNMP message assembly -------------------------------------------------
// Request/response header fields (RFC 3416 §3.2):
typedef struct {
  uint32_t msgID;
  uint8_t  msgFlags;      // bit0 auth, bit1 priv, bit2 reportable
  uint8_t  secModel;      // 3 = USM
  // security-parameters (USM): engineID, engineBoots, engineTime,
  // username, authParams(12), privParams(8) — serialized by USM layer.
  const uint8_t* engineId;    size_t engineIdLen;
  uint32_t       engineBoots; uint32_t engineTime;
  const uint8_t* username;    size_t usernameLen;
  const uint8_t* authParams;  // HMAC-SHA-256 output = 32 bytes
  const uint8_t* privParams;  // AES salt = 8 bytes
} BerMsgHeader;

// ScopedPDU body (RFC 3412 §6.2: contextEngineID, contextName, PDU).
// TODO(M1): berEncodeScopedPdu / berEncodePdu / berEncodeVarbind helpers
// and decoders, implemented against RFC 3416 §6 + §8 and validated with the
// test vectors in tests/host.

#endif  // SNMPV3_BER_H