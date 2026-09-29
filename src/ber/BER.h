// BER.h — ASN.1 BER codec for SNMP messages (RFC 3416 §6/§8, X.690).
//
// Host-compilable: no Arduino/ESP-IDF includes, so the codec is exercised in
// the host unit-test harness (tests/host) and inside the ESP32.
//
// Conventions:
//   • Return values >= 0 are byte counts; negatives are errors (BerError).
//   • Decoders advance a position cursor by reference.
//   • Big-endian (network order) per BER.
//
// SPDX-License-Identifier: GPL-3.0
#ifndef SNMPV3_BER_H
#define SNMPV3_BER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Universal + SNMP context/application tags (RFC 2578 §8, RFC 3416 §6, X.690).
typedef enum {
  BER_TAG_INTEGER       = 0x02,
  BER_TAG_OCTET_STRING  = 0x04,
  BER_TAG_NULL          = 0x05,
  BER_TAG_OID           = 0x06,
  BER_TAG_SEQUENCE      = 0x30,
  BER_TAG_GET_REQ       = 0xA0,
  BER_TAG_GET_NEXT_REQ  = 0xA1,
  BER_TAG_RESPONSE      = 0xA2,
  BER_TAG_SET_REQ       = 0xA3,
  BER_TAG_GET_BULK      = 0xA5,
  BER_TAG_INFORM_REQ    = 0xA6,
  BER_TAG_TRAP_V2       = 0xA7,
  BER_TAG_REPORT        = 0xA8,
  // SNMPv2-SMI application class (implicit CONTEXT 0 primitive exceptions are
  // how v2/v3 express per-varbind errors; tags per RFC 2578 §8).
  BER_TAG_COUNTER32     = 0x41,
  BER_TAG_UNSIGNED32    = 0x42,
  BER_TAG_TIMETICKS     = 0x43,
  BER_TAG_NOSUCHOBJECT  = 0x81,   // noSuchObject    (context 0, primitive)
  BER_TAG_NOSUCHINSTANCE= 0x82,   // noSuchInstance  (context 1, primitive)
  BER_TAG_ENDOFMIBVIEW  = 0x83    // endOfMibView    (context 2, primitive)
} BerTag;

// PDU error-status values (RFC 3416 §2).
typedef enum {
  SNMP_ERR_NO_ERROR      = 0,
  SNMP_ERR_TOO_BIG       = 1,
  SNMP_ERR_GEN_ERR       = 5,
  SNMP_ERR_NO_ACCESS     = 6,
  SNMP_ERR_WRONG_TYPE    = 7,
  SNMP_ERR_WRONG_VALUE   = 10,
  SNMP_ERR_NOT_WRITABLE  = 17
} SnmpErrStatus;

// Negative error codes (positive = bytes written/consumed).
typedef enum {
  BER_OK            = 0,
  BER_ERR_TRUNCATED = -1,
  BER_ERR_LENGTH    = -2,   // indefinite/non-minimal/oversized length
  BER_ERR_OVERFLOW  = -3,
  BER_ERR_OID       = -4,
  BER_ERR_TYPE      = -5
} BerError;

// Max arcs in a varbind name (more than enough for IANA OIDs).
#define BER_OID_MAX_ARCS 64

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
// Unsigned INTEGER semantics (Counter32/Unsigned32/TimeTicks payloads use
// this body under their application tags).
int berEncodeUint32(uint8_t* out, size_t cap, uint32_t v);
int berDecodeUint32(const uint8_t* in, size_t max, size_t* pos, uint32_t* v);
// Same minimal unsigned body under an arbitrary tag (0x41 Counter32,
// 0x42 Unsigned32, 0x43 TimeTicks, 0x02 INTEGER).
int berEncodeUintTagged(uint8_t* out, size_t cap, uint8_t tag, uint32_t v);
int berEncodeOctetString(uint8_t* out, size_t cap,
                         const uint8_t* s, size_t len);
int berEncodeNull(uint8_t* out, size_t cap);

// OIDs as arrays of 32-bit arcs. First two arcs are combined per BER 8.19.
int berEncodeOid(uint8_t* out, size_t cap, const uint32_t* arcs, size_t nArcs);
int berDecodeOid(const uint8_t* in, size_t max, size_t* pos,
                 uint32_t* arcs, size_t* nArcs);

// --- Varbinds (RFC 3416 §8.4) ----------------------------------------------
// Encode: value = generic BER TLV bytes (caller builds INTEGER/OCTET/etc.).
int berEncodeVarbind(uint8_t* out, size_t cap,
                     const uint32_t* name, size_t nameLen,
                     const uint8_t* valueTlv, size_t valueLen);
// Decode: value is left unparsed (offset/len + tag), so the caller decides
// how to interpret it (agent core, M2).
int berDecodeVarbind(const uint8_t* in, size_t max, size_t* pos,
                     uint32_t* name, size_t* nameLen,
                     uint8_t* valueTag, size_t* valueOff, size_t* valueLen);

// --- Varbind lists & PDUs (RFC 3416 §8.6) ----------------------------------
typedef struct {
  uint32_t  name[BER_OID_MAX_ARCS];
  size_t    nameLen;
  const uint8_t* valueTlv;   // encode: pre-built BER TLV of the value
  size_t    valueLen;
  uint8_t   decValueTag;     // decode: value tag
  size_t    decValueOff;     // decode: value octets offset into input buffer
  size_t    decValueLen;
} BerVarbind;

// Uniform 3-integer header: for GETBULK the RFC overrides the fields
// (non-repeaters/max-repetitions) but layout is identical, so one code path.
int berEncodePdu(uint8_t* out, size_t cap, uint8_t pduTag,
                 uint32_t reqId, uint32_t status, uint32_t idx,
                 const BerVarbind* vbs, size_t nvbs);
int berDecodePdu(const uint8_t* in, size_t max, size_t* pos,
                 uint8_t* pduTag, uint32_t* reqId,
                 uint32_t* status, uint32_t* idx,
                 BerVarbind* vbs, size_t maxVbs, size_t* nvbs);

// --- ScopedPDU (RFC 3412 §6.2) ---------------------------------------------
// contextEngineID / contextName are octet strings; pdu is already-encoded
// PDU TLV bytes (this is what gets encrypted for authPriv).
int berEncodeScopedPdu(uint8_t* out, size_t cap,
                       const uint8_t* ctxEngineId, size_t ctxEngineIdLen,
                       const uint8_t* ctxName, size_t ctxNameLen,
                       const uint8_t* pdu, size_t pduLen);
int berDecodeScopedPdu(const uint8_t* in, size_t max, size_t* pos,
                       size_t* ctxEngineIdOff, size_t* ctxEngineIdLen,
                       size_t* ctxNameOff, size_t* ctxNameLen,
                       size_t* pduOff, size_t* pduLen);

// --- v3 message envelope (RFC 3412 §6) -----------------------------------
// `scopedPdu` bytes are the msgData region: with the privFlag (bit1) set they
// are the encrypted scopedPDU and get wrapped in an OCTET STRING; without it
// they are the plaintext scopedPDU TLV and are appended as-is.
// berDecodeV3Message returns the msgData region ready for the caller:
//   priv    -> ciphertext content bytes (decrypt, then berDecodeScopedPdu)
//   no priv -> the full plaintext scopedPDU TLV (berDecodeScopedPdu directly)
// secParams is the raw USM SEQUENCE bytes (wrapped in an OCTET STRING here).
int berEncodeV3Message(uint8_t* out, size_t cap,
                       uint32_t msgId, uint32_t maxSize,
                       uint8_t msgFlags, uint8_t secModel,
                       const uint8_t* secParams, size_t secParamsLen,
                       const uint8_t* scopedPdu, size_t scopedPduLen);
int berDecodeV3Message(const uint8_t* in, size_t max,
                       uint8_t* version, uint32_t* msgId, uint32_t* maxSize,
                       uint8_t* msgFlags, uint8_t* secModel,
                       size_t* secParamsOff, size_t* secParamsLen,
                       size_t* scopedPduOff, size_t* scopedPduLen);

#ifdef __cplusplus
}
#endif
#endif  // SNMPV3_BER_H