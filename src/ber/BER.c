// BER.c — ASN.1 BER codec for SNMP (RFC 3416 §6/§8, X.690).
//
// Primitives + varbind/PDU/scopedPDU/v3-message assembly. Decoders are
// bounds-checked everywhere and only advance the cursor on success.
// OID arcs are carried as uint32 (sufficient for assigned IANA OIDs).
//
// SPDX-License-Identifier: GPL-3.0
#include "BER.h"
#include <string.h>

// --- Length ----------------------------------------------------------------
int berEncodeLength(uint8_t* out, size_t cap, size_t len) {
  if (len < 128) {
    if (cap < 1) return BER_ERR_TRUNCATED;
    out[0] = (uint8_t)len;
    return 1;
  }
  // Long form: 0x80|N then N octets of the length as a minimal base-256
  // big-endian integer (BER X.690 §8.1.3.5 — NOT base-128 like OIDs).
  uint8_t b[4];
  int n = 0;
  size_t v = len;
  while (v != 0) { b[n++] = (uint8_t)(v & 0xFF); v >>= 8; }
  if (n > 4) return BER_ERR_OVERFLOW;              // lengths > 2^31-1 unsupported
  if (cap < (size_t)(n + 1)) return BER_ERR_TRUNCATED;
  out[0] = (uint8_t)(0x80 | n);
  for (int i = 0; i < n; i++) out[1 + i] = b[n - 1 - i];
  return n + 1;
}

int berDecodeLength(const uint8_t* in, size_t max, size_t* pos, size_t* len) {
  if (*pos >= max) return BER_ERR_TRUNCATED;
  uint8_t b = in[(*pos)++];
  if (!(b & 0x80)) { *len = b; return BER_OK; }
  int n = b & 0x7F;
  if (n == 0 || n > 4) return BER_ERR_LENGTH;      // indefinite form / too long
  if (*pos + (size_t)n > max) return BER_ERR_TRUNCATED;
  if (in[*pos] == 0x00) return BER_ERR_LENGTH;     // non-minimal (leading zero)
  size_t v = 0;
  for (int i = 0; i < n; i++) {
    if (v > (((size_t)1) << (sizeof(size_t) * 8 - 8))) return BER_ERR_OVERFLOW;
    v = (v << 8) | in[(*pos)++];
  }
  if (n == 4 && v > 0x7FFFFFFFu) return BER_ERR_OVERFLOW;
  *len = v;
  return BER_OK;
}

// --- TLV header ------------------------------------------------------------
int berEncodeTlv(uint8_t* out, size_t cap, uint8_t tag,
                 const uint8_t* val, size_t len) {
  if (cap < 1) return BER_ERR_TRUNCATED;
  out[0] = tag;
  int l = berEncodeLength(out + 1, cap - 1, len);
  if (l < 0) return l;
  if (cap - 1 - (size_t)l < len) return BER_ERR_TRUNCATED;
  if (len != 0) memcpy(out + 1 + l, val, len);
  return 1 + l + (int)len;
}

int berDecodeTlv(const uint8_t* in, size_t max, size_t* pos,
                 uint8_t* tag, size_t* len) {
  if (*pos >= max) return BER_ERR_TRUNCATED;
  *tag = in[(*pos)++];
  int r = berDecodeLength(in, max, pos, len);
  if (r < 0) return r;
  if (*pos + *len > max) return BER_ERR_TRUNCATED;
  return BER_OK;
}

// --- INTEGER (minimal two's complement) ------------------------------------
int berEncodeInt32(uint8_t* out, size_t cap, int32_t v) {
  uint8_t tmp[5];
  int n = 0;
  int32_t x = v;
  do { tmp[n++] = (uint8_t)(x & 0xFF); x >>= 8; }  // arithmetic shift
  while (x != 0 && x != -1);
  if ((tmp[n - 1] & 0x80) && x == 0)      tmp[n++] = 0x00;  // pad sign
  else if (!(tmp[n - 1] & 0x80) && x == -1) tmp[n++] = 0xFF;
  uint8_t body[5];
  for (int i = 0; i < n; i++) body[i] = tmp[n - 1 - i];
  return berEncodeTlv(out, cap, BER_TAG_INTEGER, body, (size_t)n);
}

int berDecodeInt32(const uint8_t* in, size_t max, size_t* pos, int32_t* v) {
  uint8_t tag;
  size_t len;
  int r = berDecodeTlv(in, max, pos, &tag, &len);
  if (r < 0) return r;
  if (tag != BER_TAG_INTEGER) return BER_ERR_TYPE;
  if (len == 0 || len > 4) return BER_ERR_OVERFLOW;
  size_t start = *pos;
  if (len > 1) {
    uint8_t b0 = in[start], b1 = in[start + 1];
    if ((b0 == 0x00 && !(b1 & 0x80)) || (b0 == 0xFF && (b1 & 0x80)))
      return BER_ERR_LENGTH;                       // non-minimal
  }
  int32_t val = (in[start] & 0x80) ? -1 : 0;
  for (size_t i = 0; i < len; i++) val = (int32_t)((val << 8) | in[start + i]);
  *pos = start + len;
  *v = val;
  return BER_OK;
}

// --- OCTET STRING / NULL ---------------------------------------------------
int berEncodeUint32(uint8_t* out, size_t cap, uint32_t v) {
  return berEncodeUintTagged(out, cap, BER_TAG_INTEGER, v);
}

int berEncodeUintTagged(uint8_t* out, size_t cap, uint8_t tag, uint32_t v) {
  // Counter32/Unsigned32/TimeTicks are implicit-width 4-octet SMI types
  // (RFC 2578 §7.10): emit the full 4 bytes so parsers never misread a
  // high-bit value as negative. (INTEGER, by contrast, uses minimal
  // two's-complement encoding via berEncodeInt32.)
  uint8_t body[4];
  for (int i = 0; i < 4; i++) body[i] = (uint8_t)(v >> (24 - 8 * i));
  return berEncodeTlv(out, cap, tag, body, 4);
}

int berDecodeUint32(const uint8_t* in, size_t max, size_t* pos, uint32_t* v) {
  uint8_t tag; size_t len;
  int r = berDecodeTlv(in, max, pos, &tag, &len);
  if (r < 0) return r;
  if (tag != BER_TAG_INTEGER) return BER_ERR_TYPE;
  if (len == 0 || len > 5) return BER_ERR_LENGTH;
  uint32_t out = 0;
  for (size_t i = 0; i < len; i++) {
    if (i == 4) return BER_ERR_LENGTH;
    out = (out << 8) | in[*pos + i];
  }
  *pos += len;
  *v = out;
  return BER_OK;
}

int berEncodeOctetString(uint8_t* out, size_t cap,
                         const uint8_t* s, size_t len) {
  return berEncodeTlv(out, cap, BER_TAG_OCTET_STRING, s, len);
}

int berEncodeNull(uint8_t* out, size_t cap) {
  return berEncodeTlv(out, cap, BER_TAG_NULL, NULL, 0);
}

// --- OID -------------------------------------------------------------------
static int subidEncode(uint8_t* out, size_t cap, uint32_t v, size_t* nOut) {
  uint8_t tmp[5];
  int n = 0;
  do { tmp[n++] = (uint8_t)(v & 0x7F); v >>= 7; } while (v != 0);
  if ((size_t)n > cap) return BER_ERR_TRUNCATED;
  for (int i = 0; i < n; i++) {
    out[i] = tmp[n - 1 - i];
    if (i < n - 1) out[i] |= 0x80;
  }
  *nOut = (size_t)n;
  return BER_OK;
}

static int subidDecode(const uint8_t* in, size_t max, size_t* pos,
                       uint32_t* v) {
  uint32_t val = 0;
  int len = 0;
  for (;;) {
    if (*pos >= max || len >= 5) return BER_ERR_OID;  // > 5 octets = overflow
    uint8_t b = in[(*pos)++];
    len++;
    if (val > 0x0FFFFFFFu) return BER_ERR_OVERFLOW;
    val = (val << 7) | (b & 0x7F);
    if (!(b & 0x80)) break;
  }
  *v = val;
  return BER_OK;
}

int berEncodeOid(uint8_t* out, size_t cap, const uint32_t* arcs, size_t nArcs) {
  if (nArcs < 2) return BER_ERR_OID;
  if (arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39)) return BER_ERR_OID;
  if (nArcs > BER_OID_MAX_ARCS) return BER_ERR_OID;

  uint8_t body[128];
  size_t n = 0;
  size_t nSub = 0;
  uint32_t first = arcs[0] * 40u + arcs[1];
  int r = subidEncode(body + n, sizeof body - n, first, &nSub);
  if (r < 0) return r;
  n += nSub;
  for (size_t i = 2; i < nArcs; i++) {
    r = subidEncode(body + n, sizeof body - n, arcs[i], &nSub);
    if (r < 0) return r;
    n += nSub;
  }
  return berEncodeTlv(out, cap, BER_TAG_OID, body, n);
}

int berDecodeOid(const uint8_t* in, size_t max, size_t* pos,
                 uint32_t* arcs, size_t* nArcs) {
  uint8_t tag;
  size_t len;
  int r = berDecodeTlv(in, max, pos, &tag, &len);
  if (r < 0) return r;
  if (tag != BER_TAG_OID) return BER_ERR_TYPE;
  if (len == 0) return BER_ERR_OID;

  size_t start = *pos;
  size_t end = start + len;
  size_t arcsOut = 0;
  uint32_t sub;

  // first subidentifier encodes arcs[0] and arcs[1]
  r = subidDecode(in, end, pos, &sub);
  if (r < 0) return r;
  if (sub < 40)               { arcs[0] = 0; arcs[1] = sub; }
  else if (sub < 80)          { arcs[0] = 1; arcs[1] = sub - 40; }
  else                        { arcs[0] = 2; arcs[1] = sub - 80; }
  arcsOut = 2;

  while (*pos < end) {
    if (arcsOut >= *nArcs || arcsOut >= BER_OID_MAX_ARCS) return BER_ERR_OVERFLOW;
    r = subidDecode(in, end, pos, &sub);
    if (r < 0) return r;
    arcs[arcsOut++] = sub;
  }
  *nArcs = arcsOut;
  return BER_OK;
}

// --- Varbind ---------------------------------------------------------------
int berEncodeVarbind(uint8_t* out, size_t cap,
                     const uint32_t* name, size_t nameLen,
                     const uint8_t* valueTlv, size_t valueLen) {
  uint8_t body[256];
  size_t n = 0;
  int r = berEncodeOid(body + n, sizeof body - n, name, nameLen);
  if (r < 0) return r;
  n += (size_t)r;
  if (n + valueLen > sizeof body) return BER_ERR_OVERFLOW;
  memcpy(body + n, valueTlv, valueLen);
  n += valueLen;
  return berEncodeTlv(out, cap, BER_TAG_SEQUENCE, body, n);
}

int berDecodeVarbind(const uint8_t* in, size_t max, size_t* pos,
                     uint32_t* name, size_t* nameLen,
                     uint8_t* valueTag, size_t* valueOff, size_t* valueLen) {
  uint8_t tag;
  size_t len;
  int r = berDecodeTlv(in, max, pos, &tag, &len);
  if (r < 0) return r;
  if (tag != BER_TAG_SEQUENCE) return BER_ERR_TYPE;

  size_t contentEnd = *pos + len;
  size_t nArcs = BER_OID_MAX_ARCS;
  r = berDecodeOid(in, contentEnd, pos, name, &nArcs);
  if (r < 0) return r;
  *nameLen = nArcs;

  r = berDecodeTlv(in, contentEnd, pos, valueTag, valueLen);
  if (r < 0) return r;
  *valueOff = *pos;
  *pos = contentEnd;   // skip value contents (uninterpreted here)
  return BER_OK;
}

// --- PDU -------------------------------------------------------------------
int berEncodePdu(uint8_t* out, size_t cap, uint8_t pduTag,
                 uint32_t reqId, uint32_t status, uint32_t idx,
                 const BerVarbind* vbs, size_t nvbs) {
  uint8_t body[1536];
  size_t n = 0;
  int r = berEncodeInt32(body + n, sizeof body - n, (int32_t)reqId);
  if (r < 0) return r;
  n += (size_t)r;
  r = berEncodeInt32(body + n, sizeof body - n, (int32_t)status);
  if (r < 0) return r;
  n += (size_t)r;
  r = berEncodeInt32(body + n, sizeof body - n, (int32_t)idx);
  if (r < 0) return r;
  n += (size_t)r;
  for (size_t i = 0; i < nvbs; i++) {
    r = berEncodeVarbind(body + n, sizeof body - n,
                         vbs[i].name, vbs[i].nameLen,
                         vbs[i].valueTlv, vbs[i].valueLen);
    if (r < 0) return r;
  n += (size_t)r;
  }
  return berEncodeTlv(out, cap, pduTag, body, n);
}

int berDecodePdu(const uint8_t* in, size_t max, size_t* pos,
                 uint8_t* pduTag, uint32_t* reqId,
                 uint32_t* status, uint32_t* idx,
                 BerVarbind* vbs, size_t maxVbs, size_t* nvbs) {
  uint8_t tag;
  size_t len;
  int r = berDecodeTlv(in, max, pos, &tag, &len);
  if (r < 0) return r;
  *pduTag = tag;

  size_t contentEnd = *pos + len;
  int32_t v;
  r = berDecodeInt32(in, contentEnd, pos, &v); if (r < 0) return r; *reqId = (uint32_t)v;
  r = berDecodeInt32(in, contentEnd, pos, &v); if (r < 0) return r; *status = (uint32_t)v;
  r = berDecodeInt32(in, contentEnd, pos, &v); if (r < 0) return r; *idx = (uint32_t)v;

  size_t n = 0;
  while (*pos < contentEnd) {
    if (n >= maxVbs) return BER_ERR_OVERFLOW;
    size_t nameLen = BER_OID_MAX_ARCS;
    r = berDecodeVarbind(in, contentEnd, pos,
                         vbs[n].name, &nameLen,
                         &vbs[n].decValueTag, &vbs[n].decValueOff,
                         &vbs[n].decValueLen);
    if (r < 0) return r;
    vbs[n].nameLen = nameLen;
    n++;
  }
  *nvbs = n;
  return BER_OK;
}

// --- ScopedPDU --------------------------------------------------------------
int berEncodeScopedPdu(uint8_t* out, size_t cap,
                       const uint8_t* ctxEngineId, size_t ctxEngineIdLen,
                       const uint8_t* ctxName, size_t ctxNameLen,
                       const uint8_t* pdu, size_t pduLen) {
  uint8_t body[1536];
  size_t n = 0;
  int r = berEncodeOctetString(body + n, sizeof body - n, ctxEngineId, ctxEngineIdLen);
  if (r < 0) return r;
  n += (size_t)r;
  r = berEncodeOctetString(body + n, sizeof body - n, ctxName, ctxNameLen);
  if (r < 0) return r;
  n += (size_t)r;
  if (n + pduLen > sizeof body) return BER_ERR_OVERFLOW;
  memcpy(body + n, pdu, pduLen);
  n += pduLen;
  return berEncodeTlv(out, cap, BER_TAG_SEQUENCE, body, n);
}

int berDecodeScopedPdu(const uint8_t* in, size_t max, size_t* pos,
                       size_t* ctxEngineIdOff, size_t* ctxEngineIdLen,
                       size_t* ctxNameOff, size_t* ctxNameLen,
                       size_t* pduOff, size_t* pduLen) {
  uint8_t tag;
  size_t len;
  int r = berDecodeTlv(in, max, pos, &tag, &len);
  if (r < 0) return r;
  if (tag != BER_TAG_SEQUENCE) return BER_ERR_TYPE;
  size_t contentEnd = *pos + len;

  // contextEngineID ::= OCTET STRING
  uint8_t t2;
  r = berDecodeTlv(in, contentEnd, pos, &t2, &len);
  if (r < 0) return r;
  if (t2 != BER_TAG_OCTET_STRING) return BER_ERR_TYPE;
  *ctxEngineIdOff = *pos;
  *ctxEngineIdLen = len;
  *pos += len;

  // contextName ::= OCTET STRING
  r = berDecodeTlv(in, contentEnd, pos, &t2, &len);
  if (r < 0) return r;
  if (t2 != BER_TAG_OCTET_STRING) return BER_ERR_TYPE;
  *ctxNameOff = *pos;
  *ctxNameLen = len;
  *pos += len;

  // remaining = PDU TLV
  *pduOff = *pos;
  *pduLen = contentEnd - *pos;
  *pos = contentEnd;
  return BER_OK;
}

// --- v3 message envelope ----------------------------------------------------
int berEncodeV3Message(uint8_t* out, size_t cap,
                       uint32_t msgId, uint32_t maxSize,
                       uint8_t msgFlags, uint8_t secModel,
                       const uint8_t* secParams, size_t secParamsLen,
                       const uint8_t* scopedPdu, size_t scopedPduLen) {
  uint8_t body[1600];
  size_t n = 0;
  int r = berEncodeInt32(body + n, sizeof body - n, 3);      // msgVersion
  if (r < 0) return r;
  n += (size_t)r;
  r = berEncodeInt32(body + n, sizeof body - n, (int32_t)msgId);
  if (r < 0) return r;
  n += (size_t)r;
  r = berEncodeInt32(body + n, sizeof body - n, (int32_t)maxSize);
  if (r < 0) return r;
  n += (size_t)r;
  r = berEncodeOctetString(body + n, sizeof body - n, &msgFlags, 1);
  if (r < 0) return r;
  n += (size_t)r;
  r = berEncodeInt32(body + n, sizeof body - n, (int32_t)secModel);
  if (r < 0) return r;
  n += (size_t)r;
  r = berEncodeOctetString(body + n, sizeof body - n, secParams, secParamsLen);
  if (r < 0) return r;
  n += (size_t)r;
  if (msgFlags & 0x02) {
    // privFlag set: msgData ::= OCTET STRING (encrypted scopedPDU bytes)
    r = berEncodeOctetString(body + n, sizeof body - n, scopedPdu, scopedPduLen);
    if (r < 0) return r;
    n += (size_t)r;
  } else {
    // no priv: msgData ::= scopedPDU in plaintext (already a TLV)
    if (n + scopedPduLen > sizeof body) return BER_ERR_OVERFLOW;
    memcpy(body + n, scopedPdu, scopedPduLen);
    n += scopedPduLen;
  }
  return berEncodeTlv(out, cap, BER_TAG_SEQUENCE, body, n);
}

int berDecodeV3Message(const uint8_t* in, size_t max,
                       uint8_t* version, uint32_t* msgId, uint32_t* maxSize,
                       uint8_t* msgFlags, uint8_t* secModel,
                       size_t* secParamsOff, size_t* secParamsLen,
                       size_t* scopedPduOff, size_t* scopedPduLen) {
  uint8_t tag;
  size_t len;
  size_t pos = 0;
  int r = berDecodeTlv(in, max, &pos, &tag, &len);
  if (r < 0) return r;
  if (tag != BER_TAG_SEQUENCE) return BER_ERR_TYPE;
  size_t contentEnd = pos + len;

  int32_t v;
  r = berDecodeInt32(in, contentEnd, &pos, &v);          // msgVersion
  if (r < 0) return r;
  if (v != 3) return BER_ERR_TYPE;                       // v3 only
  if (version != NULL) *version = (uint8_t)v;

  r = berDecodeInt32(in, contentEnd, &pos, &v);          // msgID
  if (r < 0) return r;
  *msgId = (uint32_t)v;

  r = berDecodeInt32(in, contentEnd, &pos, &v);          // msgMaxSize
  if (r < 0) return r;
  *maxSize = (uint32_t)v;

  r = berDecodeTlv(in, contentEnd, &pos, &tag, &len);    // msgFlags
  if (r < 0) return r;
  if (tag != BER_TAG_OCTET_STRING || len != 1) return BER_ERR_TYPE;
  *msgFlags = in[pos];
  pos += 1;

  r = berDecodeInt32(in, contentEnd, &pos, &v);          // security model
  if (r < 0) return r;
  *secModel = (uint8_t)v;

  r = berDecodeTlv(in, contentEnd, &pos, &tag, &len);    // securityParameters
  if (r < 0) return r;
  if (tag != BER_TAG_OCTET_STRING) return BER_ERR_TYPE;
  *secParamsOff = pos;
  *secParamsLen = len;
  pos += len;

  // msgData (RFC 3412 §6): with privFlag set it is an OCTET STRING wrapping
  // the encrypted scopedPDU; otherwise the scopedPDU appears in plaintext.
  // Return the bytes the caller decrypts-or-parses into a ScopedPDU:
  //   priv   -> ciphertext content (decrypt, then berDecodeScopedPdu)
  //   no priv-> the full plaintext scopedPDU TLV (berDecodeScopedPdu directly)
  size_t msgDataStart = pos;
  r = berDecodeTlv(in, contentEnd, &pos, &tag, &len);
  if (r < 0) return r;
  if ((*msgFlags >> 1) & 0x01) {
    if (tag != BER_TAG_OCTET_STRING) return BER_ERR_TYPE;
    *scopedPduOff = pos;
    *scopedPduLen = len;
  } else {
    if (tag != BER_TAG_SEQUENCE) return BER_ERR_TYPE;
    *scopedPduOff = msgDataStart;
    *scopedPduLen = (pos - msgDataStart) + len;
  }
  pos += len;
  if (pos != contentEnd) return BER_ERR_LENGTH;          // trailing garbage
  return BER_OK;
}