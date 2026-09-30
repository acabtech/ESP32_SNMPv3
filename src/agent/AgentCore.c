// AgentCore.c — SNMPv3 agent request-processing core (M2).
//
// Single-threaded by contract (the Arduino loop() drives it): scratch
// buffers are static. See AgentCore.h for the processing contract.
//
// SPDX-License-Identifier: GPL-3.0
#include "AgentCore.h"

#include <string.h>

#include "../ber/BER.h"
#include "../mib/MIB.h"

static int decodeIncomingPdu(const uint8_t* plain, size_t plainLen,
                             uint8_t* pduTag, uint32_t* reqId,
                             uint32_t* status, uint32_t* idx,
                             BerVarbind* vbs, size_t maxVbs, size_t* nvbs);
static bool statsVarbind(BerVarbind* vb, size_t statIdx, uint32_t value,
                         uint8_t* valueTlv, size_t valueTlvCap);

// usmStats OIDs: 1.3.6.1.6.3.15.1.1.<n>.0  (SNMP-USER-BASED-SM-MIB)
static const uint32_t kUsmStatsBase[] = {1, 3, 6, 1, 6, 3, 15, 1, 1};
#define USM_STATS_BASE_LEN (sizeof kUsmStatsBase / sizeof kUsmStatsBase[0])

#define USM_TIME_WINDOW 150u          // RFC 3414 §2.2.3
#define USM_TIME_MAX    2147483647u   // RFC 3414: engineTime range

#define AGENT_MAX_VBS 32              // varbinds processed per request

// Scratch buffers — the agent is single-threaded (loop()-driven).
static uint8_t     s_pdu[AGENT_MAX_MSG];
static uint8_t     s_scoped[AGENT_MAX_MSG + 64];
static uint8_t     s_ct[AGENT_MAX_MSG + 64];
static uint8_t     s_sec[256];
static size_t      s_secLen;
static uint8_t     s_plain[AGENT_MAX_MSG];
static uint8_t     s_vbValue[AGENT_MAX_VBS][MIB_OCTETS_MAX + 16];
static BerVarbind  s_vbs[AGENT_MAX_VBS];
static BerVarbind  s_outVbs[AGENT_MAX_VBS];

// --- init / users -----------------------------------------------------------

void agentInit(AgentState* s,
               const uint8_t* engineId, size_t engineIdLen,
               uint32_t boots, uint32_t nowMs, uint32_t maxMessageSize) {
  memset(s, 0, sizeof *s);
  if (engineIdLen > sizeof s->engineId) engineIdLen = sizeof s->engineId;
  memcpy(s->engineId, engineId, engineIdLen);
  s->engineIdLen = engineIdLen;
  s->clock.boots = boots;
  s->clock.time = 0;
  s->clock.monotonicMs = nowMs;
  s->maxMessageSize = maxMessageSize ? maxMessageSize : AGENT_MAX_MSG;
  // RFC 3826: salt unique per encrypted message; the boot/time seed keeps
  // uniqueness across reboots.
  s->saltCounter = ((uint64_t)boots << 32) | (uint64_t)(nowMs / 1000);
}

int agentAddUser(AgentState* s, const char* name,
                 const uint8_t* authKey, const uint8_t* privKey) {
  if (s->nUsers >= AGENT_MAX_USERS) return -1;
  if (name == NULL || authKey == NULL || privKey == NULL) return -1;
  size_t len = strlen(name);
  if (len == 0 || len >= AGENT_NAME_MAX) return -1;
  AgentUser* u = &s->users[s->nUsers];
  strcpy(u->name, name);
  u->nameLen = len;
  memcpy(u->authKey, authKey, SNMPV3_SHA256_KEY);
  memcpy(u->privKey, privKey, SNMPV3_AES128_KEY);
  return (int)s->nUsers++;
}

// --- small helpers ----------------------------------------------------------

static bool memEq(const void* a, const void* b, size_t n) {
  return memcmp(a, b, n) == 0;
}

// Fresh authoritative engine time (seconds), keeping the clock current.
// Advances the monotonic anchor so usmTimeNow() downstream never
// double-counts the elapsed interval.
static uint32_t engineTimeNow(AgentState* s, uint32_t nowMs) {
  uint32_t elapsed = (uint32_t)((nowMs - (uint32_t)s->clock.monotonicMs) / 1000u);
  s->clock.time += elapsed;
  s->clock.monotonicMs = nowMs;
  if (s->clock.time > USM_TIME_MAX) s->clock.time = USM_TIME_MAX;
  return s->clock.time;
}

// Encode a MIB value into its BER TLV (application tags for SMI types).
static int encodeMibValue(uint8_t* out, size_t cap, const MibValue* v) {
  switch (v->type) {
    case MIB_T_INT32:
      return berEncodeInt32(out, cap, (int32_t)v->u32);
    case MIB_T_UINT32:
      return berEncodeUintTagged(out, cap, BER_TAG_UNSIGNED32, v->u32);
    case MIB_T_TIMETICKS:
      return berEncodeUintTagged(out, cap, BER_TAG_TIMETICKS, v->u32);
    case MIB_T_COUNTER32:
      return berEncodeUintTagged(out, cap, BER_TAG_COUNTER32, v->u32);
    case MIB_T_OCTETS:
      return berEncodeOctetString(out, cap, v->octets, v->octetsLen);
    case MIB_T_OID:
      return berEncodeOid(out, cap, v->arcs, v->arcsLen);
  }
  return -1;
}

static int encodeException(uint8_t* out, size_t cap, uint8_t tag) {
  return berEncodeTlv(out, cap, tag, NULL, 0);
}

// --- securityParameters -----------------------------------------------------

typedef struct {
  const uint8_t* engineId; size_t engineIdLen;
  uint32_t boots, time;
  const uint8_t* user;     size_t userLen;
  size_t authParamsOff;    // content offset, relative to the SEQUENCE start
  const uint8_t* salt;     // NULL unless the priv flag is set
} SecParams;

static int decodeSecParams(const uint8_t* sp, size_t spLen, uint8_t flags,
                           SecParams* p) {
  memset(p, 0, sizeof *p);
  size_t pos = 0;
  uint8_t tag; size_t len;
  int r = berDecodeTlv(sp, spLen, &pos, &tag, &len);
  if (r < 0 || tag != BER_TAG_SEQUENCE) return -1;
  size_t end = pos + len;

  r = berDecodeTlv(sp, end, &pos, &tag, &len);                 // engineID
  if (r < 0 || tag != BER_TAG_OCTET_STRING) return -1;
  p->engineId = sp + pos; p->engineIdLen = len;
  pos += len;

  r = berDecodeInt32(sp, end, &pos, (int32_t*)&p->boots);      // engineBoots
  if (r < 0) return -1;

  r = berDecodeInt32(sp, end, &pos, (int32_t*)&p->time);       // engineTime
  if (r < 0) return -1;

  r = berDecodeTlv(sp, end, &pos, &tag, &len);                 // userName
  if (r < 0 || tag != BER_TAG_OCTET_STRING) return -1;
  p->user = sp + pos; p->userLen = len;
  pos += len;

  r = berDecodeTlv(sp, end, &pos, &tag, &len);                 // authParams
  if (r < 0 || tag != BER_TAG_OCTET_STRING) return -1;
  if (flags & 0x01) {
    if (len != SNMPV3_SHA256_MAC) return -1;
    p->authParamsOff = pos;
  }
  pos += len;

  r = berDecodeTlv(sp, end, &pos, &tag, &len);                 // privParams
  if (r < 0 || tag != BER_TAG_OCTET_STRING) return -1;
  if (flags & 0x02) {
    if (len != SNMPV3_PRIV_SALT) return -1;
    p->salt = sp + pos;
  }
  pos += len;

  if (pos != end) return -1;
  return 0;
}

// --- message assembly -------------------------------------------------------

// Assemble the v3 message around a prepared PDU; encrypt and MAC-patch as
// flagged. user == NULL builds an unauthenticated report skeleton.
static int assembleMessage(AgentState* s,
                           const AgentUser* user,
                           uint32_t msgId, uint8_t flags,
                           const uint8_t* pdu, size_t pduLen,
                           uint8_t* out, size_t cap, size_t* outLen) {
  static const uint8_t zeroAuth[SNMPV3_SHA256_MAC] = {0};
  uint8_t salt[SNMPV3_PRIV_SALT] = {0};
  bool wantPriv = (flags & 0x02) != 0;

  // scopedPDU (always built in plaintext first)
  int r = berEncodeScopedPdu(s_scoped, sizeof s_scoped,
                             s->engineId, s->engineIdLen, (const uint8_t*)"", 0,
                             pdu, pduLen);
  if (r < 0) return r;
  size_t scopedLen = (size_t)r;

  // privacy: encrypt scoped with a fresh salt (RFC 3826 §3.1.3)
  if (wantPriv) {
    s->saltCounter++;
    for (int i = 0; i < SNMPV3_PRIV_SALT; i++)
      salt[i] = (uint8_t)(s->saltCounter >> (56 - 8 * i));
    uint8_t iv[SNMPV3_AES_IV];
    usmAesMakeIv(iv, s->clock.boots, s->clock.time, salt);
    r = usmAesCfbEncrypt(user->privKey, iv, s_scoped, s_ct, scopedLen);
    if (r < 0) return r;
  }

  // securityParameters (authParams zero — the MAC placeholder)
  static const uint8_t emptyName[1] = {0};
  r = usmBuildSecurityParams(s_sec, sizeof s_sec,
                             s->engineId, s->engineIdLen,
                             s->clock.boots, s->clock.time,
                             user ? (const uint8_t*)user->name : emptyName,
                             user ? user->nameLen : 0,
                             zeroAuth, salt, &s_secLen);
  if (r < 0) return r;

  // message envelope (scopedPDU is ciphertext when the priv flag is set)
  r = berEncodeV3Message(out, cap, msgId, s->maxMessageSize, flags, 3,
                         s_sec, s_secLen,
                         wantPriv ? s_ct : s_scoped,
                         scopedLen);
  if (r < 0) return r;
  size_t msgLen = (size_t)r;

  // MAC over the whole message with zeroed authParams, then patch (RFC 7860)
  if (flags & 0x01) {
    uint8_t ver; uint32_t mid, msize; uint8_t fl, sm;
    size_t spo, spl, sdo, sdl;
    r = berDecodeV3Message(out, msgLen, &ver, &mid, &msize, &fl, &sm,
                           &spo, &spl, &sdo, &sdl);
    if (r < 0) return r;
    SecParams sp;
    r = decodeSecParams(out + spo, spl, fl, &sp);
    if (r < 0) return r;
    uint8_t digest[SNMPV3_SHA256_KEY];
    r = usmHmacSha256(user->authKey, SNMPV3_SHA256_KEY, out, msgLen, digest);
    if (r < 0) return r;
    memcpy(out + spo + sp.authParamsOff, digest, SNMPV3_SHA256_MAC);
  }
  *outLen = msgLen;
  return 0;
}

// --- Report PDU (RFC 3412 §7.2.6, RFC 3414 §4) ------------------------------

static int buildReport(AgentState* s, uint32_t msgId,
                       uint32_t reqId, size_t statIdx, uint32_t statValue,
                       uint8_t* out, size_t cap, size_t* outLen) {
  uint8_t vbuf[8];
  BerVarbind vb;
  if (!statsVarbind(&vb, statIdx, statValue, vbuf, sizeof vbuf)) return -1;
  int r = berEncodePdu(s_pdu, sizeof s_pdu, BER_TAG_REPORT, reqId, 0, 0,
                       &vb, 1);
  if (r < 0) return r;
  // Reports are unauthenticated/unencrypted; the securityParameters carry
  // OUR engine ID/boots/time (that IS the discovery payload), empty user.
  return assembleMessage(s, NULL, msgId, 0x04, s_pdu, (size_t)r,
                         out, cap, outLen);
}

// usmStats report varbind: OID 1.3.6.1.6.3.15.1.1.<idx+1>.0 + Counter32.
static bool statsVarbind(BerVarbind* vb, size_t statIdx, uint32_t value,
                         uint8_t* valueTlv, size_t valueTlvCap) {
  if (statIdx >= 6) return false;
  memcpy(vb->name, kUsmStatsBase, sizeof kUsmStatsBase);
  vb->name[USM_STATS_BASE_LEN] = (uint32_t)(statIdx + 1);
  vb->name[USM_STATS_BASE_LEN + 1] = 0;
  vb->nameLen = USM_STATS_BASE_LEN + 2;
  int n = berEncodeUintTagged(valueTlv, valueTlvCap, BER_TAG_COUNTER32, value);
  if (n < 0) return false;
  vb->valueTlv = valueTlv;
  vb->valueLen = (size_t)n;
  return true;
}

// --- request parsing helpers ------------------------------------------------

// Pull request-id out of a plaintext scopedPDU TLV region (best effort).
static void extractReqId(const uint8_t* scoped, size_t scopedLen,
                         uint32_t* reqId) {
  *reqId = 0;
  if (scoped == NULL || scopedLen < 8) return;
  size_t pos = 0, ceo, cel, cno, cnl, po, pl;
  if (berDecodeScopedPdu(scoped, scopedLen, &pos, &ceo, &cel, &cno, &cnl,
                         &po, &pl) < 0)
    return;
  pos = 0;
  uint8_t tag; uint32_t status, idx;
  BerVarbind vbs[1];
  size_t nvbs;
  if (berDecodePdu(scoped + po, pl, &pos, &tag, reqId, &status, &idx,
                   vbs, 1, &nvbs) < 0)
    *reqId = 0;
}

// --- MIB dispatch helpers ---------------------------------------------------

// GET varbind: value or per-varbind exception. Returns 0 ok.
static int vbForGet(const BerVarbind* reqVb, BerVarbind* outVb,
                    uint8_t* valueBuf, size_t valueCap) {
  MibValue val;
  int r = mibGet(reqVb->name, reqVb->nameLen, &val);
  int n;
  if (r == 1) {
    n = encodeMibValue(valueBuf, valueCap, &val);
    if (n < 0) return -1;
  } else if (r == 0) {
    uint8_t exc = mibNoSuchInstance(reqVb->name, reqVb->nameLen)
                      ? BER_TAG_NOSUCHINSTANCE : BER_TAG_NOSUCHOBJECT;
    n = encodeException(valueBuf, valueCap, exc);
    if (n < 0) return -1;
  } else {
    return -1;  // getter failure -> caller emits genErr
  }
  memcpy(outVb->name, reqVb->name, reqVb->nameLen * sizeof outVb->name[0]);
  outVb->nameLen = reqVb->nameLen;
  outVb->valueTlv = valueBuf;
  outVb->valueLen = (size_t)n;
  return 0;
}

// GETNEXT varbind: successor or endOfMibView. Returns 0 ok (1 = eomv built).
static int vbForGetNext(const BerVarbind* reqVb, BerVarbind* outVb,
                        uint8_t* valueBuf, size_t valueCap) {
  uint32_t nextName[BER_OID_MAX_ARCS];
  size_t nextLen;
  if (mibNext(reqVb->name, reqVb->nameLen, nextName, &nextLen) == 0) {
    int n = encodeException(valueBuf, valueCap, BER_TAG_ENDOFMIBVIEW);
    if (n < 0) return -1;
    memcpy(outVb->name, reqVb->name, reqVb->nameLen * sizeof outVb->name[0]);
    outVb->nameLen = reqVb->nameLen;
    outVb->valueTlv = valueBuf;
    outVb->valueLen = (size_t)n;
    return 1;
  }
  MibValue val;
  if (mibGet(nextName, nextLen, &val) != 1) return -1;
  int n = encodeMibValue(valueBuf, valueCap, &val);
  if (n < 0) return -1;
  memcpy(outVb->name, nextName, nextLen * sizeof outVb->name[0]);
  outVb->nameLen = nextLen;
  outVb->valueTlv = valueBuf;
  outVb->valueLen = (size_t)n;
  return 0;
}

// Map a MIB set result to a PDU error-status (RFC 3416 §3 guidance).
static uint32_t setStatusFor(int mibResult) {
  switch (mibResult) {
    case MIB_SET_APPLIED:    return SNMP_ERR_NO_ERROR;
    case MIB_SET_NO_SUCH:    return SNMP_ERR_NOT_WRITABLE;
    case MIB_SET_READ_ONLY:  return SNMP_ERR_NOT_WRITABLE;
    case MIB_SET_WRONG_TYPE: return SNMP_ERR_WRONG_TYPE;
    case MIB_SET_REJECTED:   return SNMP_ERR_WRONG_VALUE;
    default:                 return SNMP_ERR_GEN_ERR;
  }
}

// Decode a varbind value TLV into a MibValue (SET support).
// `off`/`len` point at the value CONTENT octets (the TLV was already split by
// the varbind decoder), so INTEGER is decoded directly from those bytes.
static int decodeMibValue(const uint8_t* in, size_t off, size_t len,
                          uint8_t tag, MibValue* out) {
  memset(out, 0, sizeof *out);
  switch (tag) {
    case BER_TAG_INTEGER: {
      if (len == 0 || len > 4) return BER_ERR_OVERFLOW;
      int32_t v = (in[off] & 0x80) ? -1 : 0;   // sign-extend two's complement
      for (size_t i = 0; i < len; i++) v = (int32_t)((v << 8) | in[off + i]);
      out->type = MIB_T_INT32;
      out->u32 = (uint32_t)v;
      return 0;
    }
    case BER_TAG_OCTET_STRING:
      if (len > MIB_OCTETS_MAX) return BER_ERR_OVERFLOW;
      memcpy(out->octets, in + off, len);
      out->type = MIB_T_OCTETS;
      out->octetsLen = len;
      return 0;
    default:
      return BER_ERR_TYPE;
  }
}

// Echo a request varbind into the response list (error responses per
// RFC 3416 §4.2.x: "same values in request-id and variable-bindings").
static int echoVarbind(const BerVarbind* reqVb, const uint8_t* in,
                       BerVarbind* outVb, uint8_t* valueBuf, size_t valueCap) {
  int n = berEncodeTlv(valueBuf, valueCap, reqVb->decValueTag,
                       in + reqVb->decValueOff, reqVb->decValueLen);
  if (n < 0) return -1;
  memcpy(outVb->name, reqVb->name, reqVb->nameLen * sizeof outVb->name[0]);
  outVb->nameLen = reqVb->nameLen;
  outVb->valueTlv = valueBuf;
  outVb->valueLen = (size_t)n;
  return 0;
}

// --- main entry -------------------------------------------------------------

int agentProcess(AgentState* s, const uint8_t* in0, size_t inLen,
                 uint32_t nowMs, uint8_t* out, size_t cap, size_t* outLen) {
  *outLen = 0;
  if (inLen < 16 || inLen > AGENT_MAX_MSG) return AGENT_ERR_DROP;
  // Working copy: the MAC check zeroes authParams in place, so the
  // input must be mutable (callers may pass const/read-only memory).
  static uint8_t s_msg[AGENT_MAX_MSG];
  memcpy(s_msg, in0, inLen);
  const uint8_t* in = s_msg;

  engineTimeNow(s, nowMs);  // keep the authoritative clock fresh

  // 1) envelope
  uint8_t ver; uint32_t msgId, msgMax; uint8_t flags, secModel;
  size_t spo, spl, sdo, sdl;
  int r = berDecodeV3Message(in, inLen, &ver, &msgId, &msgMax, &flags,
                             &secModel, &spo, &spl, &sdo, &sdl);
  if (r < 0 || secModel != 3) return AGENT_ERR_DROP;

  // 2) securityParameters
  SecParams sp;
  if (decodeSecParams(in + spo, spl, flags, &sp) < 0) return AGENT_ERR_DROP;

  bool reportable = (flags & 0x04) != 0;
  bool wantAuth = (flags & 0x01) != 0;
  bool wantPriv = (flags & 0x02) != 0;

  // Best-effort request-id for reports (plaintext scopedPDU only).
  uint32_t reqId = 0;
  if (!wantPriv && sdl >= 8 && sdl <= sizeof s_plain) {
    memcpy(s_plain, in + sdo, sdl);
    extractReqId(s_plain, sdl, &reqId);
  }

  // --- security gate (RFC 3414 §3.2 order) --------------------------------
  if (!wantAuth) {
    // noAuthNoPriv: discovery (empty/unknown engine or user) is served;
    // a KNOWN user below its security level gets UnsupportedSecLevels.
    bool engineUnknown = sp.engineIdLen != s->engineIdLen ||
                         (s->engineIdLen != 0 &&
                          !memEq(sp.engineId, s->engineId, s->engineIdLen));
    bool userKnown = false;
    for (size_t i = 0; i < s->nUsers; i++) {
      if (s->users[i].nameLen == sp.userLen &&
          memcmp(s->users[i].name, sp.user, sp.userLen) == 0) {
        userKnown = true;
        break;
      }
    }
    size_t statIdx;
    if (engineUnknown) statIdx = 3;        // usmStatsUnknownEngineIDs
    else if (!userKnown) statIdx = 2;      // usmStatsUnknownUserNames
    else statIdx = 0;                      // usmStatsUnsupportedSecLevels
    s->stats[statIdx]++;
    if (!reportable) return AGENT_NO_RESPONSE;
    size_t n = 0;
    if (buildReport(s, msgId, reqId, statIdx, s->stats[statIdx],
                    out, cap, &n) == 0) {
      *outLen = n;
      return AGENT_RESPONSE;
    }
    return AGENT_ERR_DROP;
  }

  // authenticated paths: engineID must match (empty engineID is tolerated
  // for robustness — the MAC still pins the identity via localized keys).
  if (sp.engineIdLen != 0 &&
      (sp.engineIdLen != s->engineIdLen ||
       !memEq(sp.engineId, s->engineId, s->engineIdLen))) {
    s->stats[3]++;
    if (!reportable) return AGENT_NO_RESPONSE;
    size_t n = 0;
    if (buildReport(s, msgId, reqId, 3, s->stats[3], out, cap, &n) == 0) {
      *outLen = n;
      return AGENT_RESPONSE;
    }
    return AGENT_ERR_DROP;
  }

  // user lookup
  AgentUser* user = NULL;
  for (size_t i = 0; i < s->nUsers; i++) {
    if (s->users[i].nameLen == sp.userLen &&
        memcmp(s->users[i].name, sp.user, sp.userLen) == 0) {
      user = &s->users[i];
      break;
    }
  }
  if (user == NULL) {
    s->stats[2]++;
    if (!reportable) return AGENT_NO_RESPONSE;
    size_t n = 0;
    if (buildReport(s, msgId, reqId, 2, s->stats[2], out, cap, &n) == 0) {
      *outLen = n;
      return AGENT_RESPONSE;
    }
    return AGENT_ERR_DROP;
  }

  // timeliness (RFC 3414 §3.2: before the MAC check)
  if (usmTimelinessCheck(&s->clock, sp.boots, sp.time, nowMs) < 0) {
    s->stats[1]++;
    if (!reportable) return AGENT_NO_RESPONSE;
    size_t n = 0;
    if (buildReport(s, msgId, reqId, 1, s->stats[1], out, cap, &n) == 0) {
      *outLen = n;
      return AGENT_RESPONSE;
    }
    return AGENT_ERR_DROP;
  }

  // MAC verify: zero authParams in place, HMAC, compare, restore.
  {
    uint8_t digest[SNMPV3_SHA256_KEY];
    const uint8_t* macRcv = in + spo + sp.authParamsOff;
    uint8_t saved[SNMPV3_SHA256_MAC];
    memcpy(saved, macRcv, SNMPV3_SHA256_MAC);
    memset((void*)macRcv, 0, SNMPV3_SHA256_MAC);
    r = usmHmacSha256(user->authKey, SNMPV3_SHA256_KEY, in, inLen, digest);
    memcpy((void*)macRcv, saved, SNMPV3_SHA256_MAC);
    if (r < 0 || memcmp(digest, saved, SNMPV3_SHA256_MAC) != 0) {
      s->stats[4]++;
      if (!reportable) return AGENT_NO_RESPONSE;
      size_t n = 0;
      if (buildReport(s, msgId, reqId, 4, s->stats[4], out, cap, &n) == 0) {
        *outLen = n;
        return AGENT_RESPONSE;
      }
      return AGENT_ERR_DROP;
    }
  }

  // replay cache (authenticated messages only; silent drop on repeat)
  for (size_t i = 0; i < AGENT_REPLAY_CACHE; i++) {
    if (s->seen[i].used && s->seen[i].msgId == msgId &&
        s->seen[i].userIdx == (size_t)(user - s->users)) {
      return AGENT_NO_RESPONSE;
    }
  }
  s->seen[s->seenCursor].used = true;
  s->seen[s->seenCursor].msgId = msgId;
  s->seen[s->seenCursor].userIdx = (size_t)(user - s->users);
  s->seenCursor = (s->seenCursor + 1) % AGENT_REPLAY_CACHE;

  // privacy: decrypt the scopedPDU (RFC 3826 §3.1.4)
  size_t plainLen;
  if (wantPriv) {
    if (sp.salt == NULL || sdl == 0 || sdl > sizeof s_plain)
      return AGENT_ERR_DROP;
    uint8_t iv[SNMPV3_AES_IV];
    usmAesMakeIv(iv, sp.boots, sp.time, sp.salt);
    if (usmAesCfbDecrypt(user->privKey, iv, in + sdo, s_plain, sdl) < 0)
      return AGENT_ERR_DROP;
    plainLen = sdl;
  } else {
    if (sdl < 2 || sdl > sizeof s_plain) return AGENT_ERR_DROP;
    memcpy(s_plain, in + sdo, sdl);
    plainLen = sdl;
  }

  // scopedPDU + PDU parse
  uint8_t pduTag; uint32_t status, idx;
  size_t nvbs = 0;
  r = decodeIncomingPdu(s_plain, plainLen, &pduTag, &reqId, &status, &idx,
                        s_vbs, AGENT_MAX_VBS, &nvbs);
  if (r < 0) {
    // garbage after decrypt (or malformed plaintext)
    if (wantPriv) {
      s->stats[5]++;
      if (!reportable) return AGENT_NO_RESPONSE;
      size_t n = 0;
      if (buildReport(s, msgId, 0, 5, s->stats[5], out, cap, &n) == 0) {
        *outLen = n;
        return AGENT_RESPONSE;
      }
    }
    return AGENT_ERR_DROP;
  }

  // context: our engine only, default (empty) context only
  {
    size_t pos = 0, ceo, cel, cno, cnl, po, pl;
    if (berDecodeScopedPdu(s_plain, plainLen, &pos, &ceo, &cel, &cno, &cnl,
                           &po, &pl) < 0)
      return AGENT_ERR_DROP;
    if (cel != 0 && (cel != s->engineIdLen ||
                     memcmp(s_plain + ceo, s->engineId, cel) != 0))
      return AGENT_ERR_DROP;
    if (cnl != 0) return AGENT_ERR_DROP;
  }

  // --- dispatch -------------------------------------------------------------
  uint32_t errStatus = SNMP_ERR_NO_ERROR;
  uint32_t errIndex = 0;
  size_t nvbOut = 0;

  if (pduTag == BER_TAG_GET_REQ) {
    for (size_t i = 0; i < nvbs; i++) {
      if (vbForGet(&s_vbs[i], &s_outVbs[nvbOut],
                   s_vbValue[nvbOut], sizeof s_vbValue[nvbOut]) < 0) {
        errStatus = SNMP_ERR_GEN_ERR;
        errIndex = (uint32_t)(i + 1);
        break;
      }
      nvbOut++;
    }
  } else if (pduTag == BER_TAG_GET_NEXT_REQ) {
    for (size_t i = 0; i < nvbs; i++) {
      if (vbForGetNext(&s_vbs[i], &s_outVbs[nvbOut],
                       s_vbValue[nvbOut], sizeof s_vbValue[nvbOut]) < 0) {
        errStatus = SNMP_ERR_GEN_ERR;
        errIndex = (uint32_t)(i + 1);
        break;
      }
      nvbOut++;
    }
  } else if (pduTag == BER_TAG_GET_BULK) {
    // status = non-repeaters, idx = max-repetitions (RFC 3416 §4.2.3)
    size_t nonRep = status > nvbs ? nvbs : status;
    size_t maxRep = idx > 32 ? 32 : idx;
    for (size_t i = 0; i < nvbs && errStatus == SNMP_ERR_NO_ERROR; i++) {
      if (i < nonRep) {
        if (vbForGetNext(&s_vbs[i], &s_outVbs[nvbOut],
                         s_vbValue[nvbOut], sizeof s_vbValue[nvbOut]) < 0) {
          errStatus = SNMP_ERR_GEN_ERR;
          errIndex = (uint32_t)(i + 1);
          break;
        }
        nvbOut++;
      } else {
        BerVarbind cursor;
        memcpy(cursor.name, s_vbs[i].name,
               s_vbs[i].nameLen * sizeof cursor.name[0]);
        cursor.nameLen = s_vbs[i].nameLen;
        for (size_t rep = 0; rep < maxRep && nvbOut < AGENT_MAX_VBS; rep++) {
          int n = vbForGetNext(&cursor, &s_outVbs[nvbOut],
                               s_vbValue[nvbOut], sizeof s_vbValue[nvbOut]);
          if (n < 0) {
            errStatus = SNMP_ERR_GEN_ERR;
            errIndex = (uint32_t)(i + 1);
            break;
          }
          nvbOut++;
          if (s_outVbs[nvbOut - 1].valueTlv[0] == BER_TAG_ENDOFMIBVIEW)
            break;  // this column is exhausted
          memcpy(cursor.name, s_outVbs[nvbOut - 1].name,
                 s_outVbs[nvbOut - 1].nameLen * sizeof cursor.name[0]);
          cursor.nameLen = s_outVbs[nvbOut - 1].nameLen;
        }
      }
    }
  } else if (pduTag == BER_TAG_SET_REQ) {
    // Apply in order; first failure becomes error-status/index (RFC 3416
    // §4.2.5 lite: no undo — the failing agent state is documented).
    for (size_t i = 0; i < nvbs && errStatus == SNMP_ERR_NO_ERROR; i++) {
      MibValue inVal;
      // decValueOff is rebased to the decrypted plaintext (s_plain).
      if (decodeMibValue(s_plain, s_vbs[i].decValueOff, s_vbs[i].decValueLen,
                         s_vbs[i].decValueTag, &inVal) < 0) {
        errStatus = SNMP_ERR_WRONG_TYPE;
        errIndex = (uint32_t)(i + 1);
        break;
      }
      int mr = mibSet(s_vbs[i].name, s_vbs[i].nameLen, &inVal);
      if (mr != MIB_SET_APPLIED) {
        errStatus = setStatusFor(mr);
        errIndex = (uint32_t)(i + 1);
      }
    }
    if (errStatus == SNMP_ERR_NO_ERROR) {
      // success: echo the CURRENT (post-set) values (RFC 3416 Â§4.2.5)
      for (size_t i = 0; i < nvbs; i++) {
        MibValue val;
        if (mibGet(s_vbs[i].name, s_vbs[i].nameLen, &val) != 1) {
          errStatus = SNMP_ERR_GEN_ERR;
          errIndex = (uint32_t)(i + 1);
          break;
        }
        int n = encodeMibValue(s_vbValue[i], sizeof s_vbValue[i], &val);
        if (n < 0) {
          errStatus = SNMP_ERR_GEN_ERR;
          errIndex = (uint32_t)(i + 1);
          break;
        }
        memcpy(s_outVbs[i].name, s_vbs[i].name,
               s_vbs[i].nameLen * sizeof s_outVbs[i].name[0]);
        s_outVbs[i].nameLen = s_vbs[i].nameLen;
        s_outVbs[i].valueTlv = s_vbValue[i];
        s_outVbs[i].valueLen = (size_t)n;
        nvbOut++;
      }
    }
  } else {
    // Responses/Reports/Traps/Informs/unknown PDUs: agent role ignores them.
    return AGENT_NO_RESPONSE;
  }

  // Error responses echo the REQUEST varbinds (RFC 3416 Â§4.2.x) except  // Error responses echo the REQUEST varbinds (RFC 3416 §4.2.x) except
  // tooBig which carries an empty list (§4.2.1/§4.2.2/§4.2.5).
  if (errStatus != SNMP_ERR_NO_ERROR && errStatus != SNMP_ERR_TOO_BIG) {
    nvbOut = 0;
    for (size_t i = 0; i < nvbs; i++) {
      if (echoVarbind(&s_vbs[i], s_plain, &s_outVbs[i],
                      s_vbValue[i], sizeof s_vbValue[i]) < 0) {
        return AGENT_ERR_DROP;
      }
      nvbOut++;
    }
  }

  size_t nOut = 0;
  if (errStatus == SNMP_ERR_TOO_BIG) {
    r = berEncodePdu(s_pdu, sizeof s_pdu, BER_TAG_RESPONSE, reqId,
                     SNMP_ERR_TOO_BIG, 0, NULL, 0);
  } else {
    r = berEncodePdu(s_pdu, sizeof s_pdu, BER_TAG_RESPONSE, reqId,
                     errStatus, errStatus == SNMP_ERR_NO_ERROR ? 0 : errIndex,
                     s_outVbs, nvbOut);
  }
  if (r < 0) return AGENT_ERR_DROP;

  // mirror the request's security level; tooBig-clamp oversized responses
  {
    uint8_t rflags = (uint8_t)(flags & 0x03);
    uint32_t limit = msgMax < s->maxMessageSize ? msgMax : s->maxMessageSize;
    if (assembleMessage(s, user, msgId, rflags, s_pdu, (size_t)r,
                        out, cap, &nOut) < 0)
      return AGENT_ERR_DROP;
    if (nOut > limit) {
      r = berEncodePdu(s_pdu, sizeof s_pdu, BER_TAG_RESPONSE, reqId,
                       SNMP_ERR_TOO_BIG, 0, NULL, 0);
      if (r < 0) return AGENT_ERR_DROP;
      if (assembleMessage(s, user, msgId, rflags, s_pdu, (size_t)r,
                          out, cap, &nOut) < 0)
        return AGENT_ERR_DROP;
    }
  }
  *outLen = nOut;
  return AGENT_RESPONSE;
}

// decodeIncomingPdu: scopedPDU region -> PDU fields + varbinds.
// The varbind value offsets are rebased to the FULL plaintext buffer (the
// caller's `plain`), so SET/echo can read value octets directly from it.
static int decodeIncomingPdu(const uint8_t* plain, size_t plainLen,
                             uint8_t* pduTag, uint32_t* reqId,
                             uint32_t* status, uint32_t* idx,
                             BerVarbind* vbs, size_t maxVbs, size_t* nvbs) {
  size_t pos = 0, ceo, cel, cno, cnl, po, pl;
  int r = berDecodeScopedPdu(plain, plainLen, &pos, &ceo, &cel, &cno, &cnl,
                             &po, &pl);
  if (r < 0) return r;
  pos = 0;
  r = berDecodePdu(plain + po, pl, &pos, pduTag, reqId, status, idx,
                   vbs, maxVbs, nvbs);
  if (r < 0) return r;
  for (size_t i = 0; i < *nvbs; i++) vbs[i].decValueOff += po;
  return r;
}