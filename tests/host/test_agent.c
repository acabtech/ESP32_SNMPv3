// test_agent.c — agent-core tests (src/agent/AgentCore.c): full-wire
// request/response roundtrips, security rejections, MIB dispatch.
//
// The wire oracles in vec/vectors.h are built independently by
// vgen/gen_vectors.py (Python hmac + cryptography). Byte-exact checks pin
// the whole pipeline; structural checks cover the rest.
//
// SPDX-License-Identifier: GPL-3.0
#include <stdio.h>
#include <string.h>

#include "agent/AgentCore.h"
#include "ber/BER.h"
#include "mib/MIB.h"
#include "vectors.h"

static int fails = 0;
static int checks = 0;

#define ok_(cond, name) \
  do { checks++; if (!(cond)) { fails++; printf("  FAIL %s\n", name); } } while (0)

static AgentState s_agent;
static uint8_t s_out[AGENT_MAX_MSG + 128];
static size_t s_outLen;

// --- hooks ------------------------------------------------------------------

static const uint8_t* hook_engineId(void)    { return V_M2_ENGID; }
static size_t hook_engineIdLen(void)         { return V_M2_ENGID_LEN; }
static uint32_t hook_engineBoots(void)       { return s_agent.clock.boots; }
static uint32_t hook_engineTime(void)        { return s_agent.clock.time; }
static uint32_t hook_engineMaxMsg(void)      { return 1500; }
static uint32_t hook_sysUpTime(void)         { return 123456; }  // hundredths
static uint32_t hook_usmStat(size_t i)       { return s_agent.stats[i]; }

static void agent_setup(void) {
  MibSystemHooks h;
  memset(&h, 0, sizeof h);
  h.sysUpTime = hook_sysUpTime;
  h.engineId = hook_engineId;
  h.engineIdLen = hook_engineIdLen;
  h.engineBoots = hook_engineBoots;
  h.engineTime = hook_engineTime;
  h.engineMaxMessage = hook_engineMaxMsg;
  h.usmStat = hook_usmStat;
  mibSetSystemHooks(&h);
  mibSetSystemText(NULL, NULL, NULL, NULL);   // defaults
  mibRegisterSystem();                        // idempotent

  agentInit(&s_agent, V_M2_ENGID, V_M2_ENGID_LEN, V_M2_BOOTS,
            V_M2_INIT_MS, 1500);
  s_agent.saltCounter = ((uint64_t)V_M2_BOOTS << 32) | (V_M2_INIT_MS / 1000);
  ok_(agentAddUser(&s_agent, "telemetry", V_MSG_B_AUTHKEY, V_MSG_B_PRIVKEY) == 0,
      "agent: add user telemetry");
}

// --- request building (uses oracle-verified USM primitives) ------------------

static const uint8_t kSalt1[8] = {0, 0, 0, 0, 0, 0, 0, 1};

static size_t makePdu(uint8_t* out, size_t cap, uint8_t tag, uint32_t reqId,
                      uint32_t status, uint32_t idx,
                      const uint32_t* oid, size_t oidLen,
                      const uint8_t* valueTlv, size_t valueLen) {
  BerVarbind vb;
  memset(&vb, 0, sizeof vb);
  memcpy(vb.name, oid, oidLen * sizeof vb.name[0]);
  vb.nameLen = oidLen;
  // A varbind must carry a value TLV; GET/GETNEXT requests use NULL.
  uint8_t nullTlv[4];
  if (valueTlv == NULL) {
    int nt = berEncodeNull(nullTlv, sizeof nullTlv);
    vb.valueTlv = nullTlv;
    vb.valueLen = (size_t)nt;
  } else {
    vb.valueTlv = valueTlv;
    vb.valueLen = valueLen;
  }
  return (size_t)berEncodePdu(out, cap, tag, reqId, status, idx, &vb, 1);
}

static size_t makeRequest(uint8_t* out, size_t cap,
                          uint32_t msgId, uint32_t maxMsg, uint8_t flags,
                          uint32_t boots, uint32_t time,
                          const char* user,
                          const uint8_t* pduTlv, size_t pduLen) {
  static uint8_t scoped[600], ct[620], sec[256];
  size_t secLen = 0;
  int r = berEncodeScopedPdu(scoped, sizeof scoped, V_M2_ENGID, V_M2_ENGID_LEN,
                             (const uint8_t*)"", 0, pduTlv, pduLen);
  if (r < 0) return 0;
  size_t scopedLen = (size_t)r;
  // msgData: plaintext scopedPDU unless the priv flag is set (then encrypt).
  const uint8_t* data = scoped;
  size_t dataLen = scopedLen;
  if (flags & 0x02) {
    uint8_t iv[SNMPV3_AES_IV];
    usmAesMakeIv(iv, boots, time, kSalt1);
    if (usmAesCfbEncrypt(V_MSG_B_PRIVKEY, iv, scoped, ct, scopedLen) < 0) return 0;
    data = ct;
  }

  static const uint8_t zeroAuth[SNMPV3_SHA256_MAC] = {0};
  r = usmBuildSecurityParams(sec, sizeof sec, V_M2_ENGID, V_M2_ENGID_LEN,
                             boots, time, (const uint8_t*)user, strlen(user),
                             zeroAuth, kSalt1, &secLen);
  if (r < 0) return 0;
  r = berEncodeV3Message(out, cap, msgId, maxMsg, flags, 3, sec, secLen,
                         data, dataLen);
  if (r < 0) return 0;
  size_t msgLen = (size_t)r;

  // MAC patch (zero authParams in place, HMAC, splice)
  uint8_t ver; uint32_t mid, msize; uint8_t fl, sm;
  size_t spo, spl, sdo, sdl;
  r = berDecodeV3Message(out, msgLen, &ver, &mid, &msize, &fl, &sm,
                         &spo, &spl, &sdo, &sdl);
  if (r < 0) return 0;
  // authParams offset: walk secParams
  size_t pos = 0; uint8_t tag; size_t len;
  if (berDecodeTlv(out + spo, spl, &pos, &tag, &len) < 0) return 0;
  size_t seqEnd = pos + len;
  for (int i = 0; i < 4; i++) {   // engineID, boots, time, userName
    if (berDecodeTlv(out + spo, seqEnd, &pos, &tag, &len) < 0) return 0;
    pos += len;
  }
  if (berDecodeTlv(out + spo, seqEnd, &pos, &tag, &len) < 0 || len != 24)
    return 0;
  size_t authAbs = spo + pos;
  memset(out + authAbs, 0, SNMPV3_SHA256_MAC);
  uint8_t digest[SNMPV3_SHA256_KEY];
  if (usmHmacSha256(V_MSG_B_AUTHKEY, SNMPV3_SHA256_KEY, out, msgLen, digest) < 0)
    return 0;
  memcpy(out + authAbs, digest, SNMPV3_SHA256_MAC);
  return msgLen;
}

// --- response inspection -----------------------------------------------------

// Decode a response datagram: verify MAC (if flagged), decrypt (if flagged),
// return PDU fields + plaintext scopedPDU region.
static int inspectResponse(const uint8_t* resp, size_t len,
                           uint8_t* pduTag, uint32_t* reqId,
                           uint32_t* status, uint32_t* idx,
                           BerVarbind* vbs, size_t maxVbs, size_t* nvbs,
                           uint8_t* plain, size_t* plainLen) {
  uint8_t ver; uint32_t mid, msize; uint8_t fl, sm;
  size_t spo, spl, sdo, sdl;
  int r = berDecodeV3Message(resp, len, &ver, &mid, &msize, &fl, &sm,
                             &spo, &spl, &sdo, &sdl);
  if (r < 0) return -1;

  // secParams walk for MAC offset + salt
  size_t pos = 0; uint8_t tag; size_t tl;
  if (berDecodeTlv(resp + spo, spl, &pos, &tag, &tl) < 0) return -1;
  size_t seqEnd = pos + tl;
  struct { size_t tagOff; size_t off; size_t len; } tlv[6];
  for (int i = 0; i < 6; i++) {
    tlv[i].tagOff = pos;                       // offset of the TLV tag
    if (berDecodeTlv(resp + spo, seqEnd, &pos, &tag, &tl) < 0) return -1;
    tlv[i].off = pos;                          // content offset
    tlv[i].len = tl;
    pos += tl;
  }
  // tlv: 0 engineID, 1 boots, 2 time, 3 user, 4 authParams, 5 privParams
  if (fl & 0x01) {
    uint8_t macCopy[1500];
    if (len > sizeof macCopy) return -1;
    memcpy(macCopy, resp, len);
    memset(macCopy + spo + tlv[4].off, 0, SNMPV3_SHA256_MAC);
    uint8_t digest[SNMPV3_SHA256_KEY];
    if (usmHmacSha256(V_MSG_B_AUTHKEY, SNMPV3_SHA256_KEY,
                      macCopy, len, digest) < 0) return -1;
    if (memcmp(digest, resp + spo + tlv[4].off, SNMPV3_SHA256_MAC) != 0)
      return -2;  // MAC mismatch
  }

  const uint8_t* body = resp + sdo;
  size_t bodyLen = sdl;
  if (fl & 0x02) {
    uint32_t boots = 0, time = 0;
    size_t p2 = 0;
    if (berDecodeInt32(resp + spo + tlv[1].tagOff, spl, &p2,
                       (int32_t*)&boots) < 0) return -1;
    p2 = 0;
    if (berDecodeInt32(resp + spo + tlv[2].tagOff, spl, &p2,
                       (int32_t*)&time) < 0) return -1;
    uint8_t iv[SNMPV3_AES_IV];
    usmAesMakeIv(iv, boots, time, resp + spo + tlv[5].off);
    if (usmAesCfbDecrypt(V_MSG_B_PRIVKEY, iv, body, plain, bodyLen) < 0)
      return -1;
  } else {
    if (bodyLen > 600) return -1;
    memcpy(plain, body, bodyLen);
  }
  *plainLen = bodyLen;

  // scopedPDU -> PDU; rebase value offsets to the full plaintext buffer so
  // callers can read value octets as plain[decValueOff].
  size_t pos2 = 0, ceo, cel, cno, cnl, po, pl;
  if (berDecodeScopedPdu(plain, *plainLen, &pos2, &ceo, &cel, &cno, &cnl,
                         &po, &pl) < 0) return -1;
  pos2 = 0;
  int rr = berDecodePdu(plain + po, pl, &pos2, pduTag, reqId, status, idx,
                        vbs, maxVbs, nvbs);
  if (rr < 0) return rr;
  for (size_t i = 0; i < *nvbs; i++) vbs[i].decValueOff += po;
  return rr;
}

static const uint32_t kSysNameOid[] = {1, 3, 6, 1, 2, 1, 1, 5, 0};
static const uint32_t kUptimeOid[]  = {1, 3, 6, 1, 2, 1, 1, 3, 0};
static const uint32_t kContactOid[] = {1, 3, 6, 1, 2, 1, 1, 4, 0};
static const uint32_t kStatsOid[6][12] = {
  {1,3,6,1,6,3,15,1,1,1,0}, {1,3,6,1,6,3,15,1,1,2,0},
  {1,3,6,1,6,3,15,1,1,3,0}, {1,3,6,1,6,3,15,1,1,4,0},
  {1,3,6,1,6,3,15,1,1,5,0}, {1,3,6,1,6,3,15,1,1,6,0},
};

static void test_report(const uint8_t* req, size_t reqLen, size_t statIdx,
                        uint32_t expectValue, const char* name) {
  size_t n = 0;
  int res = agentProcess(&s_agent, req, reqLen, V_M2_PROC_MS,
                         s_out, sizeof s_out, &n);
  ok_(res == AGENT_RESPONSE, name);
  if (res != AGENT_RESPONSE) return;
  uint8_t pduTag; uint32_t reqId, status, idx;
  BerVarbind vbs[2]; size_t nvbs = 0;
  uint8_t plain[600]; size_t plainLen = 0;
  ok_(inspectResponse(s_out, n, &pduTag, &reqId, &status, &idx,
                      vbs, 2, &nvbs, plain, &plainLen) == 0,
      "report parses");
  ok_(pduTag == BER_TAG_REPORT, "report is Report PDU");
  ok_(nvbs == 1, "report single varbind");
  ok_(vbs[0].nameLen == 11 &&
      memcmp(vbs[0].name, kStatsOid[statIdx], 11 * sizeof(uint32_t)) == 0,
      "report stats OID");
  ok_(vbs[0].decValueTag == BER_TAG_COUNTER32, "report value is Counter32");
  uint32_t v = 0;
  if (vbs[0].decValueLen == 4)
    v = ((uint32_t)plain[vbs[0].decValueOff] << 24) |
        ((uint32_t)plain[vbs[0].decValueOff + 1] << 16) |
        ((uint32_t)plain[vbs[0].decValueOff + 2] << 8) |
        (uint32_t)plain[vbs[0].decValueOff + 3];
  ok_(vbs[0].decValueLen == 4 && v == expectValue, "report counter value");
}

static void test_m2(void) {
  printf("== agent core (M2) ==\n");
  agent_setup();

  // 1) discovery: byte-exact Report
  {
    size_t n = 0;
    int res = agentProcess(&s_agent, V_REQ_DISCOVERY, sizeof V_REQ_DISCOVERY,
                           V_M2_PROC_MS, s_out, sizeof s_out, &n);
    ok_(res == AGENT_RESPONSE, "discovery: response");
    ok_(n == sizeof V_RESP_DISCOVERY &&
        memcmp(s_out, V_RESP_DISCOVERY, n) == 0,
        "discovery: byte-exact report");
  }

  // 2) authPriv GET: byte-exact response
  {
    size_t n = 0;
    int res = agentProcess(&s_agent, V_REQ_GET, sizeof V_REQ_GET,
                           V_M2_PROC_MS, s_out, sizeof s_out, &n);
    ok_(res == AGENT_RESPONSE, "GET: response");
    ok_(n == sizeof V_RESP_GET && memcmp(s_out, V_RESP_GET, n) == 0,
        "GET: byte-exact response");
  }

  // 3) replay: same msgId from the same user -> silence
  {
    size_t n = 123;
    int res = agentProcess(&s_agent, V_REQ_GET, sizeof V_REQ_GET,
                           V_M2_PROC_MS, s_out, sizeof s_out, &n);
    ok_(res == AGENT_NO_RESPONSE && n == 0, "replay: dropped silently");
  }

  // 4) tampered MAC -> usmStatsWrongDigests
  {
    uint8_t bad[600];
    memcpy(bad, V_REQ_GET, sizeof V_REQ_GET);
    bad[sizeof V_REQ_GET - 1] ^= 0xFF;
    test_report(bad, sizeof V_REQ_GET, 4, 1, "tamper: WrongDigests report");
  }

  // 5) stale engineTime -> usmStatsNotInTimeWindows
  test_report(V_REQ_STALE, sizeof V_REQ_STALE, 1, 1, "stale: NotInTimeWindows");

  // 6) unknown user -> usmStatsUnknownUserNames
  test_report(V_REQ_UNKNOWN_USER, sizeof V_REQ_UNKNOWN_USER, 2, 1,
              "unknown user: UnknownUserNames");

  // 7) SET sysName.0 = "hobbes"
  {
    size_t n = 0;
    int res = agentProcess(&s_agent, V_REQ_SET_NAME, sizeof V_REQ_SET_NAME,
                           V_M2_PROC_MS, s_out, sizeof s_out, &n);
    ok_(res == AGENT_RESPONSE, "SET: response");
    uint8_t pduTag; uint32_t reqId, status, idx;
    BerVarbind vbs[2]; size_t nvbs = 0;
    uint8_t plain[600]; size_t plainLen = 0;
    ok_(inspectResponse(s_out, n, &pduTag, &reqId, &status, &idx,
                        vbs, 2, &nvbs, plain, &plainLen) == 0, "SET: parses");
    ok_(pduTag == BER_TAG_RESPONSE && status == 0 && idx == 0, "SET: ok PDU");
    ok_(reqId == 45, "SET: request-id echoed");
    ok_(nvbs == 1 && vbs[0].nameLen == 9 &&
        memcmp(vbs[0].name, kSysNameOid, 9 * sizeof(uint32_t)) == 0,
        "SET: sysName varbind");
    ok_(vbs[0].decValueTag == BER_TAG_OCTET_STRING &&
        vbs[0].decValueLen == 6 &&
        memcmp(plain + vbs[0].decValueOff, "hobbes", 6) == 0,
        "SET: value echoed");
    // MIB state updated
    MibValue val;
    uint32_t nm[9];
    memcpy(nm, kSysNameOid, sizeof nm);
    ok_(mibGet(nm, 9, &val) == 1 && val.type == MIB_T_OCTETS &&
        val.octetsLen == 6 && memcmp(val.octets, "hobbes", 6) == 0,
        "SET: MIB state updated");
  }

  // 8) GETNEXT sysUpTime.0 -> sysContact.0
  {
    size_t n = 0;
    int res = agentProcess(&s_agent, V_REQ_NEXT, sizeof V_REQ_NEXT,
                           V_M2_PROC_MS, s_out, sizeof s_out, &n);
    ok_(res == AGENT_RESPONSE, "GETNEXT: response");
    uint8_t pduTag; uint32_t reqId, status, idx;
    BerVarbind vbs[2]; size_t nvbs = 0;
    uint8_t plain[600]; size_t plainLen = 0;
    ok_(inspectResponse(s_out, n, &pduTag, &reqId, &status, &idx,
                        vbs, 2, &nvbs, plain, &plainLen) == 0, "GETNEXT: parses");
    ok_(nvbs == 1 && vbs[0].nameLen == 9 &&
        memcmp(vbs[0].name, kContactOid, 9 * sizeof(uint32_t)) == 0,
        "GETNEXT: successor OID");
    ok_(vbs[0].decValueTag == BER_TAG_OCTET_STRING && vbs[0].decValueLen == 0,
        "GETNEXT: sysContact empty value");
  }

  // 9) C-built requests: exceptions, typed values, bulk, set errors
  {
    uint8_t pdu[200], req[700];
    size_t n = 0, pl = 0, rl = 0;
    int res = 0;

    // 9a) GET unknown subtree -> noSuchObject (0x81)
    const uint32_t kUnknown[] = {1, 3, 6, 1, 99};
    pl = makePdu(pdu, sizeof pdu, BER_TAG_GET_REQ, 50, 0, 0,
                        kUnknown, 5, NULL, 0);
    rl = makeRequest(req, sizeof req, 900, 65507, 0x07,
                            V_M2_BOOTS, V_M2_REQ_TIME, "telemetry", pdu, pl);
    ok_(rl > 0, "build unknown-GET request");
    res = agentProcess(&s_agent, req, rl, V_M2_PROC_MS, s_out, sizeof s_out, &n);
    ok_(res == AGENT_RESPONSE, "unknown-GET: response");
    {
      uint8_t pduTag; uint32_t reqId, status, idx;
      BerVarbind vbs[2]; size_t nvbs = 0;
      uint8_t plain[600]; size_t plainLen = 0;
      ok_(inspectResponse(s_out, n, &pduTag, &reqId, &status, &idx,
                          vbs, 2, &nvbs, plain, &plainLen) == 0, "unknown: parses");
      ok_(nvbs == 1 && vbs[0].decValueTag == BER_TAG_NOSUCHOBJECT,
          "unknown-GET: noSuchObject exception");
    }

    // 9b) GET under a known parent, missing instance -> noSuchInstance (0x82)
    const uint32_t kParent[] = {1, 3, 6, 1, 2, 1, 1, 1, 1};
    pl = makePdu(pdu, sizeof pdu, BER_TAG_GET_REQ, 51, 0, 0,
                 kParent, 9, NULL, 0);
    rl = makeRequest(req, sizeof req, 901, 65507, 0x07,
                     V_M2_BOOTS, V_M2_REQ_TIME, "telemetry", pdu, pl);
    res = agentProcess(&s_agent, req, rl, V_M2_PROC_MS, s_out, sizeof s_out, &n);
    {
      uint8_t pduTag; uint32_t reqId, status, idx;
      BerVarbind vbs[2]; size_t nvbs = 0;
      uint8_t plain[600]; size_t plainLen = 0;
      ok_(res == AGENT_RESPONSE && inspectResponse(s_out, n, &pduTag, &reqId,
          &status, &idx, vbs, 2, &nvbs, plain, &plainLen) == 0,
          "parent-GET: parses");
      ok_(nvbs == 1 && vbs[0].decValueTag == BER_TAG_NOSUCHINSTANCE,
          "parent-GET: noSuchInstance exception");
    }

    // 9c) typed values: sysUpTime.0 -> TimeTicks (0x43) 123456
    {
      pl = makePdu(pdu, sizeof pdu, BER_TAG_GET_REQ, 52, 0, 0,
                   kUptimeOid, 9, NULL, 0);
      rl = makeRequest(req, sizeof req, 902, 65507, 0x07,
                       V_M2_BOOTS, V_M2_REQ_TIME, "telemetry", pdu, pl);
      res = agentProcess(&s_agent, req, rl, V_M2_PROC_MS, s_out, sizeof s_out, &n);
      uint8_t pduTag; uint32_t reqId, status, idx;
      BerVarbind vbs[2]; size_t nvbs = 0;
      uint8_t plain[600]; size_t plainLen = 0;
      ok_(res == AGENT_RESPONSE && inspectResponse(s_out, n, &pduTag, &reqId,
          &status, &idx, vbs, 2, &nvbs, plain, &plainLen) == 0,
          "uptime-GET: parses");
      ok_(nvbs == 1 && vbs[0].decValueTag == BER_TAG_TIMETICKS,
          "uptime-GET: TimeTicks tag");
      uint32_t v = 0;
      if (vbs[0].decValueLen == 4)
        v = ((uint32_t)plain[vbs[0].decValueOff] << 24) |
            ((uint32_t)plain[vbs[0].decValueOff + 1] << 16) |
            ((uint32_t)plain[vbs[0].decValueOff + 2] << 8) |
            (uint32_t)plain[vbs[0].decValueOff + 3];
      ok_(vbs[0].decValueLen == 4 && v == 123456, "uptime-GET: value");
    }

    // 9d) GetBulk: 0 non-repeaters, 25 repetitions from sysDescr parent
    {
      const uint32_t kFrom[] = {1, 3, 6, 1, 2, 1, 1, 1};
      BerVarbind vb;
      memset(&vb, 0, sizeof vb);
      memcpy(vb.name, kFrom, sizeof kFrom);
      vb.nameLen = 8;
      // build a NULL value TLV for the request varbind
      uint8_t nullTlv[4];
      int nt = berEncodeNull(nullTlv, sizeof nullTlv);
      vb.valueTlv = nullTlv; vb.valueLen = (size_t)nt;
      size_t pl2 = (size_t)berEncodePdu(pdu, sizeof pdu, BER_TAG_GET_BULK,
                                        53, 0, 25, &vb, 1);
      size_t rl2 = makeRequest(req, sizeof req, 903, 65507, 0x07,
                               V_M2_BOOTS, V_M2_REQ_TIME, "telemetry", pdu, pl2);
      res = agentProcess(&s_agent, req, rl2, V_M2_PROC_MS, s_out, sizeof s_out, &n);
      uint8_t pduTag; uint32_t reqId, status, idx;
      BerVarbind vbs[32]; size_t nvbs = 0;
      uint8_t plain[600]; size_t plainLen = 0;
      ok_(res == AGENT_RESPONSE && inspectResponse(s_out, n, &pduTag, &reqId,
          &status, &idx, vbs, 32, &nvbs, plain, &plainLen) == 0,
          "bulk: parses");
      // The MIB holds the 17 system leaves plus the app scalars + table that
      // test_mib registered earlier (shared static registry), so the walk is
      // 17 sys + 3 app + 2 table rows + endOfMibView = 23 varbinds.
      ok_(nvbs == 23, "bulk: 22 leaves + endOfMibView");
      ok_(nvbs >= 1 && vbs[0].nameLen == 9 &&
          vbs[0].name[7] == 1 && vbs[0].name[8] == 0,
          "bulk: first is sysDescr.0");
      ok_(nvbs == 23 && vbs[22].decValueTag == BER_TAG_ENDOFMIBVIEW,
          "bulk: last is endOfMibView");
      // leaves appear in order: names monotonic (skip the trailing
      // endOfMibView varbind, which echoes the last leaf's name)
      int mono = 1;
      for (size_t i = 1; i + 1 < nvbs && mono; i++) {
        mono = mibArcCmp(vbs[i - 1].name, vbs[i - 1].nameLen,
                         vbs[i].name, vbs[i].nameLen) < 0;
      }
      ok_(mono, "bulk: monotonic order");
    }

    // 9e) SET read-only -> notWritable(17) + echoed varbind
    {
      const uint32_t kDesc[9] = {1, 3, 6, 1, 2, 1, 1, 1, 0};
      uint8_t valTlv[16];
      int vt = berEncodeOctetString(valTlv, sizeof valTlv,
                                    (const uint8_t*)"x", 1);
      BerVarbind vb;
      memset(&vb, 0, sizeof vb);
      memcpy(vb.name, kDesc, sizeof kDesc);
      vb.nameLen = 9;
      vb.valueTlv = valTlv; vb.valueLen = (size_t)vt;
      size_t pl2 = (size_t)berEncodePdu(pdu, sizeof pdu, BER_TAG_SET_REQ,
                                        54, 0, 0, &vb, 1);
      size_t rl2 = makeRequest(req, sizeof req, 904, 65507, 0x07,
                               V_M2_BOOTS, V_M2_REQ_TIME, "telemetry", pdu, pl2);
      res = agentProcess(&s_agent, req, rl2, V_M2_PROC_MS, s_out, sizeof s_out, &n);
      uint8_t pduTag; uint32_t reqId, status, idx;
      BerVarbind vbs[2]; size_t nvbs = 0;
      uint8_t plain[600]; size_t plainLen = 0;
      ok_(res == AGENT_RESPONSE && inspectResponse(s_out, n, &pduTag, &reqId,
          &status, &idx, vbs, 2, &nvbs, plain, &plainLen) == 0,
          "SET-RO: parses");
      ok_(status == 17 && idx == 1, "SET-RO: notWritable@1");
      ok_(nvbs == 1 && vbs[0].decValueTag == BER_TAG_OCTET_STRING,
          "SET-RO: request varbind echoed");
    }

    // 9f) SET wrong type -> wrongType(7)
    {
      const uint32_t kName[9] = {1, 3, 6, 1, 2, 1, 1, 5, 0};
      uint8_t valTlv[8];
      int vt = berEncodeInt32(valTlv, sizeof valTlv, 5);   // INTEGER, not OCTETS
      BerVarbind vb;
      memset(&vb, 0, sizeof vb);
      memcpy(vb.name, kName, sizeof kName);
      vb.nameLen = 9;
      vb.valueTlv = valTlv; vb.valueLen = (size_t)vt;
      size_t pl2 = (size_t)berEncodePdu(pdu, sizeof pdu, BER_TAG_SET_REQ,
                                        55, 0, 0, &vb, 1);
      size_t rl2 = makeRequest(req, sizeof req, 905, 65507, 0x07,
                               V_M2_BOOTS, V_M2_REQ_TIME, "telemetry", pdu, pl2);
      res = agentProcess(&s_agent, req, rl2, V_M2_PROC_MS, s_out, sizeof s_out, &n);
      uint8_t pduTag; uint32_t reqId, status, idx;
      BerVarbind vbs[2]; size_t nvbs = 0;
      uint8_t plain[600]; size_t plainLen = 0;
      ok_(res == AGENT_RESPONSE && inspectResponse(s_out, n, &pduTag, &reqId,
          &status, &idx, vbs, 2, &nvbs, plain, &plainLen) == 0,
          "SET-type: parses");
      ok_(status == 7 && idx == 1, "SET-type: wrongType@1");
    }

    // 9g) SET unknown OID -> notWritable(17)
    {
      const uint32_t kNo[] = {1, 3, 6, 1, 4, 1, 67018, 42, 0};
      uint8_t valTlv[8];
      int vt = berEncodeInt32(valTlv, sizeof valTlv, 1);
      BerVarbind vb;
      memset(&vb, 0, sizeof vb);
      memcpy(vb.name, kNo, sizeof kNo);
      vb.nameLen = 9;
      vb.valueTlv = valTlv; vb.valueLen = (size_t)vt;
      size_t pl2 = (size_t)berEncodePdu(pdu, sizeof pdu, BER_TAG_SET_REQ,
                                        56, 0, 0, &vb, 1);
      size_t rl2 = makeRequest(req, sizeof req, 906, 65507, 0x07,
                               V_M2_BOOTS, V_M2_REQ_TIME, "telemetry", pdu, pl2);
      res = agentProcess(&s_agent, req, rl2, V_M2_PROC_MS, s_out, sizeof s_out, &n);
      uint8_t pduTag; uint32_t reqId, status, idx;
      BerVarbind vbs[2]; size_t nvbs = 0;
      uint8_t plain[600]; size_t plainLen = 0;
      ok_(res == AGENT_RESPONSE && inspectResponse(s_out, n, &pduTag, &reqId,
          &status, &idx, vbs, 2, &nvbs, plain, &plainLen) == 0,
          "SET-noobj: parses");
      ok_(status == 17 && idx == 1, "SET-noobj: notWritable@1");
    }

    // 9h) tooBig: two-varbind GET with a small msgMaxSize
    {
      const uint32_t kDesc[9] = {1, 3, 6, 1, 2, 1, 1, 1, 0};
      const uint32_t kName[9] = {1, 3, 6, 1, 2, 1, 1, 5, 0};
      BerVarbind vbs2[2];
      memset(vbs2, 0, sizeof vbs2);
      uint8_t nullTlv[4];
      int nt = berEncodeNull(nullTlv, sizeof nullTlv);
      for (int i = 0; i < 2; i++) {
        const uint32_t* src = i == 0 ? kDesc : kName;
        memcpy(vbs2[i].name, src, 9 * sizeof(uint32_t));
        vbs2[i].nameLen = 9;
        vbs2[i].valueTlv = nullTlv;
        vbs2[i].valueLen = (size_t)nt;
      }
      size_t pl2 = (size_t)berEncodePdu(pdu, sizeof pdu, BER_TAG_GET_REQ,
                                        57, 0, 0, vbs2, 2);
      size_t rl2 = makeRequest(req, sizeof req, 907, 150 /* small */, 0x07,
                               V_M2_BOOTS, V_M2_REQ_TIME, "telemetry", pdu, pl2);
      res = agentProcess(&s_agent, req, rl2, V_M2_PROC_MS, s_out, sizeof s_out, &n);
      ok_(res == AGENT_RESPONSE, "tooBig: response");
      uint8_t pduTag; uint32_t reqId, status, idx;
      BerVarbind vbs[2]; size_t nvbs = 0;
      uint8_t plain[600]; size_t plainLen = 0;
      ok_(inspectResponse(s_out, n, &pduTag, &reqId, &status, &idx,
                          vbs, 2, &nvbs, plain, &plainLen) == 0, "tooBig: parses");
      ok_(status == 1 && idx == 0 && nvbs == 0, "tooBig: status=1, no varbinds");
    }
  }

  // 10) response to a noAuth request from a KNOWN user -> UnsupportedSecLevels
  //     (build a genuinely noAuth request: plaintext scopedPDU, flags 0x04)
  {
    uint8_t pdu[200], req[700];
    const uint32_t kDesc[9] = {1, 3, 6, 1, 2, 1, 1, 1, 0};
    size_t pl = makePdu(pdu, sizeof pdu, BER_TAG_GET_REQ, 58, 0, 0,
                        kDesc, 9, NULL, 0);
    size_t rl = makeRequest(req, sizeof req, 908, 65507, 0x04,
                            V_M2_BOOTS, V_M2_REQ_TIME, "telemetry", pdu, pl);
    size_t n = 0;
    int res = agentProcess(&s_agent, req, rl, V_M2_PROC_MS,
                           s_out, sizeof s_out, &n);
    ok_(res == AGENT_RESPONSE, "noAuth-known-user: report");
    uint8_t pduTag; uint32_t reqId2, status, idx;
    BerVarbind vbs[2]; size_t nvbs = 0;
    uint8_t plain[600]; size_t plainLen = 0;
    // report is unencrypted plaintext; inspectResponse handles flags 0x04
    ok_(inspectResponse(s_out, n, &pduTag, &reqId2, &status, &idx,
                        vbs, 2, &nvbs, plain, &plainLen) == 0, "noAuth: parses");
    ok_(nvbs == 1 && vbs[0].nameLen == 11 &&
        memcmp(vbs[0].name, kStatsOid[0], 11 * sizeof(uint32_t)) == 0,
        "noAuth: UnsupportedSecLevels report");
    ok_(reqId2 == 58, "noAuth: request-id echoed (plaintext body readable)");
  }

  printf("  %d checks, %d failures\n", checks, fails);
}

int test_agent(void) {
  test_m2();
  return fails;
}