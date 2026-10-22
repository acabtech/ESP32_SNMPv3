// test_notify.c — v3 notification tests (src/agent/AgentCore.c, M3):
// trap/inform message construction (authPriv, MAC + CFB), the inform retry
// state machine, and acknowledgement matching against a manager Response.
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

// Standard notification varbind OIDs.
static const uint32_t kSysUpTimeOid[]   = {1, 3, 6, 1, 2, 1, 1, 3, 0};
static const uint32_t kSnmpTrapOidOid[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
static const uint32_t kSysNameOid[]     = {1, 3, 6, 1, 2, 1, 1, 5, 0};

static const uint8_t kSalt1[8] = {0, 0, 0, 0, 0, 0, 0, 1};

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
  mibSetSystemText(NULL, NULL, NULL, NULL);
  mibRegisterSystem();

  agentInit(&s_agent, V_M2_ENGID, V_M2_ENGID_LEN, V_M2_BOOTS,
            V_M2_INIT_MS, 1500);
  s_agent.saltCounter = ((uint64_t)V_M2_BOOTS << 32) | (V_M2_INIT_MS / 1000);
  ok_(agentAddUser(&s_agent, "telemetry", V_MSG_B_AUTHKEY, V_MSG_B_PRIVKEY) == 0,
      "notify: add user telemetry");
}

// --- notification inspection ------------------------------------------------

// Decode a notification datagram: verify MAC, decrypt, return PDU fields +
// plaintext scopedPDU region. Mirrors test_agent.c's inspectResponse.
static int inspectNotification(const uint8_t* msg, size_t len,
                               uint8_t* pduTag, uint32_t* reqId,
                               uint8_t* flagsOut,
                               BerVarbind* vbs, size_t maxVbs, size_t* nvbs,
                               uint8_t* plain, size_t* plainLen) {
  uint8_t ver; uint32_t mid, msize; uint8_t fl, sm;
  size_t spo, spl, sdo, sdl;
  int r = berDecodeV3Message(msg, len, &ver, &mid, &msize, &fl, &sm,
                             &spo, &spl, &sdo, &sdl);
  if (r < 0) return -1;
  *flagsOut = fl;

  size_t pos = 0; uint8_t tag; size_t tl;
  if (berDecodeTlv(msg + spo, spl, &pos, &tag, &tl) < 0) return -1;
  size_t seqEnd = pos + tl;
  struct { size_t tagOff; size_t off; size_t len; } tlv[6];
  for (int i = 0; i < 6; i++) {
    tlv[i].tagOff = pos;
    if (berDecodeTlv(msg + spo, seqEnd, &pos, &tag, &tl) < 0) return -1;
    tlv[i].off = pos;
    tlv[i].len = tl;
    pos += tl;
  }
  // tlv: 0 engineID, 1 boots, 2 time, 3 user, 4 authParams, 5 privParams
  if (fl & 0x01) {
    uint8_t macCopy[1500];
    if (len > sizeof macCopy) return -1;
    memcpy(macCopy, msg, len);
    memset(macCopy + spo + tlv[4].off, 0, SNMPV3_SHA256_MAC);
    uint8_t digest[SNMPV3_SHA256_KEY];
    if (usmHmacSha256(V_MSG_B_AUTHKEY, SNMPV3_SHA256_KEY,
                      macCopy, len, digest) < 0) return -1;
    if (memcmp(digest, msg + spo + tlv[4].off, SNMPV3_SHA256_MAC) != 0)
      return -2;  // MAC mismatch
  }

  const uint8_t* body = msg + sdo;
  size_t bodyLen = sdl;
  if (fl & 0x02) {
    uint32_t boots = 0, time = 0;
    size_t p2 = 0;
    if (berDecodeInt32(msg + spo + tlv[1].tagOff, spl, &p2,
                       (int32_t*)&boots) < 0) return -1;
    p2 = 0;
    if (berDecodeInt32(msg + spo + tlv[2].tagOff, spl, &p2,
                       (int32_t*)&time) < 0) return -1;
    uint8_t iv[SNMPV3_AES_IV];
    usmAesMakeIv(iv, boots, time, msg + spo + tlv[5].off);
    if (usmAesCfbDecrypt(V_MSG_B_PRIVKEY, iv, body, plain, bodyLen) < 0)
      return -1;
  } else {
    if (bodyLen > 600) return -1;
    memcpy(plain, body, bodyLen);
  }
  *plainLen = bodyLen;

  size_t pos2 = 0, ceo, cel, cno, cnl, po, pl;
  if (berDecodeScopedPdu(plain, *plainLen, &pos2, &ceo, &cel, &cno, &cnl,
                         &po, &pl) < 0) return -1;
  pos2 = 0;
  int rr = berDecodePdu(plain + po, pl, &pos2, pduTag, reqId, &(uint32_t){0},
                        &(uint32_t){0}, vbs, maxVbs, nvbs);
  if (rr < 0) return rr;
  for (size_t i = 0; i < *nvbs; i++) vbs[i].decValueOff += po;
  return rr;
}

// --- manager Response builder (for the inform ack test) ---------------------

// Build an authPriv v3 Response PDU from the manager back to the agent, with
// the agent's engineID/boots/time and the user's keys (the agent is the
// authoritative engine for a notification it sent).
static size_t makeManagerResponse(uint8_t* out, size_t cap,
                                  uint32_t msgId, uint32_t reqId,
                                  uint32_t boots, uint32_t time) {
  uint8_t pdu[64];
  int pl = berEncodePdu(pdu, sizeof pdu, BER_TAG_RESPONSE, reqId, 0, 0,
                        NULL, 0);
  if (pl < 0) return 0;
  static uint8_t scoped[128], ct[160], sec[256];
  int r = berEncodeScopedPdu(scoped, sizeof scoped, V_M2_ENGID, V_M2_ENGID_LEN,
                             (const uint8_t*)"", 0, pdu, (size_t)pl);
  if (r < 0) return 0;
  size_t scopedLen = (size_t)r;
  uint8_t iv[SNMPV3_AES_IV];
  usmAesMakeIv(iv, boots, time, kSalt1);
  if (usmAesCfbEncrypt(V_MSG_B_PRIVKEY, iv, scoped, ct, scopedLen) < 0)
    return 0;
  static const uint8_t zeroAuth[SNMPV3_SHA256_MAC] = {0};
  size_t secLen = 0;
  r = usmBuildSecurityParams(sec, sizeof sec, V_M2_ENGID, V_M2_ENGID_LEN,
                             boots, time, (const uint8_t*)"telemetry", 9,
                             zeroAuth, kSalt1, &secLen);
  if (r < 0) return 0;
  r = berEncodeV3Message(out, cap, msgId, 65507, 0x07, 3, sec, secLen,
                         ct, scopedLen);
  if (r < 0) return 0;
  size_t msgLen = (size_t)r;

  uint8_t ver; uint32_t mid, msize; uint8_t fl, sm;
  size_t spo, spl, sdo, sdl;
  if (berDecodeV3Message(out, msgLen, &ver, &mid, &msize, &fl, &sm,
                         &spo, &spl, &sdo, &sdl) < 0) return 0;
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

// --- tests ------------------------------------------------------------------

static void test_trap(void) {
  printf("== notifications: trap (M3) ==\n");
  uint8_t msg[AGENT_MAX_MSG + 64];
  size_t msgLen = 0;
  int r = agentBuildNotification(&s_agent, &s_agent.users[0], BER_TAG_TRAP_V2,
                                 0x11223344u, 0x11223344u,
                                 kSysNameOid, 9, 123456, V_M2_PROC_MS,
                                 msg, sizeof msg, &msgLen);
  ok_(r == 0 && msgLen > 0, "trap: built");

  uint8_t pduTag, flags; uint32_t reqId;
  BerVarbind vbs[4]; size_t nvbs = 0;
  uint8_t plain[600]; size_t plainLen = 0;
  ok_(inspectNotification(msg, msgLen, &pduTag, &reqId, &flags,
                          vbs, 4, &nvbs, plain, &plainLen) == 0,
      "trap: parses + MAC verifies");
  ok_(flags == 0x03, "trap: flags authPriv, not reportable");
  ok_(pduTag == BER_TAG_TRAP_V2, "trap: Trap PDU tag");
  ok_(reqId == 0x11223344u, "trap: request-id");
  ok_(nvbs == 3, "trap: 3 varbinds");

  // varbind 0: sysUpTime.0 = TimeTicks(123456)
  ok_(vbs[0].nameLen == 9 &&
      memcmp(vbs[0].name, kSysUpTimeOid, 9 * sizeof(uint32_t)) == 0,
      "trap: varbind0 sysUpTime.0");
  ok_(vbs[0].decValueTag == BER_TAG_TIMETICKS && vbs[0].decValueLen == 4,
      "trap: varbind0 TimeTicks");
  {
    uint32_t v = ((uint32_t)plain[vbs[0].decValueOff] << 24) |
                 ((uint32_t)plain[vbs[0].decValueOff + 1] << 16) |
                 ((uint32_t)plain[vbs[0].decValueOff + 2] << 8) |
                 (uint32_t)plain[vbs[0].decValueOff + 3];
    ok_(v == 123456, "trap: varbind0 uptime value");
  }

  // varbind 1: snmpTrapOID.0 = OID(sysName.0)
  ok_(vbs[1].nameLen == 11 &&
      memcmp(vbs[1].name, kSnmpTrapOidOid, 11 * sizeof(uint32_t)) == 0,
      "trap: varbind1 snmpTrapOID.0");
  ok_(vbs[1].decValueTag == BER_TAG_OID, "trap: varbind1 OID value");
  {
    uint32_t arcs[BER_OID_MAX_ARCS]; size_t n = BER_OID_MAX_ARCS;
    size_t p = 0;
    // decode the OID value from the plaintext buffer
    uint8_t oidTlv[64];
    int ot = berEncodeTlv(oidTlv, sizeof oidTlv, vbs[1].decValueTag,
                          plain + vbs[1].decValueOff, vbs[1].decValueLen);
    ok_(ot > 0, "trap: varbind1 OID TLV");
    p = 0;
    ok_(berDecodeOid(oidTlv, (size_t)ot, &p, arcs, &n) >= 0 &&
        n == 9 && memcmp(arcs, kSysNameOid, 9 * sizeof(uint32_t)) == 0,
        "trap: varbind1 OID == trap OID");
  }

  // varbind 2: sysName.0 = current value (OCTET STRING)
  ok_(vbs[2].nameLen == 9 &&
      memcmp(vbs[2].name, kSysNameOid, 9 * sizeof(uint32_t)) == 0,
      "trap: varbind2 payload OID");
  ok_(vbs[2].decValueTag == BER_TAG_OCTET_STRING,
      "trap: varbind2 OCTET STRING value");
}

static void test_inform(void) {
  printf("== notifications: inform (M3) ==\n");
  uint8_t msg[AGENT_MAX_MSG + 64];
  size_t msgLen = 0;
  int r = agentBuildNotification(&s_agent, &s_agent.users[0],
                                 BER_TAG_INFORM_REQ, 0x55667788u, 0x55667788u,
                                 kSysNameOid, 9, 123456, V_M2_PROC_MS,
                                 msg, sizeof msg, &msgLen);
  ok_(r == 0 && msgLen > 0, "inform: built");

  uint8_t pduTag, flags; uint32_t reqId;
  BerVarbind vbs[4]; size_t nvbs = 0;
  uint8_t plain[600]; size_t plainLen = 0;
  ok_(inspectNotification(msg, msgLen, &pduTag, &reqId, &flags,
                          vbs, 4, &nvbs, plain, &plainLen) == 0,
      "inform: parses + MAC verifies");
  ok_(flags == 0x07, "inform: flags authPriv + reportable");
  ok_(pduTag == BER_TAG_INFORM_REQ, "inform: InformRequest PDU tag");
  ok_(reqId == 0x55667788u, "inform: request-id");
  ok_(nvbs == 3, "inform: 3 varbinds");
}

static void test_inform_state_machine(void) {
  printf("== notifications: inform retry state machine (M3) ==\n");
  uint8_t msg[16] = {0};
  AgentInform inf;
  agentInformStart(&inf, msg, sizeof msg, 7, 7, 0);
  ok_(inf.active && inf.attempts == 1, "inform-sm: armed, 1 attempt");

  ok_(agentInformTick(&inf, 100) == 0, "inform-sm: waiting at 100 ms");
  ok_(agentInformTick(&inf, AGENT_INFORM_ATTEMPT_MS) == 1 &&
      inf.attempts == 2, "inform-sm: retry 1 at 1250 ms");
  ok_(agentInformTick(&inf, 2 * AGENT_INFORM_ATTEMPT_MS) == 1 &&
      inf.attempts == 3, "inform-sm: retry 2 at 2500 ms");
  ok_(agentInformTick(&inf, 3 * AGENT_INFORM_ATTEMPT_MS) == 1 &&
      inf.attempts == 4, "inform-sm: retry 3 at 3750 ms");
  ok_(agentInformTick(&inf, AGENT_INFORM_TOTAL_MS) == -1 && !inf.active,
      "inform-sm: give up at 5000 ms");
  ok_(agentInformTick(&inf, 6000) == -1, "inform-sm: stays inactive");
}

static void test_inform_ack(void) {
  printf("== notifications: inform acknowledgement (M3) ==\n");
  uint8_t msg[AGENT_MAX_MSG + 64];
  size_t msgLen = 0;
  uint32_t reqId = 0x0BADF00Du;
  int r = agentBuildNotification(&s_agent, &s_agent.users[0],
                                 BER_TAG_INFORM_REQ, 0x0BADF00Du, reqId,
                                 kSysNameOid, 9, 123456, V_M2_PROC_MS,
                                 msg, sizeof msg, &msgLen);
  ok_(r == 0 && msgLen > 0, "inform-ack: built");

  AgentInform inf;
  agentInformStart(&inf, msg, msgLen, 0x0BADF00Du, reqId, V_M2_PROC_MS);

  // matching Response -> acknowledged
  uint8_t resp[AGENT_MAX_MSG + 64];
  size_t respLen = makeManagerResponse(resp, sizeof resp, 0x99u, reqId,
                                       s_agent.clock.boots, s_agent.clock.time);
  ok_(respLen > 0, "inform-ack: manager response built");
  ok_(agentInformAck(&inf, &s_agent, &s_agent.users[0], resp, respLen) == 1,
      "inform-ack: matching response acknowledged");
  ok_(!inf.active, "inform-ack: state machine cleared");

  // wrong request-id -> not acknowledged
  agentInformStart(&inf, msg, msgLen, 0x0BADF00Du, reqId, V_M2_PROC_MS);
  respLen = makeManagerResponse(resp, sizeof resp, 0x99u, reqId + 1,
                                s_agent.clock.boots, s_agent.clock.time);
  ok_(respLen > 0, "inform-ack: mismatched response built");
  ok_(agentInformAck(&inf, &s_agent, &s_agent.users[0], resp, respLen) == 0,
      "inform-ack: wrong request-id rejected");
  ok_(inf.active, "inform-ack: still pending after mismatch");

  // tampered MAC -> not acknowledged
  agentInformStart(&inf, msg, msgLen, 0x0BADF00Du, reqId, V_M2_PROC_MS);
  respLen = makeManagerResponse(resp, sizeof resp, 0x99u, reqId,
                                s_agent.clock.boots, s_agent.clock.time);
  resp[respLen - 1] ^= 0xFF;
  ok_(agentInformAck(&inf, &s_agent, &s_agent.users[0], resp, respLen) == 0,
      "inform-ack: tampered MAC rejected");
}

int test_notify(void) {
  agent_setup();
  test_trap();
  test_inform();
  test_inform_state_machine();
  test_inform_ack();
  printf("  %d checks, %d failures\n", checks, fails);
  return fails;
}
