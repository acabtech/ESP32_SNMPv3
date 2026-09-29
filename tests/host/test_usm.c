// test_usm.c — USM layer tests (src/usm/USM.c) with generated vectors.
//
// Covers: SHA-256 key localization (pysnmp oracle), HMAC-SHA-256 with the
// RFC 7860 24-octet MAC, AES-128-CFB with the RFC 3826 IV construction,
// msgFlags, securityParameters serialization (byte-compared against the
// discovery wire sample), timeliness window, and a full authPriv message:
// decrypt + MAC verify.
//
// SPDX-License-Identifier: GPL-3.0
#include <stdio.h>
#include <string.h>
#include "USM.h"
#include "BER.h"
#include "crypto.h"
#include "vectors.h"

static int fails = 0;
static int checks = 0;

static void ok_(int cond, const char* what) {
  checks++;
  if (!cond) { fails++; printf("  FAIL: %s\n", what); }
}

// ---------------------------------------------------------------------------
static void test_localize(void) {
  for (int i = 0; i < N_AUTHKEY; i++) {
    const AuthKeyVec* v = &VEC_AUTHKEY[i];
    uint8_t ku[32];
    int r = usmKeyLocalize(v->pass, v->passLen, v->engineId, v->engineIdLen, ku);
    ok_(r == USM_ERR_OK, "localize rc");
    ok_(memcmp(ku, v->ku, 32) == 0, "localized key == pysnmp oracle");
  }
  // empty passphrase rejected
  uint8_t ku[32];
  ok_(usmKeyLocalize(NULL, 0, NULL, 0, ku) != USM_ERR_OK, "empty passphrase rejected");
}

static void test_hmac(void) {
  for (int i = 0; i < N_HMAC; i++) {
    const HmacVec* v = &VEC_HMAC[i];
    uint8_t out[32];
    int r = usmHmacSha256(v->key, v->keyLen, v->msg, v->msgLen, out);
    ok_(r == USM_ERR_OK, "hmac rc");
    ok_(memcmp(out, v->mac, 24) == 0, "HMAC-SHA-256 truncated-24 == oracle");
    // out must equal oracle.full for the first 24 and the full digest check:
    // (the oracle stores the first 24 octets; assert the digest starts with them)
    (void)out;
  }
}

static void test_cfb(void) {
  for (int i = 0; i < N_CFB; i++) {
    const CfbVec* v = &VEC_CFB[i];
    uint8_t iv[16], out[128], back[128];
    usmAesMakeIv(iv, v->boots, v->time, v->salt);
    int r = usmAesCfbEncrypt(v->key, iv, v->pt, out, v->ptLen);
    ok_(r == USM_ERR_OK, "cfb encrypt rc");
    ok_(memcmp(out, v->ct, v->ptLen) == 0, "AES-128-CFB ciphertext == oracle");

    // decrypt: fresh IV
    usmAesMakeIv(iv, v->boots, v->time, v->salt);
    usmAesCfbDecrypt(v->key, iv, v->ct, back, v->ptLen);
    ok_(memcmp(back, v->pt, v->ptLen) == 0, "AES-128-CFB decrypt == plaintext");
  }
  // chained segment encryption (feedback carried across calls) must match
  // one-shot for a 40-byte plaintext split as 16+16+8
  {
    const CfbVec* v = &VEC_CFB[1];
    uint8_t iv[16], a[128], b[128];
    usmAesMakeIv(iv, v->boots, v->time, v->salt);
    usmAesCfbEncrypt(v->key, iv, v->pt, a, v->ptLen);          // one shot
    usmAesMakeIv(iv, v->boots, v->time, v->salt);
    size_t h = (v->ptLen > 16 ? 16 : v->ptLen);
    size_t h2 = (v->ptLen > 32 ? 16 : (v->ptLen > h ? v->ptLen - h : 0));
    (void)h2;
    usmAesCfbEncrypt(v->key, iv, v->pt, b, h);
    usmAesCfbEncrypt(v->key, iv, v->pt + h, b + h, v->ptLen - h);
    ok_(memcmp(a, b, v->ptLen) == 0, "AES-128-CFB chained == one-shot");
  }
}

static void test_flags(void) {
  ok_(usmMsgFlags(false, false) == 0x00, "flags none");
  ok_(usmMsgFlags(true, false) == 0x01, "flags auth");
  ok_(usmMsgFlags(false, true) == 0x02, "flags priv");
  ok_(usmMsgFlags(true, true) == 0x03, "flags auth+priv");
}

static void test_security_params(void) {
  // Rebuild the securityParameters of wire sample A and compare bytes.
  // secParams region of MSG_A == SEQUENCE { engineID, boots 1234, time 5678,
  // "", 24 zero octets, 8 zero octets }
  size_t spo = 0, spl = 0;
  size_t sdo = 0, sdl = 0;
  uint8_t ver = 0; uint32_t mid = 0, msize = 0; uint8_t fl = 0, sm = 0;
  int r = berDecodeV3Message(V_MSG_A, sizeof V_MSG_A, &ver, &mid, &msize,
                             &fl, &sm, &spo, &spl, &sdo, &sdl);
  ok_(r == BER_OK, "MSG_A decode for secParams");

  uint8_t eid[] = {0x80, 0x00, 0x1f, 0x88, 0x80, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
  uint8_t zero24[24] = {0}, zero8[8] = {0};
  uint8_t sp[256]; size_t spLen = 0;
  r = usmBuildSecurityParams(sp, sizeof sp, eid, sizeof eid, 1234, 5678,
                             NULL, 0, zero24, zero8, &spLen);
  ok_(r == USM_ERR_OK, "securityParams rc");
  ok_(spLen == spl && memcmp(sp, V_MSG_A + spo, spl) == 0,
      "securityParams == sample A bytes");

  // parse it back (test-local USM SEQUENCE parser)
  size_t pos = 0; uint8_t tag; size_t len;
  r = berDecodeTlv(sp, spLen, &pos, &tag, &len);
  ok_(r == BER_OK && tag == BER_TAG_SEQUENCE, "secParams wrapper SEQUENCE");
  size_t end = pos + len;
  // engineID
  r = berDecodeTlv(sp, end, &pos, &tag, &len);
  ok_(r == BER_OK && tag == BER_TAG_OCTET_STRING && len == sizeof eid, "sp engineID");
  pos += len;
  int32_t boots, time;
  r = berDecodeInt32(sp, end, &pos, &boots);
  ok_(r == BER_OK && boots == 1234, "sp boots");
  r = berDecodeInt32(sp, end, &pos, &time);
  ok_(r == BER_OK && time == 5678, "sp time");
  r = berDecodeTlv(sp, end, &pos, &tag, &len);
  ok_(r == BER_OK && tag == BER_TAG_OCTET_STRING && len == 0, "sp user empty");
  pos += len;
  r = berDecodeTlv(sp, end, &pos, &tag, &len);
  ok_(r == BER_OK && len == SNMPV3_SHA256_MAC, "sp authParams len24");
  pos += len;
  r = berDecodeTlv(sp, end, &pos, &tag, &len);
  ok_(r == BER_OK && len == SNMPV3_PRIV_SALT, "sp privParams len8");
}

static void test_timeliness(void) {
  UsmEngineClock clk = {1234, 1000, 1000000};  // boots, time, ms anchor
  // remote at same boots, within 150 s around now
  uint32_t now = usmTimeNow(&clk, 1005000);    // time + 5 s
  ok_(usmTimelinessCheck(&clk, 1234, now, 1005000) == USM_ERR_OK, "in-window accept");
  ok_(usmTimelinessCheck(&clk, 1234, now - 150, 1005000) == USM_ERR_OK, "edge -150 accept");
  ok_(usmTimelinessCheck(&clk, 1234, now + 150, 1005000) == USM_ERR_OK, "edge +150 accept");
  ok_(usmTimelinessCheck(&clk, 1234, now - 151, 1005000) == USM_ERR_NOT_IN_TIME, "edge -151 reject");
  ok_(usmTimelinessCheck(&clk, 1234, now + 151, 1005000) == USM_ERR_NOT_IN_TIME, "edge +151 reject");
  ok_(usmTimelinessCheck(&clk, 9999, now, 1005000) == USM_ERR_NOT_IN_TIME, "boots mismatch reject");
  // time now advances with ms
  ok_(usmTimeNow(&clk, 2000000) == 1000 + 1000, "usmTimeNow second boundary");
}

static void test_msg_b_full(void) {
  // Full authPriv message: parse, MAC-verify, decrypt, dispatch-parse.
  uint8_t ver = 0; uint32_t mid = 0, msize = 0; uint8_t fl = 0, sm = 0;
  size_t spo, spl, sdo, sdl;
  int r = berDecodeV3Message(V_MSG_B, sizeof V_MSG_B, &ver, &mid, &msize,
                             &fl, &sm, &spo, &spl, &sdo, &sdl);
  ok_(r == BER_OK, "MSG_B decode");

  // --- parse USM securityParameters ---
  size_t pos = 0; uint8_t tag; size_t len;
  r = berDecodeTlv(V_MSG_B + spo, spl, &pos, &tag, &len);   // SEQUENCE
  ok_(r == BER_OK && tag == BER_TAG_SEQUENCE, "MSG_B secParams SEQUENCE");
  size_t end = pos + len;
  size_t engLen = 0, userLen = 0;
  r = berDecodeTlv(V_MSG_B + spo, end, &pos, &tag, &len); engLen = len; pos += len;
  ok_(r == BER_OK && tag == BER_TAG_OCTET_STRING, "MSG_B engineID octet");
  int32_t boots = 0, time = 0;
  r = berDecodeInt32(V_MSG_B + spo, end, &pos, &boots); ok_(r == BER_OK, "MSG_B boots");
  r = berDecodeInt32(V_MSG_B + spo, end, &pos, &time);  ok_(r == BER_OK, "MSG_B time");
  r = berDecodeTlv(V_MSG_B + spo, end, &pos, &tag, &len); userLen = len; pos += len;
  ok_(r == BER_OK && tag == BER_TAG_OCTET_STRING && userLen == 9, "MSG_B user telemetry");
  (void)engLen; (void)userLen;

  // authParams: must equal MAC computed over zeroed placeholder
  r = berDecodeTlv(V_MSG_B + spo, end, &pos, &tag, &len);
  ok_(r == BER_OK && len == SNMPV3_SHA256_MAC, "MSG_B authParams len");
  size_t authOff = pos;   // relative to the secParams region (V_MSG_B + spo)
  uint8_t mac[32];
  memcpy(mac, V_MSG_B + spo + authOff, SNMPV3_SHA256_MAC);
  pos += len;             // skip the authParams content

  uint8_t zeroed[512];
  size_t z = 0;
  if (sizeof zeroed < sizeof V_MSG_B) ok_(0, "buffer for zeroed msg");
  for (size_t i = 0; i < sizeof V_MSG_B; i++) {
    if (i >= spo + authOff && i < spo + authOff + SNMPV3_SHA256_MAC)
      zeroed[z++] = 0;
    else
      zeroed[z++] = V_MSG_B[i];
  }
  uint8_t check[32];
  usmHmacSha256(V_MSG_B_AUTHKEY, 32, zeroed, z, check);
  ok_(memcmp(check, mac, SNMPV3_SHA256_MAC) == 0, "MSG_B MAC verifies (RFC 7860)");

  // privParams = salt
  r = berDecodeTlv(V_MSG_B + spo, end, &pos, &tag, &len);
  ok_(r == BER_OK && len == SNMPV3_PRIV_SALT, "MSG_B privParams salt len");
  size_t saltOff = pos;

  // --- decrypt scopedPDU and validate plaintext ---
  uint8_t iv[16], plain[256];
  usmAesMakeIv(iv, (uint32_t)boots, (uint32_t)time, V_MSG_B + spo + saltOff);
  usmAesCfbDecrypt(V_MSG_B_PRIVKEY, iv, V_MSG_B + sdo, plain, sdl);
  ok_(sdl == sizeof V_MSG_B_PLAIN && memcmp(plain, V_MSG_B_PLAIN, sdl) == 0,
      "MSG_B scopedPDU decrypts to oracle plaintext");

  // --- dispatch-parse the decrypted scopedPDU ---
  size_t ppos = 0, eo, el, no, nl, po, pl;
  r = berDecodeScopedPdu(plain, sdl, &ppos, &eo, &el, &no, &nl, &po, &pl);
  ok_(r == BER_OK, "MSG_B scopedPDU decode");
  size_t pos2 = po; uint8_t pduTag; uint32_t rid = 0, st = 99, ix = 99;
  BerVarbind vbs[4]; size_t nvbs = 0;
  r = berDecodePdu(plain, po + pl, &pos2, &pduTag, &rid, &st, &ix, vbs, 4, &nvbs);
  ok_(r == BER_OK && pduTag == BER_TAG_GET_REQ && rid == 42 && st == 0 && ix == 0
      && nvbs == 1, "MSG_B GetRequest fields");
  uint32_t wantName[] = {1, 3, 6, 1, 4, 1, 99999, 1, 1, 0};
  ok_(vbs[0].nameLen == 10 && memcmp(vbs[0].name, wantName, 10 * 4) == 0,
      "MSG_B varbind OID");
  ok_(vbs[0].decValueTag == BER_TAG_NULL, "MSG_B get varbind value NULL");
}

int test_usm(void) {
  printf("== USM layer ==\n");
  test_localize();
  test_hmac();
  test_cfb();
  test_flags();
  test_security_params();
  test_timeliness();
  test_msg_b_full();
  printf("  %d checks, %d failures\n", checks, fails);
  return fails;
}