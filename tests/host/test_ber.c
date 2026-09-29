// test_ber.c — BER codec tests (src/ber/BER.c) with generated vectors.
//
// Covers: length, INTEGER and OID known-answer encodings, round-trips,
// a deterministic fuzz pass, varbind/PDU/scopedPDU assembly, and both
// wire samples (discovery Report decode + byte-identical re-encode;
// authPriv GetRequest header/field decode).
//
// SPDX-License-Identifier: GPL-3.0
#include <stdio.h>
#include <string.h>
#include "BER.h"
#include "vectors.h"

static int fails = 0;
static int checks = 0;

static void ok_(int cond, const char* what) {
  checks++;
  if (!cond) { fails++; printf("  FAIL: %s\n", what); }
}

// --- helpers ---------------------------------------------------------------
static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static void from_hex(uint8_t* out, const char* h) {
  for (size_t i = 0; i < strlen(h) / 2; i++)
    out[i] = (uint8_t)((hexval(h[2 * i]) << 4) | hexval(h[2 * i + 1]));
}

static void expect_bytes(const uint8_t* got, size_t gotLen,
                         const uint8_t* want, size_t wantLen, const char* what) {
  ok_(gotLen == wantLen && memcmp(got, want, wantLen) == 0, what);
}

// pseudo-random for deterministic fuzz
static uint32_t rng = 0x12345678u;
static uint32_t rnd(void) { rng = rng * 1664525u + 1013904223u; return rng; }

// --- tests -----------------------------------------------------------------
static void test_length(void) {
  uint8_t buf[16];
  size_t vals[] = {0, 1, 127, 128, 255, 256, 5000, 16383, 16384, 65535, 1000000};
  for (size_t i = 0; i < sizeof vals / sizeof vals[0]; i++) {
    int n = berEncodeLength(buf, sizeof buf, vals[i]);
    ok_(n > 0, "length encode ok");
    size_t pos = 0, out = 0;
    int r = berDecodeLength(buf, (size_t)n, &pos, &out);
    ok_(r == BER_OK && pos == (size_t)n && out == vals[i], "length roundtrip");
  }
  // fuzz round-trip
  for (int i = 0; i < 2000; i++) {
    size_t v = rnd() % 2000000;
    int n = berEncodeLength(buf, sizeof buf, v);
    size_t pos = 0, out = 0;
    ok_(n > 0 && berDecodeLength(buf, (size_t)n, &pos, &out) == BER_OK
        && out == v, "length fuzz roundtrip");
  }
}

static void test_int(void) {
  uint8_t got[8], want[8];
  // known-answer encodings
  struct { int32_t v; const char* hex; } ka[] = {
    {0, "020100"}, {127, "02017f"}, {128, "02020080"}, {255, "020200ff"},
    {256, "02020100"}, {-1, "0201ff"}, {-128, "020180"}, {-129, "0202ff7f"},
    {0x7fffffff, "02047fffffff"}, {0x80000000, "020480000000"},
  };
  for (size_t i = 0; i < sizeof ka / sizeof ka[0]; i++) {
    int n = berEncodeInt32(got, sizeof got, ka[i].v);
    from_hex(want, ka[i].hex);
    expect_bytes(got, (size_t)n, want, strlen(ka[i].hex) / 2, "INTEGER known-answer");
    size_t pos = 0; int32_t back = -12345;
    int r = berDecodeInt32(got, (size_t)n, &pos, &back);
    ok_(r == BER_OK && back == ka[i].v && pos == (size_t)n, "INTEGER decode-back");
  }
  // decode of externally-produced non-minimal must be rejected
  {
    uint8_t bad[] = {0x02, 0x02, 0x00, 0x7f};  // non-minimal 127
    size_t pos = 0; int32_t v = 0;
    ok_(berDecodeInt32(bad, sizeof bad, &pos, &v) != BER_OK, "INTEGER rejects non-minimal");
  }
  // roundtrip fuzz
  for (int i = 0; i < 2000; i++) {
    int32_t v = (int32_t)rnd();
    int n = berEncodeInt32(got, sizeof got, v);
    size_t pos = 0; int32_t back = 0;
    if (berDecodeInt32(got, (size_t)n, &pos, &back) != BER_OK || back != v)
      ok_(0, "INTEGER fuzz roundtrip");
  }
  ok_(1, "INTEGER fuzz roundtrip");
}

static void test_oid(void) {
  uint8_t got[64], want[64];
  // 1.3.6.1.6.3.10.1.1.5  (usmHMAC192SHA256AuthProtocol) — known bytes
  {
    uint32_t arcs[] = {1, 3, 6, 1, 6, 3, 10, 1, 1, 5};
    int n = berEncodeOid(got, sizeof got, arcs, 10);
    from_hex(want, "06092b060106030a010105");
    expect_bytes(got, (size_t)n, want, 11, "OID usmHMAC192SHA256 known bytes");
  }
  // 1.3.6.1.4.1.99999.1.1.0 — exercises a 3-octet subidentifier (99999)
  {
    uint32_t arcs[] = {1, 3, 6, 1, 4, 1, 99999, 1, 1, 0};
    int n = berEncodeOid(got, sizeof got, arcs, 10);
    from_hex(want, "060b2b06010401868d1f010100");
    expect_bytes(got, (size_t)n, want, 13, "OID with 99999 subid known bytes");
  }
  // roundtrip fuzz incl. large arcs
  for (int i = 0; i < 500; i++) {
    uint32_t arcs[8], back[8];
    arcs[0] = 1; arcs[1] = 3;
    int nArcs = 2 + (int)(rnd() % 6);
    for (int a = 2; a < nArcs; a++) arcs[a] = rnd() & 0xFFFFFFFu;
    arcs[0] = rnd() % 3;
    if (arcs[0] != 2) arcs[1] = rnd() % 40;
    else arcs[1] = rnd();
    int n = berEncodeOid(got, sizeof got, arcs, (size_t)nArcs);
    size_t pos = 0; size_t nBack = 8;
    int r = berDecodeOid(got, (size_t)n, &pos, back, &nBack);
    if (r != BER_OK || nBack != (size_t)nArcs) { ok_(0, "OID fuzz decode"); continue; }
    int same = 1;
    for (int a = 0; a < nArcs; a++) if (back[a] != arcs[a]) same = 0;
    ok_(same, "OID fuzz roundtrip");
  }
}

static void test_structs(void) {
  uint8_t buf[512];
  // varbind: name + INTEGER 42
  uint32_t nm[] = {1, 3, 6, 1, 4, 1, 99999, 1, 1, 0};
  uint8_t val42[8]; int vn = berEncodeInt32(val42, sizeof val42, 42);
  int n = berEncodeVarbind(buf, sizeof buf, nm, 10, val42, (size_t)vn);
  ok_(n > 0, "varbind encode");

  // PDU GetRequest with one varbind, decode fields + name
  BerVarbind vb;
  memset(&vb, 0, sizeof vb);
  memcpy(vb.name, nm, sizeof nm); vb.nameLen = 10;
  vb.valueTlv = val42; vb.valueLen = (size_t)vn;
  n = berEncodePdu(buf, sizeof buf, BER_TAG_GET_REQ, 77, 0, 0, &vb, 1);
  ok_(n > 0, "PDU encode");
  size_t pos = 0; uint8_t tag = 0; uint32_t rid = 0, st = 1, ix = 1;
  BerVarbind out[4]; size_t nOut = 0;
  int r = berDecodePdu(buf, (size_t)n, &pos, &tag, &rid, &st, &ix, out, 4, &nOut);
  ok_(r == BER_OK && tag == BER_TAG_GET_REQ && rid == 77 && st == 0 && ix == 0
      && nOut == 1 && out[0].nameLen == 10, "PDU decode fields");
  ok_(memcmp(out[0].name, nm, 10 * 4) == 0, "PDU decode varbind name");
  ok_(out[0].decValueTag == BER_TAG_INTEGER && out[0].decValueLen == 1,
      "PDU decode varbind value bounds");

  // scopedPDU roundtrip
  uint8_t pdu[256]; int pn = berEncodePdu(pdu, sizeof pdu, BER_TAG_GET_REQ, 7, 0, 0, &vb, 1);
  uint8_t eid[] = {0x80, 0x00, 0x1f, 0x88, 0x80, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
  n = berEncodeScopedPdu(buf, sizeof buf, eid, sizeof eid, NULL, 0, pdu, (size_t)pn);
  ok_(n > 0, "scopedPDU encode");
  pos = 0; size_t eo, el, no, nl, po, pl;
  r = berDecodeScopedPdu(buf, (size_t)n, &pos, &eo, &el, &no, &nl, &po, &pl);
  ok_(r == BER_OK && el == sizeof eid && memcmp(buf + eo, eid, el) == 0
      && nl == 0 && pl == (size_t)pn, "scopedPDU decode");
  ok_(memcmp(buf + po, pdu, pl) == 0, "scopedPDU PDU bytes preserved");
}

static void test_msg_a(void) {
  // decode sample A (discovery Report)
  uint8_t ver = 0; uint32_t mid = 0, msize = 0; uint8_t fl = 0, sm = 0;
  size_t spo, spl, sdo, sdl;
  int r = berDecodeV3Message(V_MSG_A, sizeof V_MSG_A,
                             &ver, &mid, &msize, &fl, &sm,
                             &spo, &spl, &sdo, &sdl);
  ok_(r == BER_OK, "MSG_A decode");
  ok_(ver == 3 && mid == V_MSG_A_EXPECT_MSGID && msize == V_MSG_A_EXPECT_MAXSIZE
      && fl == V_MSG_A_EXPECT_FLAGS && sm == V_MSG_A_EXPECT_SECMODEL,
      "MSG_A header fields");
  ok_(spl + sdl + (spo - 6) + 6 <= sizeof V_MSG_A, "MSG_A offsets sane");

  // re-encode must reproduce the sample byte-for-byte (deterministic: no
  // crypto in discovery reports)
  uint8_t rebuf[512];
  int n = berEncodeV3Message(rebuf, sizeof rebuf,
                             mid, msize, fl, sm,
                             V_MSG_A + spo, spl,
                             V_MSG_A + sdo, sdl);
  expect_bytes(rebuf, (size_t)n, V_MSG_A, sizeof V_MSG_A, "MSG_A re-encode == sample");

  // securityParams must be a valid SEQUENCE with engineID/boots/time
  size_t pos = 0; uint8_t tag; size_t len;
  int r2 = berDecodeTlv(V_MSG_A + spo, spl, &pos, &tag, &len);
  ok_(r2 == BER_OK && tag == BER_TAG_SEQUENCE, "MSG_A secParams wrapper SEQUENCE");
}

static void test_msg_b(void) {
  uint8_t ver = 0; uint32_t mid = 0, msize = 0; uint8_t fl = 0, sm = 0;
  size_t spo, spl, sdo, sdl;
  int r = berDecodeV3Message(V_MSG_B, sizeof V_MSG_B,
                             &ver, &mid, &msize, &fl, &sm,
                             &spo, &spl, &sdo, &sdl);
  ok_(r == BER_OK, "MSG_B decode");
  ok_(ver == 3 && mid == V_MSG_B_EXPECT_MSGID && msize == V_MSG_B_EXPECT_MAXSIZE
      && fl == V_MSG_B_EXPECT_FLAGS && sm == V_MSG_B_EXPECT_SECMODEL,
      "MSG_B header fields");
  // privFlag set -> msgData is an OCTET STRING wrapping the ciphertext:
  // stream cipher means ciphertext length == plaintext scopedPDU length
  ok_(sdl == sizeof V_MSG_B_PLAIN, "MSG_B msgData == ciphertext len");

  // re-encode (priv flag wraps ciphertext in OCTET STRING) == sample bytes
  uint8_t rebuf[512];
  int n = berEncodeV3Message(rebuf, sizeof rebuf, mid, msize, fl, sm,
                             V_MSG_B + spo, spl, V_MSG_B + sdo, sdl);
  expect_bytes(rebuf, (size_t)n, V_MSG_B, sizeof V_MSG_B, "MSG_B re-encode == sample");
}

int test_ber(void) {
  printf("== BER codec ==\n");
  test_length();
  test_int();
  test_oid();
  test_structs();
  test_msg_a();
  test_msg_b();
  (void)checks;
  printf("  %d checks, %d failures\n", checks, fails);
  return fails;
}