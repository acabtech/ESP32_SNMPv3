// test_mib.c — MIB registry tests (src/mib/MIB.c): parse/resolve/next/set/
// exceptions/tables/standard subtrees. No wire, no crypto.
//
// SPDX-License-Identifier: GPL-3.0
#include <stdio.h>
#include <string.h>

#include "mib/MIB.h"

static int fails = 0;
static int checks = 0;

#define ok_(cond, name) \
  do { checks++; if (!(cond)) { fails++; printf("  FAIL %s\n", name); } } while (0)

static uint32_t hook_uptime(void) { return 987654; }
static const uint8_t* hook_engid(void) { return (const uint8_t*)"\x80\x06\xaa\xbb\xcc\xdd\xee\xff"; }
static size_t hook_engidLen(void) { return 8; }
static uint32_t hook_boots(void) { return 7; }
static uint32_t hook_time(void)  { return 300; }
static uint32_t hook_maxmsg(void) { return 1500; }
static uint32_t hook_stat(size_t i) { return 100 + (uint32_t)i; }

static size_t tbl_rows(void) { return 2; }
static int32_t tbl_cell(size_t row, size_t col) { (void)col; return (int32_t)(row * 10); }

static int32_t g_appVal = -17;
static int32_t app_get(void) { return g_appVal; }
static bool app_set(int32_t v) { if (v > 1000) return false; g_appVal = v; return true; }

static int32_t app2_get(void) { return 42; }
static bool app2_set(int32_t v) { (void)v; return false; }   // always rejects

int test_mib(void) {
  printf("== MIB registry ==\n");

  // --- parse ---
  uint32_t a[MIB_ARCS_MAX];
  ok_(mibParseOid("1.3.6.1.4.1.67018.1.1.0", a, MIB_ARCS_MAX) == 10 &&
      a[6] == 67018, "parse: arcs + big arc");
  ok_(mibParseOid("", a, MIB_ARCS_MAX) == -1, "parse: empty");
  ok_(mibParseOid("1.3.6.", a, MIB_ARCS_MAX) == -1, "parse: trailing dot");
  ok_(mibParseOid("1.3.6.x", a, MIB_ARCS_MAX) == -1, "parse: garbage");
  ok_(mibParseOid("4294967295.1", a, MIB_ARCS_MAX) == 2 &&
      a[0] == 4294967295u, "parse: u32 arc");
  ok_(mibParseOid("4294967296.1", a, MIB_ARCS_MAX) == -1, "parse: >u32 arc");

  // --- hooks + system leaves ---
  MibSystemHooks h;
  memset(&h, 0, sizeof h);
  h.sysUpTime = hook_uptime;
  h.engineId = hook_engid;
  h.engineIdLen = hook_engidLen;
  h.engineBoots = hook_boots;
  h.engineTime = hook_time;
  h.engineMaxMessage = hook_maxmsg;
  h.usmStat = hook_stat;
  mibSetSystemHooks(&h);
  ok_(mibRegisterSystem() == 0, "system: register");
  ok_(mibRegisterSystem() == 0, "system: register idempotent");

  MibValue v;
  ok_(mibGet((uint32_t[]){1,3,6,1,2,1,1,1,0}, 9, &v) == 1 &&
      v.type == MIB_T_OCTETS && v.octetsLen == 18 &&
      memcmp(v.octets, "ESP32-SNMPv3-Agent", 18) == 0, "sys: sysDescr default");
  ok_(mibGet((uint32_t[]){1,3,6,1,2,1,1,2,0}, 9, &v) == 1 &&
      v.type == MIB_T_OID && v.arcsLen == 8 &&
      v.arcs[6] == 67018 && v.arcs[7] == 1, "sys: sysObjectID PEN 67018");
  ok_(mibGet((uint32_t[]){1,3,6,1,2,1,1,3,0}, 9, &v) == 1 &&
      v.type == MIB_T_TIMETICKS && v.u32 == 987654, "sys: sysUpTime");
  ok_(mibGet((uint32_t[]){1,3,6,1,2,1,1,7,0}, 9, &v) == 1 &&
      v.type == MIB_T_INT32 && v.u32 == 72, "sys: sysServices");
  ok_(mibGet((uint32_t[]){1,3,6,1,6,3,1,1,4,0}, 10, &v) == 1 &&
      v.type == MIB_T_OCTETS && v.octetsLen == 8 &&
      v.octets[2] == 0xaa, "sys: snmpEngineID");
  ok_(mibGet((uint32_t[]){1,3,6,1,6,3,1,1,5,0}, 10, &v) == 1 &&
      v.type == MIB_T_UINT32 && v.u32 == 7, "sys: snmpEngineBoots");
  ok_(mibGet((uint32_t[]){1,3,6,1,6,3,1,1,6,0}, 10, &v) == 1 &&
      v.type == MIB_T_UINT32 && v.u32 == 300, "sys: snmpEngineTime");
  ok_(mibGet((uint32_t[]){1,3,6,1,6,3,15,1,1,4,0}, 11, &v) == 1 &&
      v.type == MIB_T_COUNTER32 && v.u32 == 103, "sys: usmStats[3]");

  // --- app scalars (public-API style) ---
  ok_(mibRegisterInt32("1.3.6.1.4.1.67018.10.1.0", app_get, app_set) >= 0,
      "app: register RW");
  ok_(mibRegisterInt32("1.3.6.1.4.1.67018.10.1.0", app_get, app_set) == -1,
      "app: duplicate rejected");
  ok_(mibRegisterInt32("1.3.6.1.4.1.67018.10.2.0", app2_get, app2_set) >= 0,
      "app: register rejecting-setter");
  ok_(mibRegisterInt32("1.3.6.1.4.1.67018.10.3.0", app_get, NULL) >= 0,
      "app: register RO");
  ok_(mibRegisterInt32("1.3.6.1.4.1.67018.10.4.0", NULL, NULL) == -1,
      "app: getter NULL rejected");

  uint32_t kApp1[] = {1,3,6,1,4,1,67018,10,1,0};
  ok_(mibGet(kApp1, 10, &v) == 1 && v.type == MIB_T_INT32 && v.u32 == 0xFFFFFFEFu,
      "app: get initial -17");
  MibValue in;
  memset(&in, 0, sizeof in);
  in.type = MIB_T_INT32; in.u32 = 5;
  ok_(mibSet(kApp1, 10, &in) == MIB_SET_APPLIED, "app: set applied");
  ok_(mibGet(kApp1, 10, &v) == 1 && v.u32 == 5, "app: get after set");
  in.u32 = 2000;   // setter rejects >1000
  ok_(mibSet(kApp1, 10, &in) == MIB_SET_REJECTED, "app: setter rejection");
  in.type = MIB_T_OCTETS; in.u32 = 5;
  ok_(mibSet(kApp1, 10, &in) == MIB_SET_WRONG_TYPE, "app: wrong type");
  uint32_t kApp3[] = {1,3,6,1,4,1,67018,10,3,0};
  in.type = MIB_T_INT32; in.u32 = 5;
  ok_(mibSet(kApp3, 10, &in) == MIB_SET_READ_ONLY, "app: RO rejected");
  uint32_t kNo[] = {1,3,6,1,4,1,67018,99,9,0};
  ok_(mibSet(kNo, 10, &in) == MIB_SET_NO_SUCH, "app: unknown OID");

  // Register the dynamic table here so ordering checks below include it.
  uint32_t kTbl[] = {1,3,6,1,4,1,67018,20};
  ok_(mibRegisterTableBase(kTbl, 8, tbl_rows, tbl_cell) >= 0, "table: register");

  // --- GetNext ordering (incl. the 67018 arc and prefix-first rule) ---
  uint32_t nxt[MIB_ARCS_MAX]; size_t nxtLen;
  uint32_t q[] = {1,3,6,1,4,1,67018,10,1,0};
  ok_(mibNext(q, 10, nxt, &nxtLen) == 1 && nxtLen == 10 &&
      nxt[8] == 2, "next: 10.1.0 -> 10.2.0");
  uint32_t qRoot[] = {1,3,6,1,4,1,67018};
  ok_(mibNext(qRoot, 7, nxt, &nxtLen) == 1 && nxtLen == 10 &&
      nxt[7] == 10 && nxt[8] == 1, "next: prefix-first into .10.1.0");
  uint32_t qMid[] = {1,3,6,1,4,1,67018,10,2,0};
  ok_(mibNext(qMid, 10, nxt, &nxtLen) == 1 && nxtLen == 10 &&
      nxt[8] == 3, "next: 10.2.0 -> 10.3.0");
  uint32_t qLast[] = {1,3,6,1,4,1,67018,10,3,0};
  // The dynamic table row 1 (1.3.6.1.4.1.67018.20.1) is the next instance.
  ok_(mibNext(qLast, 10, nxt, &nxtLen) == 1 && nxtLen == 9 &&
      nxt[7] == 20 && nxt[8] == 1, "next: app subtree -> table row 1");
  // exact: from the LAST registered leaf overall -> endOfMibView is covered
  // by the agent bulk test; here verify parent navigation:
  uint32_t qUnder[] = {1,3,6,1,4,1,67018,10,1};   // instance-less parent
  ok_(mibNext(qUnder, 9, nxt, &nxtLen) == 1 && nxtLen == 10 &&
      nxt[8] == 1 && nxt[9] == 0, "next: parent -> own instance .0");

  // --- exceptions ---
  uint32_t eUnder[] = {1,3,6,1,4,1,67018,10,1,1};
  ok_(mibNoSuchInstance(eUnder, 10), "exc: under registered -> noSuchInstance");
  uint32_t eParent[] = {1,3,6,1,4,1,67018,10};
  ok_(mibNoSuchInstance(eParent, 8), "exc: parent of registered -> noSuchInstance");
  ok_(!mibNoSuchInstance(kNo, 10), "exc: unrelated -> noSuchObject");
  ok_(!mibNoSuchInstance((uint32_t[]){1,3,6,1,88}, 5), "exc: foreign root");

  // --- table (registered above) ---
  uint32_t t1[] = {1,3,6,1,4,1,67018,20,1};
  ok_(mibGet(t1, 9, &v) == 1 && v.type == MIB_T_INT32 && v.u32 == 0,
      "table: row 1 = 0");
  uint32_t t2[] = {1,3,6,1,4,1,67018,20,2};
  ok_(mibGet(t2, 9, &v) == 1 && v.u32 == 10, "table: row 2 = 10");
  uint32_t t3[] = {1,3,6,1,4,1,67018,20,3};
  ok_(mibGet(t3, 9, &v) == 0, "table: row 3 missing");
  ok_(mibNext(t1, 9, nxt, &nxtLen) == 1 && nxtLen == 9 && nxt[8] == 2,
      "table: next row");
  uint32_t tq[] = {1,3,6,1,4,1,67018,20};
  ok_(mibNext(tq, 8, nxt, &nxtLen) == 1 && nxtLen == 9 && nxt[8] == 1,
      "table: base -> row 1");
  ok_(mibNoSuchInstance((uint32_t[]){1,3,6,1,4,1,67018,20,5}, 9),
      "table: out-of-range instance -> noSuchInstance");
  in.type = MIB_T_INT32; in.u32 = 1;
  ok_(mibSet(t1, 9, &in) == MIB_SET_READ_ONLY, "table: not settable");

  printf("  %d checks, %d failures\n", checks, fails);
  return fails;
}