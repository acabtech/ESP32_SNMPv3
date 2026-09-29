// MIB.c — sorted-instance object registry + standard subtrees (M2).
//
// SPDX-License-Identifier: GPL-3.0
#include "MIB.h"

#include <stdlib.h>
#include <string.h>

#define MIB_MAX_LEAVES 64
#define MIB_MAX_TABLES 4

typedef struct {
  uint32_t arcs[MIB_ARCS_MAX];
  size_t   arcsLen;
  MibType  type;
  uint8_t  writable;
  MibGetFn get;
  MibSetFn set;
  void*    ctx;
} MibLeaf;

typedef struct {
  uint32_t arcs[MIB_ARCS_MAX];
  size_t   arcsLen;
  size_t (*rows)(void);
  int32_t (*cell)(size_t row, size_t col);
} MibTable;

typedef struct {  // closure for the public int32 scalar API
  int32_t (*getter)(void);
  bool (*setter)(int32_t value);
} Int32Ctx;

static MibLeaf  g_leaves[MIB_MAX_LEAVES];
static size_t   g_nLeaves;
static Int32Ctx g_i32ctx[MIB_MAX_LEAVES];
static size_t   g_nI32ctx;

static MibTable g_tables[MIB_MAX_TABLES];
static size_t   g_nTables;

static char g_sysDescr[MIB_OCTETS_MAX]    = "ESP32-SNMPv3-Agent";
static char g_sysName[MIB_OCTETS_MAX]     = "esp32-snmp";
static char g_sysContact[MIB_OCTETS_MAX]  = "";
static char g_sysLocation[MIB_OCTETS_MAX] = "";

static MibSystemHooks g_hooks;  // zeroed = defaults (no dynamic sources)

// --- OID helpers ------------------------------------------------------------

int mibParseOid(const char* dotted, uint32_t* arcs, size_t cap) {
  if (dotted == NULL || arcs == NULL || cap == 0) return -1;
  size_t n = 0;
  const char* p = dotted;
  while (*p) {
    if (*p < '0' || *p > '9') return -1;
    uint64_t v = 0;
    while (*p >= '0' && *p <= '9') {
      v = v * 10 + (uint32_t)(*p - '0');
      if (v > 0xFFFFFFFFull) return -1;
      p++;
    }
    if (n >= cap) return -1;
    arcs[n++] = (uint32_t)v;
    if (*p == '.') { p++; if (!(*p >= '0' && *p <= '9')) return -1; }
    else if (*p) return -1;
  }
  if (n == 0) return -1;
  return (int)n;
}

// Arc-wise compare; when one OID is a proper prefix of the other, the
// shorter sorts first (RFC 2578 lexicographic instance ordering).
int mibArcCmp(const uint32_t* a, size_t an,
              const uint32_t* b, size_t bn) {
  size_t m = an < bn ? an : bn;
  for (size_t i = 0; i < m; i++) {
    if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
  }
  if (an == bn) return 0;
  return an < bn ? -1 : 1;
}

static bool properPrefix(const uint32_t* a, size_t an,
                         const uint32_t* b, size_t bn) {
  if (an >= bn) return false;
  for (size_t i = 0; i < an; i++) if (a[i] != b[i]) return false;
  return true;
}

static int leafCmp(const void* pa, const void* pb) {
  const MibLeaf* a = (const MibLeaf*)pa;
  const MibLeaf* b = (const MibLeaf*)pb;
  return mibArcCmp(a->arcs, a->arcsLen, b->arcs, b->arcsLen);
}

static void mibSort(void) {
  qsort(g_leaves, g_nLeaves, sizeof g_leaves[0], leafCmp);
}

static const MibLeaf* findExact(const uint32_t* arcs, size_t nArcs) {
  size_t lo = 0, hi = g_nLeaves;
  while (lo < hi) {
    size_t mid = (lo + hi) / 2;
    int c = mibArcCmp(g_leaves[mid].arcs, g_leaves[mid].arcsLen, arcs, nArcs);
    if (c == 0) return &g_leaves[mid];
    if (c < 0) lo = mid + 1; else hi = mid;
  }
  return NULL;
}

// --- Registration -----------------------------------------------------------

int mibRegisterCtx(const uint32_t* arcs, size_t nArcs, MibType type,
                   MibGetFn get, MibSetFn set, void* ctx) {
  if (arcs == NULL || nArcs == 0 || nArcs > MIB_ARCS_MAX) return -1;
  if (g_nLeaves >= MIB_MAX_LEAVES) return -1;
  if (findExact(arcs, nArcs) != NULL) return -1;   // duplicate instance
  MibLeaf* l = &g_leaves[g_nLeaves++];
  memcpy(l->arcs, arcs, nArcs * sizeof arcs[0]);
  l->arcsLen = nArcs;
  l->type = type;
  l->writable = (set != NULL);
  l->get = get;
  l->set = set;
  l->ctx = ctx;
  mibSort();
  return (int)(l - g_leaves);
}

int mibRegister(const uint32_t* arcs, size_t nArcs, MibType type,
                MibGetFn get, MibSetFn set) {
  return mibRegisterCtx(arcs, nArcs, type, get, set, NULL);
}

static bool int32GetWrap(void* ctx, MibValue* out);
static bool int32SetWrap(void* ctx, const MibValue* in);

int mibRegisterInt32(const char* dottedOid,
                     int32_t (*getter)(void),
                     bool (*setter)(int32_t value)) {
  uint32_t arcs[MIB_ARCS_MAX];
  int n = mibParseOid(dottedOid, arcs, MIB_ARCS_MAX);
  if (n < 0) return -1;
  if (getter == NULL) return -1;   // a getter is mandatory
  if (g_nI32ctx >= MIB_MAX_LEAVES) return -1;
  if (findExact(arcs, (size_t)n) != NULL) return -1;

  Int32Ctx* ctx = &g_i32ctx[g_nI32ctx++];
  ctx->getter = getter;
  ctx->setter = setter;
  int r = mibRegisterCtx(arcs, (size_t)n, MIB_T_INT32,
                         int32GetWrap, setter ? int32SetWrap : NULL, ctx);
  if (r < 0) { g_nI32ctx--; return -1; }
  return r;
}

// --- Wrapper closures -------------------------------------------------------

static bool int32GetWrap(void* ctx, MibValue* out) {
  Int32Ctx* c = (Int32Ctx*)ctx;
  out->type = MIB_T_INT32;
  out->u32 = (uint32_t)c->getter();
  return true;
}

static bool int32SetWrap(void* ctx, const MibValue* in) {
  Int32Ctx* c = (Int32Ctx*)ctx;
  return c->setter((int32_t)in->u32);
}

// --- Standard system leaves -------------------------------------------------

static bool sysDescrGet(void* ctx, MibValue* v) {
  (void)ctx;
  v->type = MIB_T_OCTETS;
  size_t n = strlen(g_sysDescr);
  if (n > sizeof v->octets) n = sizeof v->octets;
  memcpy(v->octets, g_sysDescr, n);
  v->octetsLen = n;
  return true;
}

static bool sysObjectIDGet(void* ctx, MibValue* v) {
  // Placeholder enterprise root (1.3.6.1.4.1.99999.1) until the IANA PEN is
  // assigned; this is the single point of change.
  (void)ctx;
  static const uint32_t kRoot[] = {1, 3, 6, 1, 4, 1, 99999, 1};
  v->type = MIB_T_OID;
  memcpy(v->arcs, kRoot, sizeof kRoot);
  v->arcsLen = sizeof kRoot / sizeof kRoot[0];
  return true;
}

static bool sysServicesGet(void* ctx, MibValue* v) {
  // End-system application+internet+transport layers (classic 72).
  (void)ctx;
  v->type = MIB_T_INT32;
  v->u32 = 72;
  return true;
}

static bool sysUpTimeGet(void* ctx, MibValue* v) {
  (void)ctx;
  if (!g_hooks.sysUpTime) return false;
  v->type = MIB_T_TIMETICKS;
  v->u32 = g_hooks.sysUpTime();
  return true;
}

static bool strGet(void* ctx, MibValue* v) {
  const char* s = (const char*)ctx;
  size_t n = strlen(s);
  if (n > sizeof v->octets) n = sizeof v->octets;
  memcpy(v->octets, s, n);
  v->type = MIB_T_OCTETS;
  v->octetsLen = n;
  return true;
}

static bool sysContactSet(void* ctx, const MibValue* in) {
  char* dst = (char*)ctx;
  if (in->type != MIB_T_OCTETS) return false;
  if (in->octetsLen >= MIB_OCTETS_MAX) return false;
  memcpy(dst, in->octets, in->octetsLen);
  dst[in->octetsLen] = 0;
  return true;
}

static bool engineIdGet(void* ctx, MibValue* v) {
  (void)ctx;
  if (!g_hooks.engineId) return false;
  size_t n = g_hooks.engineIdLen();
  if (n > sizeof v->octets) return false;
  memcpy(v->octets, g_hooks.engineId(), n);
  v->type = MIB_T_OCTETS;
  v->octetsLen = n;
  return true;
}

static bool engineBootsGet(void* ctx, MibValue* v) {
  (void)ctx;
  if (!g_hooks.engineBoots) return false;
  v->type = MIB_T_UINT32;
  v->u32 = g_hooks.engineBoots();
  return true;
}

static bool engineTimeGet(void* ctx, MibValue* v) {
  (void)ctx;
  if (!g_hooks.engineTime) return false;
  v->type = MIB_T_UINT32;
  v->u32 = g_hooks.engineTime();
  return true;
}

static bool engineMaxMsgGet(void* ctx, MibValue* v) {
  (void)ctx;
  if (!g_hooks.engineMaxMessage) return false;
  v->type = MIB_T_UINT32;
  v->u32 = g_hooks.engineMaxMessage();
  return true;
}

static bool usmStatGet(void* ctx, MibValue* v) {
  if (!g_hooks.usmStat) return false;
  v->type = MIB_T_COUNTER32;
  v->u32 = g_hooks.usmStat((size_t)(uintptr_t)ctx);
  return true;
}

void mibSetSystemHooks(const MibSystemHooks* hooks) {
  if (hooks) g_hooks = *hooks; else memset(&g_hooks, 0, sizeof g_hooks);
}

void mibSetSystemText(const char* sysDescr, const char* sysName,
                      const char* sysContact, const char* sysLocation) {
  if (sysDescr && strlen(sysDescr) < MIB_OCTETS_MAX)
    strcpy(g_sysDescr, sysDescr);
  if (sysName && strlen(sysName) < MIB_OCTETS_MAX)
    strcpy(g_sysName, sysName);
  if (sysContact && strlen(sysContact) < MIB_OCTETS_MAX)
    strcpy(g_sysContact, sysContact);
  if (sysLocation && strlen(sysLocation) < MIB_OCTETS_MAX)
    strcpy(g_sysLocation, sysLocation);
}

static int mibRegisterSystemInner(void);

static bool g_systemRegistered;

int mibRegisterSystem(void) {
  if (g_systemRegistered) return 0;
  if (mibRegisterSystemInner() < 0) return -1;
  g_systemRegistered = true;
  return 0;
}

static int mibRegisterSystemInner(void) {
  uint32_t a[MIB_ARCS_MAX];
  int n;

  n = mibParseOid("1.3.6.1.2.1.1.1.0", a, MIB_ARCS_MAX);      // sysDescr
  if (n < 0) return -1;
  if (mibRegister(a, (size_t)n, MIB_T_OCTETS, sysDescrGet, NULL) < 0) return -1;
  n = mibParseOid("1.3.6.1.2.1.1.2.0", a, MIB_ARCS_MAX);      // sysObjectID
  if (n < 0) return -1;
  if (mibRegister(a, (size_t)n, MIB_T_OID, sysObjectIDGet, NULL) < 0) return -1;
  n = mibParseOid("1.3.6.1.2.1.1.3.0", a, MIB_ARCS_MAX);      // sysUpTime
  if (n < 0) return -1;
  if (mibRegister(a, (size_t)n, MIB_T_TIMETICKS, sysUpTimeGet, NULL) < 0) return -1;
  n = mibParseOid("1.3.6.1.2.1.1.4.0", a, MIB_ARCS_MAX);      // sysContact (RW)
  if (n < 0) return -1;
  if (mibRegisterCtx(a, (size_t)n, MIB_T_OCTETS, strGet, sysContactSet,
                     g_sysContact) < 0) return -1;
  n = mibParseOid("1.3.6.1.2.1.1.5.0", a, MIB_ARCS_MAX);      // sysName (RW)
  if (n < 0) return -1;
  if (mibRegisterCtx(a, (size_t)n, MIB_T_OCTETS, strGet, sysContactSet,
                     g_sysName) < 0) return -1;
  n = mibParseOid("1.3.6.1.2.1.1.6.0", a, MIB_ARCS_MAX);      // sysLocation (RW)
  if (n < 0) return -1;
  if (mibRegisterCtx(a, (size_t)n, MIB_T_OCTETS, strGet, sysContactSet,
                     g_sysLocation) < 0) return -1;
  n = mibParseOid("1.3.6.1.2.1.1.7.0", a, MIB_ARCS_MAX);      // sysServices
  if (n < 0) return -1;
  if (mibRegister(a, (size_t)n, MIB_T_INT32, sysServicesGet, NULL) < 0) return -1;

  // SNMP-FRAMEWORK-MIB snmpEngine group (RFC 3411 §7.1.2).
  static const struct { const char* oid; bool (*get)(void*, MibValue*); } kEng[] = {
    { "1.3.6.1.6.3.1.1.4.0", engineIdGet },      // snmpEngineID
    { "1.3.6.1.6.3.1.1.5.0", engineBootsGet },   // snmpEngineBoots
    { "1.3.6.1.6.3.1.1.6.0", engineTimeGet },    // snmpEngineTime
    { "1.3.6.1.6.3.1.1.7.0", engineMaxMsgGet },  // snmpEngineMaxMessageSize
  };
  for (size_t i = 0; i < sizeof kEng / sizeof kEng[0]; i++) {
    n = mibParseOid(kEng[i].oid, a, MIB_ARCS_MAX);
    if (n < 0) return -1;
    if (mibRegister(a, (size_t)n, MIB_T_UINT32, kEng[i].get, NULL) < 0)
      return -1;
  }
  // snmpEngineID is octets, not uint32 — overwrite its type.
  for (size_t i = 0; i < g_nLeaves; i++) {
    uint32_t eng[MIB_ARCS_MAX];
    int m = mibParseOid("1.3.6.1.6.3.1.1.4.0", eng, MIB_ARCS_MAX);
    if (m > 0 && mibArcCmp(g_leaves[i].arcs, g_leaves[i].arcsLen, eng, (size_t)m) == 0)
      g_leaves[i].type = MIB_T_OCTETS;
  }

  // SNMP-USER-BASED-SM-MIB usmStats (counters served by the agent core).
  static const char* kStats[] = {
    "1.3.6.1.6.3.15.1.1.1.0",  // usmStatsUnsupportedSecLevels
    "1.3.6.1.6.3.15.1.1.2.0",  // usmStatsNotInTimeWindows
    "1.3.6.1.6.3.15.1.1.3.0",  // usmStatsUnknownUserNames
    "1.3.6.1.6.3.15.1.1.4.0",  // usmStatsUnknownEngineIDs
    "1.3.6.1.6.3.15.1.1.5.0",  // usmStatsWrongDigests
    "1.3.6.1.6.3.15.1.1.6.0",  // usmStatsDecryptionErrors
  };
  for (size_t i = 0; i < sizeof kStats / sizeof kStats[0]; i++) {
    n = mibParseOid(kStats[i], a, MIB_ARCS_MAX);
    if (n < 0) return -1;
    if (mibRegisterCtx(a, (size_t)n, MIB_T_COUNTER32, usmStatGet, NULL,
                       (void*)(uintptr_t)i) < 0) return -1;
  }
  return 0;
}

// --- Tables -----------------------------------------------------------------

static MibTable* findTableFor(const uint32_t* arcs, size_t nArcs) {
  for (size_t i = 0; i < g_nTables; i++) {
    MibTable* t = &g_tables[i];
    if (nArcs >= t->arcsLen &&
        memcmp(t->arcs, arcs, t->arcsLen * sizeof arcs[0]) == 0)
      return t;
  }
  return NULL;
}

int mibRegisterTableBase(const uint32_t* base, size_t nBase,
                         size_t (*rows)(void),
                         int32_t (*cell)(size_t row, size_t col)) {
  if (base == NULL || nBase == 0 || nBase > MIB_ARCS_MAX) return -1;
  if (rows == NULL || cell == NULL) return -1;
  if (g_nTables >= MIB_MAX_TABLES) return -1;
  MibTable* t = &g_tables[g_nTables++];
  memcpy(t->arcs, base, nBase * sizeof base[0]);
  t->arcsLen = nBase;
  t->rows = rows;
  t->cell = cell;
  return (int)(t - g_tables);
}

static size_t tableRows(const MibTable* t) {
  size_t n = t->rows();
  return n > 65535 ? 65535 : n;
}

// --- Dispatch ---------------------------------------------------------------

static int leafGet(const MibLeaf* l, MibValue* out) {
  memset(out, 0, sizeof *out);
  if (!l->get(l->ctx, out)) return -1;
  out->type = l->type;  // getter may leave the type untouched
  return 1;
}

int mibGet(const uint32_t* arcs, size_t nArcs, MibValue* out) {
  if (out == NULL || arcs == NULL || nArcs == 0) return -1;
  const MibLeaf* l = findExact(arcs, nArcs);
  if (l != NULL) return leafGet(l, out);

  // Dynamic table instance: <base>.<row+1>
  MibTable* t = findTableFor(arcs, nArcs);
  if (t != NULL && nArcs == t->arcsLen + 1) {
    uint32_t row = arcs[t->arcsLen];
    if (row >= 1 && row <= tableRows(t)) {
      memset(out, 0, sizeof *out);
      out->type = MIB_T_INT32;
      out->u32 = (uint32_t)t->cell(row - 1, 0);
      return 1;
    }
  }
  return 0;  // not found
}

int mibSet(const uint32_t* arcs, size_t nArcs, const MibValue* in) {
  if (in == NULL || arcs == NULL || nArcs == 0) return MIB_SET_ERROR;
  MibLeaf* l = (MibLeaf*)findExact(arcs, nArcs);
  if (l == NULL) {
    // Dynamic table instances exist (mibGet serves them) but are RO.
    MibTable* t = findTableFor(arcs, nArcs);
    if (t != NULL && nArcs == t->arcsLen + 1) {
      uint32_t row = arcs[t->arcsLen];
      if (row >= 1 && row <= tableRows(t)) return MIB_SET_READ_ONLY;
    }
    return MIB_SET_NO_SUCH;                    // unknown instance
  }
  if (!l->writable || l->set == NULL) return MIB_SET_READ_ONLY;
  if (in->type != l->type) return MIB_SET_WRONG_TYPE;
  return l->set(l->ctx, in) ? MIB_SET_APPLIED : MIB_SET_REJECTED;
}

int mibNext(const uint32_t* arcs, size_t nArcs,
            uint32_t* nextArcs, size_t* nextLen) {
  if (nextArcs == NULL || nextLen == NULL) return 0;

  // 1) static leaves: first leaf strictly greater than `arcs`.
  const MibLeaf* best = NULL;
  size_t lo = 0, hi = g_nLeaves;
  while (lo < hi) {
    size_t mid = (lo + hi) / 2;
    if (mibArcCmp(g_leaves[mid].arcs, g_leaves[mid].arcsLen, arcs, nArcs) > 0) {
      best = &g_leaves[mid];
      hi = mid;
    } else {
      lo = mid + 1;
    }
  }

  // 2) dynamic tables: smallest instance <base>.<r> greater than `arcs`;
  //    keep whichever candidate (static or table) is smaller overall.
  uint32_t cand[MIB_ARCS_MAX];
  size_t candLen = 0;
  bool have = false;
  for (size_t i = 0; i < g_nTables; i++) {
    MibTable* t = &g_tables[i];
    size_t nRows = tableRows(t);
    for (size_t r = 1; r <= nRows; r++) {
      memcpy(cand, t->arcs, t->arcsLen * sizeof cand[0]);
      cand[t->arcsLen] = (uint32_t)r;
      candLen = t->arcsLen + 1;
      if (mibArcCmp(cand, candLen, arcs, nArcs) > 0) break;  // smallest hit
      candLen = 0;
    }
    if (candLen != 0) {
      if (best == NULL ||
          mibArcCmp(cand, candLen, best->arcs, best->arcsLen) < 0) {
        memcpy(nextArcs, cand, candLen * sizeof cand[0]);
        *nextLen = candLen;
        have = true;
        best = NULL;
      }
    }
  }

  if (best != NULL) {
    memcpy(nextArcs, best->arcs, best->arcsLen * sizeof nextArcs[0]);
    *nextLen = best->arcsLen;
    have = true;
  }
  return have ? 1 : 0;
}

// RFC 2578 §8.2: a name is a noSuchInstance when it shares the OBJECT
// prefix of a registered instance (the object exists, the instance does
// not), or when it names an ancestor object/subtree of a registered leaf.
// A name unrelated to anything registered is a noSuchObject instead.
static bool instanceOf(const uint32_t* q, size_t qn,
                       const uint32_t* l, size_t ln) {
  if (ln == 0) return false;
  size_t objLen = ln - 1;               // object prefix of the instance
  if (qn >= ln && memcmp(q, l, objLen * sizeof q[0]) == 0) return true;
  if (qn <  ln && memcmp(q, l, qn    * sizeof q[0]) == 0) return true;
  return false;
}

bool mibNoSuchInstance(const uint32_t* arcs, size_t nArcs) {
  for (size_t i = 0; i < g_nLeaves; i++) {
    const MibLeaf* l = &g_leaves[i];
    if (instanceOf(arcs, nArcs, l->arcs, l->arcsLen)) return true;
  }
  for (size_t i = 0; i < g_nTables; i++) {
    const MibTable* t = &g_tables[i];
    // instance of the table (base.<row>) or an ancestor of the base
    if (nArcs == t->arcsLen + 1 &&
        memcmp(arcs, t->arcs, t->arcsLen * sizeof arcs[0]) == 0)
      return true;
    if (nArcs <= t->arcsLen &&
        memcmp(arcs, t->arcs, nArcs * sizeof arcs[0]) == 0)
      return true;
  }
  return false;
}