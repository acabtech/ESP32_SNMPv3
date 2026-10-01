// MIB.h — managed-object tree for the agent (M2).
//
// Implementation notes:
//   • Objects live in a flat, lexicographically sorted instance table (exact
//     match = binary search; GetNext = first strictly-greater instance,
//     arc-wise with the standard "shorter prefix sorts first" rule).
//   • Every registered OID string names the SERVED INSTANCE (the sketch's
//     convention is scalars at ".0", e.g. "1.3.6.1.4.1.67018.1.1.0").
//   • Values are typed (Integer32 / Unsigned32 / TimeTicks / Counter32 /
//     OctetString / OID) — SNMPv2-SMI application types are encoded with
//     their proper BER tags by the agent core.
//   • Columnar objects (experimental v0.1 API) are dynamic: instance OID =
//     <base>.<row+1>, value = cell(row, 0). They cannot be Set.
//
// Host-compilable: no Arduino types here (unit-tested in tests/host).
//
// SPDX-License-Identifier: GPL-3.0
#ifndef SNMPV3_MIB_H
#define SNMPV3_MIB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MIB_OCTETS_MAX 128
#define MIB_ARCS_MAX   64

// --- Value model ------------------------------------------------------------
typedef enum {
  MIB_T_INT32,      // INTEGER           -> BER 0x02
  MIB_T_UINT32,     // Unsigned32/Gauge  -> BER 0x42
  MIB_T_TIMETICKS,  // TimeTicks         -> BER 0x43
  MIB_T_COUNTER32,  // Counter32         -> BER 0x41
  MIB_T_OCTETS,     // OCTET STRING      -> BER 0x04
  MIB_T_OID,        // OBJECT IDENTIFIER -> BER 0x06
} MibType;

typedef struct {
  MibType type;
  uint32_t u32;                     // INT32 (bit pattern), UINT32, TIMETICKS, COUNTER32
  uint8_t  octets[MIB_OCTETS_MAX];  // OCTETS payload (getter copies in)
  size_t   octetsLen;
  uint32_t arcs[MIB_ARCS_MAX];      // OID value payload
  size_t   arcsLen;
} MibValue;

typedef bool (*MibGetFn)(void* ctx, MibValue* out);      // fill *out
typedef bool (*MibSetFn)(void* ctx, const MibValue* in); // validate + apply

// --- Registration -----------------------------------------------------------
// Parse a dotted OID string ("1.3.6.1.4.1.67018.1.1.0") into an arc vector.
// Returns arc count, or -1 on malformed input / overflow.
int mibParseOid(const char* dotted, uint32_t* arcs, size_t cap);

// Register a static instance OID. Returns the leaf index (>= 0) or -1 when
// full / duplicate / malformed. ctx flows into the getter/setter callbacks.
int mibRegisterCtx(const uint32_t* arcs, size_t nArcs, MibType type,
                   MibGetFn get, MibSetFn set, void* ctx);
int mibRegister(const uint32_t* arcs, size_t nArcs, MibType type,
                MibGetFn get, MibSetFn set);   // ctx = NULL

// Register the standard system subtrees (SNMPv2-MIB sys group, SNMP-FRAMEWORK
// snmpEngine group, usmStats counters). Returns 0 on success.
int mibRegisterSystem(void);

// Register a dynamic single-column table (public-API registerTable):
//   instance OID = <base>.<row+1>, value = INT32 cell(row, 0).
// Returns the table index (>= 0) or -1 when full.
int mibRegisterTableBase(const uint32_t* base, size_t nBase,
                         size_t (*rows)(void),
                         int32_t (*cell)(size_t row, size_t col));

// Convenience for sketches: register an int32 scalar from the public API.
int mibRegisterInt32(const char* dottedOid,
                     int32_t (*getter)(void),
                     bool (*setter)(int32_t value));

// --- Dispatch primitives (used by the agent core) ---------------------------
// Exact instance lookup; fills *out with the current value.
// Returns 1 on hit, 0 when the OID is not registered, -1 on getter failure.
int mibGet(const uint32_t* arcs, size_t nArcs, MibValue* out);

// Set result codes (mapped by the agent core to PDU error-status):
typedef enum {
  MIB_SET_APPLIED   = 1,   // value written
  MIB_SET_NO_SUCH   = 0,   // unknown instance           -> notWritable
  MIB_SET_ERROR     = -1,  // malformed call             -> genErr
  MIB_SET_READ_ONLY = -2,  // known but not writable     -> notWritable
  MIB_SET_WRONG_TYPE= -3,  // value type mismatch        -> wrongType
  MIB_SET_REJECTED  = -4,  // setter rejected the value  -> wrongValue
} MibSetResult;
int mibSet(const uint32_t* arcs, size_t nArcs, const MibValue* in);

// First registered instance OID strictly greater than `arcs` (arc-wise,
// prefix-first). Writes into nextArcs (cap MIB_ARCS_MAX), *nextLen set.
// Returns 1 on hit, 0 when the OID space is exhausted (endOfMibView).
int mibNext(const uint32_t* arcs, size_t nArcs,
            uint32_t* nextArcs, size_t* nextLen);

// Exception classification for GET-family errors (RFC 2578 §8/§12):
//   true  -> noSuchInstance (query relates to a registered object,
//             instance missing)
//   false -> noSuchObject (nothing registered relates to the query)
bool mibNoSuchInstance(const uint32_t* arcs, size_t nArcs);

// Arc-wise lexicographic compare (exposed for tests / the agent core).
int mibArcCmp(const uint32_t* a, size_t an,
              const uint32_t* b, size_t bn);

// --- Standard subtrees' dynamic sources -------------------------------------
typedef struct MibSystemHooks {
  // Return hundredths-of-seconds uptime (TimeTicks value).
  uint32_t (*sysUpTime)(void);
  // Engine attributes (SNMP-FRAMEWORK-MIB). NULL hooks serve nothing.
  const uint8_t* (*engineId)(void);   size_t (*engineIdLen)(void);
  uint32_t (*engineBoots)(void);
  uint32_t (*engineTime)(void);       // seconds since boots
  uint32_t (*engineMaxMessage)(void);
  // usmStats counters (index 0..5 = UnsupportedSecLevels, NotInTimeWindows,
  // UnknownUserNames, UnknownEngineIDs, WrongDigests, DecryptionErrors).
  uint32_t (*usmStat)(size_t idx);
} MibSystemHooks;

void mibSetSystemHooks(const MibSystemHooks* hooks);
void mibSetSystemText(const char* sysDescr, const char* sysName,
                      const char* sysContact, const char* sysLocation);

#ifdef __cplusplus
}
#endif
#endif  // SNMPV3_MIB_H