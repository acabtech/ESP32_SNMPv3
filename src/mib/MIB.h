// MIB.h — managed-object tree for the agent (M0 scaffold).
//
// Scope for v0.1:
//   • SNMPv2-MIB subset (sysDescr, sysUpTime, sysContact, sysName, sysLocation)
//   • SNMP-FRAMEWORK-MIB / SNMPv3-MIB subset (snmpEngineID, snmpEngineBoots,
//     snmpEngineTime, snmpEngineMaxMessageSize, snmpEngineMaxStackPhytes? — see RFC 3411)
//   • Application subtrees (registered by the sketch via SnmpV3Agent)
//
// Host-compilable: no Arduino types here (unit-testable on PC).
//
// SPDX-License-Identifier: GPL-3.0
#ifndef SNMPV3_MIB_H
#define SNMPV3_MIB_H

#include <stdint.h>
#include <stddef.h>

// --- Node & value model ----------------------------------------------------
typedef int32_t (*MibGetter)(void);
typedef bool    (*MibSetter)(int32_t value);
typedef int32_t (*MibCell)(size_t row, size_t col);

typedef enum {
  MIB_NODE_SCALAR,        // leaf, read-only
  MIB_NODE_SCALAR_RW,     // leaf, settable
  MIB_NODE_TABLE_COLUMN,  // columnar leaf under a table row
  MIB_NODE_ROW_INDEX,     // implicit: <.1> of each row
} MibNodeKind;

typedef struct MibNode {
  struct MibNode* children[16];   // fixed fan-out (indexed by next arc); 0 = absent
  const uint32_t* oid;            // full dotted vector of this node (canonical)
  size_t          oidLen;
  MibNodeKind     kind;
  MibGetter       getter;         // scalar
  MibSetter       setter;         // RW
  MibCell         cell;           // table column
  size_t          tableArcs;      // arcs consumed after the table base OID
} MibNode;

// --- Registry API (backed by a shared static tree in the agent process) ----
int mibRegisterScalar(const char* dottedOid, MibGetter get);
int mibRegisterScalarRW(const char* dottedOid, MibGetter get, MibSetter set);
int mibRegisterTable(const char* dottedBaseOid, MibCell cell);

// --- Resolution ------------------------------------------------------------
// Resolve a request OID to the deepest registered node.
//   exact   : true if the OID terminated exactly on the node
//   instance: vector of remaining arcs (row/column instance), or 0
// Returns 1 on hit, 0 on noSuchObject (→ nextOid semantics), -1 on error.
int mibResolve(const uint32_t* oid, size_t nArcs,
               const MibNode** node, bool* exact,
               uint32_t* instance, size_t* nInstance);

// --- System values (SNMPv2-MIB, wired at agent start) ----------------------
void mibSetSystem(const char* sysDescr, const char* sysName,
                  const char* sysContact, const char* sysLocation);
uint32_t mibSysUpTimeSeconds();   // derived from millis()

#endif  // SNMPV3_MIB_H