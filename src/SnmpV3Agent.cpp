// SnmpV3Agent.cpp — M0 scaffold stub implementation.
//
// Every method is a documented TODO returning a safe default so that the
// library (and the example sketches) COMPILE from day one. The public
// contract in SnmpV3Agent.h is final for v0.1; bodies are replaced as the
// BER / USM / MIB core lands (docs/ROADMAP.md, M1 → M3).
//
// SPDX-License-Identifier: GPL-3.0
#include "SnmpV3Agent.h"

class SnmpV3AgentImpl;  // TODO(M1)

static SnmpV3Agent s_instance;  // backing store for the SNMPv3 singleton

bool SnmpV3Agent::begin(uint16_t agentPort) {
  (void)agentPort;
  // TODO(M1): engine ID from MAC, NVS boots/time, open UDP :161.
  return false;  // M0 scaffold — no agent yet
}

void SnmpV3Agent::loop() {
  // TODO(M2): non-blocking socket pump + request dispatch.
}

bool SnmpV3Agent::addUser(const char* username,
                          const char* authPassphrase,
                          const char* privPassphrase) {
  (void)username; (void)authPassphrase; (void)privPassphrase;
  // TODO(M1): RFC 3414 key localization (SHA-256 + AES-128 only).
  return false;
}

bool SnmpV3Agent::setEngineId(const char* engineIdHex) {
  (void)engineIdHex;
  // TODO(M1): hex parse + RFC 3411 §4 validation.
  return false;
}

bool SnmpV3Agent::registerScalar(const char* oid, int32_t (*getter)(void)) {
  (void)oid; (void)getter;
  // TODO(M2): parse OID, insert into MIB tree.
  return false;
}

bool SnmpV3Agent::registerScalar(const char* oid,
                                 int32_t (*getter)(void),
                                 bool (*setter)(int32_t value)) {
  (void)oid; (void)getter; (void)setter;
  // TODO(M2): parse OID, insert RW node.
  return false;
}

bool SnmpV3Agent::registerTable(const char* baseOid,
                                size_t (*rows)(void),
                                int32_t (*cell)(size_t row, size_t col)) {
  (void)baseOid; (void)rows; (void)cell;
  // TODO(M2): columnar table node + row instance mapping.
  return false;  // EXPERIMENTAL
}

void SnmpV3Agent::setTrapManager(IPAddress ip, uint16_t port) {
  (void)ip; (void)port;
  // TODO(M3): notification target.
}

bool SnmpV3Agent::sendTrap(const char* oid, uint32_t instance) {
  (void)oid; (void)instance;
  // TODO(M3): v3 trap on UDP :162, authPriv.
  return false;
}

bool SnmpV3Agent::sendInform(const char* oid, uint32_t instance) {
  (void)oid; (void)instance;
  // TODO(M3): v3 inform with response wait + retries (RFC 3416).
  return false;
}

uint32_t SnmpV3Agent::engineBoots() { return 0; /* TODO(M1) */ }
uint8_t  SnmpV3Agent::engineIdLen() { return 0; /* TODO(M1) */ }
uint8_t  SnmpV3Agent::state()       { return 0; /* TODO(M1) */ }
bool     SnmpV3Agent::connected()   { return false; /* TODO(M1) */ }

// Singleton instance (see header).
SnmpV3Agent SNMPv3;