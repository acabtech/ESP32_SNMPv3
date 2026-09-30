// AgentCore.h — SNMPv3 agent request-processing core (M2).
//
// Pure C, host-compilable (no Arduino/ESP-IDF includes). The Arduino layer
// (SnmpV3Agent.cpp) owns the UDP socket, the ms clock source and NVS
// persistence, and feeds datagrams to agentProcess(); the core owns all
// protocol logic:
//
//   request  ->  envelope decode
//            ->  USM security gate (level / engineID / user / timeliness /
//                MAC / decrypt) with RFC 3414 §4 discovery Reports
//            ->  scopedPDU + PDU decode
//            ->  MIB dispatch (Get / GetNext / GetBulk / Set)
//            ->  response build (mirror the request's security level),
//                MAC over the zeroed-authParams message, CFB encryption
//
// Determinism: outgoing privParams salts come from an internal counter
// (RFC 3826 uniqueness); tests seed it for byte-exact oracles.
//
// SPDX-License-Identifier: GPL-3.0
#ifndef SNMPV3_AGENTCORE_H
#define SNMPV3_AGENTCORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "../usm/USM.h"
#include "../usm/store.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AGENT_MAX_USERS     4
#define AGENT_NAME_MAX      32
#define AGENT_REPLAY_CACHE  32   // docs/DESIGN.md: 32-entry msgID ring
#define AGENT_MAX_MSG       1500   // our msgMaxSize (UDP datagram budget)

typedef struct {
  char     name[AGENT_NAME_MAX];         // NUL-terminated USM user name
  size_t   nameLen;
  uint8_t  authKey[SNMPV3_SHA256_KEY];   // localized with the engine ID
  uint8_t  privKey[SNMPV3_AES128_KEY];
} AgentUser;

typedef struct {
  // --- authoritative engine (RFC 3411/3414) ---
  uint8_t  engineId[32];
  size_t   engineIdLen;
  UsmEngineClock clock;                 // boots + time + monotonic anchor
  uint32_t maxMessageSize;              // snmpEngineMaxMessageSize
  uint64_t saltCounter;                 // outgoing priv salt (unique per msg)

  // --- users ---
  AgentUser users[AGENT_MAX_USERS];
  size_t   nUsers;

  // --- usmStats counters (index = MIB usmStats leaf index) ---
  uint32_t stats[6];

  // --- replay cache: (msgId, userIdx) seen recently ---
  struct { uint32_t msgId; size_t userIdx; bool used; } seen[AGENT_REPLAY_CACHE];
  size_t   seenCursor;
} AgentState;

// One-time init. `nowMs` seeds the engine-time anchor; boots must already be
// incremented by the caller (from the store) per RFC 3414 §2.3.
void agentInit(AgentState* s,
               const uint8_t* engineId, size_t engineIdLen,
               uint32_t boots, uint32_t nowMs, uint32_t maxMessageSize);

// Add a user whose keys are ALREADY localized with the engine ID (the
// Arduino layer localizes at addUser() time). Returns user index or -1.
int agentAddUser(AgentState* s, const char* name,
                 const uint8_t* authKey, const uint8_t* privKey);

typedef enum {
  AGENT_RESPONSE    = 1,   // *outLen bytes to send back
  AGENT_NO_RESPONSE = 0,   // drop silently
  AGENT_ERR_DROP    = -1   // malformed / unprocessable (drop)
} AgentResult;

// Process one request datagram. `nowMs` = current monotonic ms (clock source
// is injected so the core stays host-testable). Returns AGENT_* and writes
// the response datagram to out/outLen. `out` must hold >= AGENT_MAX_MSG.
int agentProcess(AgentState* s, const uint8_t* in, size_t inLen,
                 uint32_t nowMs, uint8_t* out, size_t cap, size_t* outLen);

#ifdef __cplusplus
}
#endif
#endif  // SNMPV3_AGENTCORE_H