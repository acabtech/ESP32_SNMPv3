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

// --- v3 notifications: traps / informs (M3) --------------------------------
// Standard notification varbind OIDs (RFC 3416 §4.2.6):
//   sysUpTime.0   = 1.3.6.1.2.1.1.3.0
//   snmpTrapOID.0 = 1.3.6.1.6.3.1.1.4.1.0
// A notification's varbind list is [sysUpTime.0, snmpTrapOID.0, trapOid=value].

// Inform retry policy (RFC 3416 §3.2.5, docs/ROADMAP.md M3):
//   max 3 retries within a 5 s total budget -> 4 attempts, 1250 ms each.
#define AGENT_INFORM_MAX_RETRIES 3
#define AGENT_INFORM_TOTAL_MS    5000u
#define AGENT_INFORM_ATTEMPT_MS \
  (AGENT_INFORM_TOTAL_MS / (AGENT_INFORM_MAX_RETRIES + 1))

// Find a user by name; NULL when absent.
AgentUser* agentFindUser(AgentState* s, const char* name);

// Build a v3 notification message (Trap or Inform) for `trapOid`, authPriv,
// as `user`. `pduTag` = BER_TAG_TRAP_V2 (fire-and-forget) or
// BER_TAG_INFORM_REQ (acknowledged). The engine clock is refreshed from
// `nowMs`; `uptimeTicks` is the agent's sysUpTime in hundredths of seconds.
// Returns 0 and sets *outLen, or negative on error.
int agentBuildNotification(AgentState* s, const AgentUser* user,
                           uint8_t pduTag, uint32_t msgId, uint32_t reqId,
                           const uint32_t* trapOid, size_t trapOidLen,
                           uint32_t uptimeTicks, uint32_t nowMs,
                           uint8_t* out, size_t cap, size_t* outLen);

// --- inform retry state machine (non-blocking, tick-driven) ----------------
typedef struct {
  bool     active;
  uint8_t  msg[AGENT_MAX_MSG];   // the built inform datagram (re-sent verbatim)
  size_t   msgLen;
  uint32_t msgId;
  uint32_t reqId;
  uint32_t startMs;              // when the inform began (budget anchor)
  uint32_t sentMs;               // when the current attempt was sent
  uint8_t  attempts;             // sends so far (1 = initial)
} AgentInform;

// Arm the state machine with a built message (attempts = 1, sent now).
void agentInformStart(AgentInform* inf, const uint8_t* msg, size_t msgLen,
                      uint32_t msgId, uint32_t reqId, uint32_t nowMs);

// Drive retries. Returns 1 = (re)send inf->msg now, 0 = keep waiting,
// -1 = give up (budget exhausted). Clears `active` on -1.
int agentInformTick(AgentInform* inf, uint32_t nowMs);

// Verify a manager response against a pending inform: envelope + engineID +
// user + MAC + decrypt + Response PDU with a matching request-id.
// Returns 1 = acknowledged (clears `active`), 0 = no match / not an ack.
int agentInformAck(AgentInform* inf, AgentState* s, const AgentUser* user,
                   const uint8_t* resp, size_t respLen);

#ifdef __cplusplus
}
#endif
#endif  // SNMPV3_AGENTCORE_H