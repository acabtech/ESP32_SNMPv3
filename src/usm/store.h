// store.h — agent persistence seam (engine boots / engine ID).
//
// The authoritative engine state MUST survive reboots (RFC 3414 §2.2.2:
// snmpEngineBoots is persistent; losing it would let clock skew break
// timeliness windows). This header is the only persistence contract the
// host-testable core sees, so tests can inject a RAM store while the ESP32
// build wires it to NVS (store_esp32.c).
//
// SPDX-License-Identifier: GPL-3.0
#ifndef SNMPV3_STORE_H
#define SNMPV3_STORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  // Load the persisted boot counter. Return false when nothing is stored
  // (first boot) or the backing store is unavailable — the agent then
  // treats boots as 0 and increments it to 1 itself.
  bool (*loadBoots)(uint32_t* boots);
  // Persist the boot counter. Called after every increment (i.e., once per
  // boot, not per request). Return false to signal a failing store; the
  // agent still runs (with an unreliable RFC timeliness story) but state()
  // reports the degraded condition.
  bool (*saveBoots)(uint32_t boots);
} AgentStore;

#ifdef __cplusplus
}
#endif
#endif  // SNMPV3_STORE_H
