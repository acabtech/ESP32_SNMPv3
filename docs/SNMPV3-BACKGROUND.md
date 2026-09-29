# SNMPv3 in 10 minutes (background)

A short, no-jargon primer written for reviewers, customers, and the capstone
deck. The authority is RFC 3411–3416.

## Why SNMPv3 instead of "community string" SNMP

SNMPv1/v2c protect access with a *community string* — effectively a shared
password sent **in plaintext on the wire** with every request. On any
snoopable network, that's no security at all. SNMPv3 keeps the same
request/response model but adds the **User-based Security Model (USM)**:

- **Authentication** — every message carries an HMAC; integrity +
  origin authenticity. v0.1 uses HMAC-SHA-256 (RFC 7860).
- **Privacy** — PDU payloads are encrypted (v0.1: AES-128 CFB, RFC 3826).
- **Timeliness / replay protection** — engineBoots/engineTime +
  message-ID checks stop captured traffic from being replayed.

An `authPriv` SNMPv3 message is *both* authenticated *and* encrypted. That's
the only mode this library implements.

## The players

| Role | What it does | Example |
|------|--------------|---------|
| **Manager** (NMS) | Polls agents, receives notifications | Zabbix, Home Assistant, PRTG, net-snmp |
| **Agent** | Lives on the *managed device*; answers polls, sends traps | this library, on the ESP32 |
| **USM user** | A named principal with auth + priv passphrases | `telemetry` in the examples |

## The conversation (agent discovery in 3 steps)

1. The manager doesn't know the device yet → it sends its first request with
   empty security parameters.
2. The device answers a `report` PDU saying *"here's my engineID, boots and
   time"* (this exchange is unauthenticated — it's the protocol's doorbell,
   not a security level; nothing sensitive is exchanged).
3. The manager now derives *localized keys* from your passphrases
   + the device's engineID, and everything after is full authPriv.

The same dance happens automatically for Zabbix and Home Assistant — that's
why their config screens ask for username/passphrases and just work.

## Why the ESP32 family is a good fit

- All three chips (classic ESP32, S2, S3) carry **hardware SHA-1/SHA-256 and
  AES engines**; ESP-IDF's mbedtls layer uses them transparently, so HMAC
  and AES cost microseconds, not milliseconds.
- The Arduino core keeps the UX identical across the family — one library,
  three targets, one `loop()`.
- Auxiliary requirements (Wi-Fi, NVS flash for boots counters, UDP stack)
  are all first-class in the SDK.

## Costs / constraints you should know

- USM keys are *localized per engine* — re-pairing a device (new engineID)
  silently invalidates configured users until managers re-learn.
- `engineBoots` must persist across reboots (NVS) or NMS caches reject the
  node as "not in time window". This library handles it; plain "hello world"
  SNMPv3 ports usually get this wrong.
- The agent holds one request at a time in a fixed buffer — by design for a
  microcontroller. Enough for a sensor node; not a general-purpose NMS box.