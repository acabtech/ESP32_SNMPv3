# ESP32_SNMPv3
SNMP version 3 library for ESP32 and ESP32-S3 using LwIP and crypto stack

This library provides a basic framework for an SNMPv3 agent on ESP32 and ESP32-S3, 
using the mbedtls cryptographic libraries included in the ESP-IDF (via Arduino core).

## Features
- Agent-only SNMPv3
- Supports GetRequest and SetRequest PDUs
- USM (User-based Security Model) with authPriv (HMAC-SHA1 + AES-128)
- Designed for Arduino IDE and PlatformIO compatibility

## Dependencies
- Arduino core for ESP32 (which includes mbedtls crypto and WiFiUdp)
- The library includes `Arduino.h`, `WiFiUdp.h`, `mbedtls/md.h`, and `mbedtls/aes.h`

## Installation
### Arduino IDE
1. Download the ZIP of this repository.
2. In Arduino IDE: Sketch > Include Library > Add .ZIP Library...
3. Select the downloaded ZIP.

### PlatformIO
1. Copy the library to your `lib/` directory in your PlatformIO project.
2. Or install via `pio lib install` if you publish it to the registry.

## Usage
See `example.ino` for a complete example.

### Basic Steps
1. Include the library: `#include <SNMPv3.h>`
2. Create an instance: `SNMPv3Agent agent;`
3. In `setup()`:
   - Define engine ID (unique, typically 10+ bytes)
   - Define user name
   - Define authentication key (HMAC-SHA1, 20 bytes)
   - Define privacy key (AES-128, 16 bytes)
   - Call `agent.begin(port, engineId, userName, authKey, authKeyLen, privKey, privKeyLen);`
   - Add OIDs with `agent.addObject(oid, oidLen, getHandler, setHandler);`
4. In `loop()`: call `agent.loop();`

## Important Note
This library provides the framework for SNMPv3 packet processing, but the core cryptographic functions 
(authentication, encryption, decryption) and BER encoding/decoding are currently stubbed out.
To make a fully functional SNMPv3 agent, you must implement the following private methods in `SNMPv3.cpp`:
- `parseSNMPv3Message`
- `authenticateAndDecrypt`
- `encryptAndAuthenticate`
- BER helper functions (`berDecodeLength`, `berDecodeTag`, `berEncodeLength`, `berEncodeTag`)
- `processPacket` (to handle the parsed PDU and build a response)

The example in `example.ino` shows how to set up the agent and add simple OID handlers.

## License
This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.
