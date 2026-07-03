#include <SNMPv3.h>

// Example OID handler for a simple read-only object (e.g., sysDescr.0 = 1.3.6.1.2.1.1.1.0)
int getSysDescr(uint8_t* value, size_t* len) {
  const char* str = "ESP32 SNMPv3 Agent";
  *len = strlen(str);
  memcpy(value, str, *len);
  return 0; // success
}

// Example OID handler for a simple read-write object (e.g., a counter)
uint8_t counterValue = 0;
int getCounter(uint8_t* value, size_t* len) {
  *len = 1;
  value[0] = counterValue;
  return 0;
}
int setCounter(uint8_t* value, size_t len) {
  if (len != 1) return -1;
  counterValue = value[0];
  return 0;
}

// SNMPv3 agent instance
SNMPv3Agent agent;

// Engine ID (should be unique, typically 10+ bytes)
uint8_t engineId[] = {0x80, 0x00, 0x1f, 0x88, 0x80, 0x7f, 0x01, 0x02, 0x03, 0x04};
// User name
const char* userName = "initial";
// Authentication key (HMAC-SHA1, 20 bytes)
uint8_t authKey[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                     0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13};
// Privacy key (AES-128, 16 bytes)
uint8_t privKey[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                     0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

void setup() {
  Serial.begin(115200);
  // Wait for serial to initialize
  while (!Serial) { delay(10); }
  Serial.println("Starting SNMPv3 Agent...");

  // Initialize the agent on UDP port 161
  if (!agent.begin(161, (const char*)engineId, userName, authKey, sizeof(authKey), privKey, sizeof(privKey))) {
    Serial.println("Failed to initialize SNMPv3 agent");
    while (true) { delay(1000); }
  }

  // Add objects (OIDs)
  // sysDescr.0 = 1.3.6.1.2.1.1.1.0
  uint8_t oidSysDescr[] = {1,3,6,1,2,1,1,1,0};
  agent.addObject(oidSysDescr, sizeof(oidSysDescr), getSysDescr, nullptr);

  // A custom counter: 1.3.6.1.4.1.99999.1.0 (enterprise specific)
  uint8_t oidCounter[] = {1,3,6,1,4,1,99999,1,0};
  agent.addObject(oidCounter, sizeof(oidCounter), getCounter, setCounter);

  Serial.println("SNMPv3 agent initialized");
}

void loop() {
  agent.loop();
  delay(10); // small delay to prevent watchdog trigger
}