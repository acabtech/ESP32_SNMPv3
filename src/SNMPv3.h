#ifndef SNMPv3_h
#define SNMPv3_h

#include <Arduino.h>
#include <WiFiUdp.h>
#include "mbedtls/md.h"
#include "mbedtls/aes.h"

#define MAX_OIDS 10
#define OID_MAX_LEN 16
#define SNMPv3_PACKET_SIZE 480

typedef struct {
  uint8_t oid[OID_MAX_LEN];
  size_t oidLen;
  int (*getHandler)(uint8_t*, size_t*); // returns value length, fills buffer
  int (*setHandler)(uint8_t*, size_t);  // returns 0 on success
} SNMPv3Object;

class SNMPv3Agent {
  public:
    SNMPv3Agent();
    ~SNMPv3Agent();

    // Initialize agent: set UDP port, engine ID, user, authKey, privKey
    // engineId: typically 10 bytes (enterprise specific)
    // userName: null-terminated string
    // authKey: HMAC-SHA1 key (20 bytes for SHA1)
    // privKey: AES key (16 bytes for AES-128)
    bool begin(uint16_t port, const char* engineId, const char* userName, 
               const uint8_t* authKey, size_t authKeyLen,
               const uint8_t* privKey, size_t privKeyLen);

    // Add an object (OID) with get and set handlers
    bool addObject(const uint8_t* oid, size_t oidLen, 
                   int (*getHandler)(uint8_t*, size_t*),
                   int (*setHandler)(uint8_t*, size_t));

    // Main loop to process incoming packets
    void loop();

  private:
    WiFiUdp udp;
    uint16_t localPort;
    char* engineId_;
    char* userName_;
    unsigned char authKey_[32]; // max 20 for SHA1, but we allow up to 32
    unsigned char privKey_[32]; // max 16 for AES-128, but we allow up to 32
    size_t authKeyLen_;
    size_t privKeyLen_;
    SNMPv3Object objects_[MAX_OIDS];
    size_t numObjects_;

    // Internal functions for SNMPv3 processing
    bool processPacket(uint8_t* packet, size_t len, IPAddress remoteIP, uint16_t remotePort);
    bool parseSNMPv3Message(uint8_t* msg, size_t msgLen,
                            uint8_t* version, uint32_t* msgID, uint8_t* msgFlags, uint32_t* msgSecurityModel,
                            uint8_t** securityParams, size_t* securityParamsLen,
                            uint8_t** scopedPDU, size_t* scopedPDULen);
    bool authenticateAndDecrypt(uint8_t* msg, size_t msgLen,
                                uint8_t* securityParams, size_t securityParamsLen,
                                uint8_t* scopedPDU, size_t scopedPDULen,
                                uint8_t* authKey, size_t authKeyLen,
                                uint8_t* privKey, size_t privKeyLen,
                                uint8_t* decryptedPDU, size_t* decryptedPDULen);
    bool encryptAndAuthenticate(uint8_t* plaintext, size_t plaintextLen,
                                uint8_t* encrypted, size_t* encryptedLen,
                                uint8_t* authKey, size_t authKeyLen,
                                uint8_t* privKey, size_t privKeyLen,
                                uint8_t* salt, size_t saltLen);
    // BER encoding/decoding helpers for SNMPv3
    int berDecodeLength(uint8_t** data, size_t* len);
    int berDecodeTag(uint8_t** data, size_t* len, uint8_t* tag);
    int berEncodeLength(uint8_t** data, size_t len);
    int berEncodeTag(uint8_t** data, size_t len, uint8_t tag);
    // Simple OID lookup
    SNMPv3Object* findObject(const uint8_t* oid, size_t oidLen);
};

#endif