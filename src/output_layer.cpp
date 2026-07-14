// rESPonder32 — Step 7: Output Layer
//
// Defines the shared hash store used by all capture modules (SMB, HTTP NTLM).
// Other modules call addCapturedHash() to record a hash; this sketch also runs
// a WebServer on port 8080 so you can pull the list over HTTP without root.
//
// Interface (what SMB and HTTP modules call):
//   void addCapturedHash(const char* hashStr)  — store + Serial print
//   int  getCapturedHashCount()                 — current count
//   const char* getCapturedHash(int idx)        — pointer into stored String
//
// WebServer routes:
//   GET /        -> 200 text/plain, banner message
//   GET /hashes  -> 200 text/plain, one hashcat-format hash per line
//
// Demo mode: loop() adds a fake hash every 10 seconds so the interface can be
// exercised without a live Windows client.
//
// Build & run (emulator):
//   cd /home/machine/projects/rESPonder32 && ./esp32emu/esp32emu run src/output_layer.cpp
//
// On real ESP32: same file, Arduino IDE or PlatformIO, set WIFI_SSID/PASS.

#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

static const char*    WIFI_SSID   = "YourSSID";
static const char*    WIFI_PASS   = "YourPassword";
static const uint16_t WEB_PORT    = 8080;

static const char* DEMO_HASH =
    "DemoUser::WORKGROUP:0102030405060708:"
    "aabbccdd112233440102030405060708aabbccdd11223344:"
    "0506070801020304";

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

static std::vector<String> g_capturedHashes;
static WebServer           g_server(WEB_PORT);
static uint8_t             ourIP[4] = {127, 0, 0, 1};
static unsigned long       g_lastDemoMs = 0;

// ---------------------------------------------------------------------------
// Helpers
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
// Public interface (called by SMB server and HTTP NTLM server)
// ---------------------------------------------------------------------------

void addCapturedHash(const char* hashStr) {
    g_capturedHashes.push_back(String(hashStr));
    Serial.printf("[OUTPUT] Captured hash #%d: %s\n",
                  (int)g_capturedHashes.size(), hashStr);
}

int getCapturedHashCount() {
    return (int)g_capturedHashes.size();
}

// Returns a raw pointer into the stored String — valid until the vector
// reallocates. Callers must copy if they need to store it.
const char* getCapturedHash(int idx) {
    if (idx < 0 || idx >= (int)g_capturedHashes.size()) return nullptr;
    return g_capturedHashes[idx].c_str();
}

// ---------------------------------------------------------------------------
// WebServer route handlers
// ---------------------------------------------------------------------------

static void handleRoot() {
    g_server.send(200, "text/plain",
                  "rESPonder32 - use /hashes for captured hashes\n");
}

static void handleHashes() {
    String body;
    for (const String& h : g_capturedHashes) {
        body += h;
        body += '\n';
    }
    // Empty store still returns 200 with an empty body — callers can count lines.
    g_server.send(200, "text/plain", body);
}

static void handleNotFound() {
    g_server.send(404, "text/plain", "Not found\n");
}

// ---------------------------------------------------------------------------
// Arduino entry points
// ---------------------------------------------------------------------------

void setup() {
    Serial.begin(115200);
    Serial.println("\n[rESPonder32] Output Layer v0.1");

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

    g_server.on("/",       HTTP_GET, handleRoot);
    g_server.on("/hashes", HTTP_GET, handleHashes);
    g_server.onNotFound(handleNotFound);
    g_server.begin();

    Serial.printf("[OUTPUT] WebServer listening on port %u\n", WEB_PORT);
    Serial.printf("[OUTPUT] GET http://%d.%d.%d.%d:%u/hashes\n",
                  ourIP[0], ourIP[1], ourIP[2], ourIP[3], WEB_PORT);

    // Seed one placeholder so the endpoint is non-empty from the start.
    addCapturedHash(DEMO_HASH);

    g_lastDemoMs = millis();
}

void loop() {
    g_server.handleClient();

    // Add a fresh demo hash every 10 seconds so the store visibly grows.
    if (millis() - g_lastDemoMs >= 10000) {
        g_lastDemoMs = millis();
        addCapturedHash(DEMO_HASH);
        Serial.printf("[OUTPUT] Hash store now has %d entries\n",
                      getCapturedHashCount());
    }
}
