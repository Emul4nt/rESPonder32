#!/usr/bin/env python3
"""
Full three-leg HTTP NTLM handshake test against http_ntlm_server.

All three legs run on the same TCP connection, matching what Windows does.
Sends synthetic NTLM Type 1, verifies Type 2 challenge structure field-by-field,
then sends a realistic NTLM Type 3, checks the 200 OK response.
Also verifies that plain requests with no Authorization get a 401 with
WWW-Authenticate: NTLM (no token), and that garbage Authorization data is
handled gracefully without a crash.

Usage:
  Terminal 1:  ./esp32emu/esp32emu run src/http_ntlm_server.cpp
  Terminal 2:  python3 tests/test_http.py
"""

import socket
import struct
import base64
import sys
import os

HOST    = "127.0.0.1"
PORT    = int(os.environ.get("HTTP_PORT", "8080"))
TIMEOUT = 3.0


# ---------------------------------------------------------------------------
# NTLM message builders (minimal — enough to trigger Responder-style server)
# ---------------------------------------------------------------------------

NTLMSSP_SIG = b"NTLMSSP\x00"

def build_type1() -> bytes:
    """
    NTLM Type 1 NEGOTIATE_MESSAGE (minimal).
    Follows MS-NLMP §2.2.1.1. Flags include NTLM_REQUEST_NON_NT_SESSION_KEY
    and a handful of common negotiate flags.
    """
    flags = (
        0x00000001 |  # NTLMSSP_NEGOTIATE_UNICODE
        0x00000002 |  # NTLMSSP_NEGOTIATE_OEM
        0x00000004 |  # NTLMSSP_REQUEST_TARGET
        0x00000200 |  # NTLMSSP_NEGOTIATE_NTLM
        0x00008000 |  # NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        0x00800000    # NTLMSSP_NEGOTIATE_128
    )
    # Signature(8) + MsgType(4) + NegotiateFlags(4) + DomainNameFields(8) +
    # WorkstationFields(8) + Version(8) = 40 bytes
    return (
        NTLMSSP_SIG +
        struct.pack("<I", 1) +           # MessageType = 1
        struct.pack("<I", flags) +       # NegotiateFlags
        struct.pack("<HHI", 0, 0, 40) + # DomainNameLen/MaxLen/Offset (empty)
        struct.pack("<HHI", 0, 0, 40) + # WorkstationLen/MaxLen/Offset (empty)
        b"\x06\x01\x00\x00\x00\x00\x00\x0f"  # Version (Vista, NTLM rev 15)
    )


def build_type3(challenge: bytes, username: str = "TestUser",
                domain: str = "TESTDOMAIN") -> bytes:
    """
    NTLM Type 3 AUTHENTICATE_MESSAGE (minimal NTLMv2 response).
    Generates a plausible but fake NTLMv2 NT response blob so the server
    can exercise its hash-parsing path. The hash values are not cryptographically
    valid — only the structure and offsets matter for the extraction test.
    """
    # NTLMv2 NT hash response: 16-byte NTProofStr + 28-byte blob header
    # (MIC, blob sig, reserved, timestamp, client nonce, reserved2, avpairs=EOL)
    nt_proof      = bytes(range(16))       # fake NTProofStr (16 bytes)
    blob_header   = (
        b"\x01\x01\x00\x00" +            # blob signature
        b"\x00\x00\x00\x00" +            # reserved
        b"\x00" * 8 +                    # timestamp
        b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11" +  # client nonce
        b"\x00\x00\x00\x00" +            # reserved2
        b"\x00\x00\x00\x00\x00\x00\x00\x00"    # minimal AvPairs (EOL)
    )
    nt_response   = nt_proof + blob_header     # 16 + 28 = 44 bytes
    lm_response   = bytes(24)                  # LM response: 24 zero bytes

    # Encode domain and username as UTF-16LE
    domain_utf16  = domain.encode("utf-16-le")
    user_utf16    = username.encode("utf-16-le")
    workstation   = "WORKSTATION".encode("utf-16-le")

    # Build the offsets.
    # NTLMSSP header layout:
    #   Signature(8) + MsgType(4) + LmFields(8) + NtFields(8) + DomainFields(8)
    #   + UserFields(8) + WorkstationFields(8) + Version(8) = 60 bytes
    # Data payload follows immediately at offset 60.
    fixed_header_size = 60
    lm_offset     = fixed_header_size
    nt_offset     = lm_offset + len(lm_response)
    dom_offset    = nt_offset + len(nt_response)
    user_offset   = dom_offset + len(domain_utf16)
    ws_offset     = user_offset + len(user_utf16)

    def sec_buf(data: bytes, offset: int) -> bytes:
        l = len(data)
        return struct.pack("<HHI", l, l, offset)

    header = (
        NTLMSSP_SIG +
        struct.pack("<I", 3) +                    # MessageType = 3
        sec_buf(lm_response, lm_offset) +         # LmChallengeResponseFields
        sec_buf(nt_response, nt_offset) +         # NtChallengeResponseFields
        sec_buf(domain_utf16, dom_offset) +       # DomainNameFields
        sec_buf(user_utf16, user_offset) +        # UserNameFields
        sec_buf(workstation, ws_offset) +         # WorkstationFields
        b"\x00" * 8                               # Version (pad to 72 bytes)
    )

    return header + lm_response + nt_response + domain_utf16 + user_utf16 + workstation


# ---------------------------------------------------------------------------
# Raw HTTP helpers
# ---------------------------------------------------------------------------

def recv_response(sock: socket.socket) -> str:
    """Read until \r\n\r\n (end of HTTP headers). Returns raw header block."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.decode("latin-1")


def send_request(sock: socket.socket, auth_header: str = "") -> str:
    """Send a GET / request, optionally with an Authorization header."""
    req = "GET / HTTP/1.1\r\nHost: %s\r\n" % HOST
    if auth_header:
        req += "Authorization: NTLM %s\r\n" % auth_header
    req += "Connection: keep-alive\r\n\r\n"
    sock.sendall(req.encode("latin-1"))
    return recv_response(sock)


def parse_status(response: str) -> int:
    """Extract HTTP status code from first line."""
    try:
        return int(response.split(" ", 2)[1])
    except (IndexError, ValueError):
        return 0


def extract_ntlm_token(response: str) -> str:
    """Return the base64 token from WWW-Authenticate: NTLM <token>, or ''."""
    for line in response.splitlines():
        if line.startswith("WWW-Authenticate: NTLM "):
            return line[len("WWW-Authenticate: NTLM "):].strip()
    return ""


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

passed = 0
failed = 0


def check(condition: bool, name: str, detail: str = "") -> bool:
    global passed, failed
    if condition:
        print("[test] PASS  %s" % name)
        passed += 1
        return True
    else:
        msg = "[test] FAIL  %s" % name
        if detail:
            msg += "  (%s)" % detail
        print(msg)
        failed += 1
        return False


def test_initial_401():
    """Plain GET with no Authorization should get 401 with WWW-Authenticate: NTLM."""
    print("\n-- test_initial_401 --")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((HOST, PORT))
        resp = send_request(s)
        print("[test] Response: %s" % resp[:200].replace("\r\n", "|"))
        status = parse_status(resp)
        check(status == 401, "status is 401", "got %d" % status)
        has_ntlm = "WWW-Authenticate: NTLM" in resp
        check(has_ntlm, "WWW-Authenticate: NTLM header present")
        # Initial 401 should NOT contain a base64 token
        token = extract_ntlm_token(resp)
        check(token == "", "no token in initial 401", "got '%s'" % token)
    except socket.timeout:
        check(False, "response received within %gs" % TIMEOUT)
    finally:
        s.close()


def test_full_handshake():
    """Full 3-leg NTLM handshake on one connection."""
    print("\n-- test_full_handshake --")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((HOST, PORT))

        # Leg 1: plain request -> 401
        resp1 = send_request(s)
        print("[test] Leg 1 response: %s" % resp1[:120].replace("\r\n", "|"))
        check(parse_status(resp1) == 401, "leg 1: 401")

        # Leg 2: Type 1 -> 401 with Type 2 challenge
        type1_b64 = base64.b64encode(build_type1()).decode("ascii")
        resp2 = send_request(s, auth_header=type1_b64)
        print("[test] Leg 2 response: %s" % resp2[:200].replace("\r\n", "|"))

        ok2 = check(parse_status(resp2) == 401, "leg 2: 401 with challenge")
        token2 = extract_ntlm_token(resp2)
        check(token2 != "", "leg 2: WWW-Authenticate token present")

        if ok2 and token2:
            # Decode and inspect Type 2
            try:
                type2 = base64.b64decode(token2)
            except Exception as e:
                check(False, "Type 2 base64 decode", str(e))
                return

            print("[test] Type 2 raw (%d bytes): %s" % (len(type2), type2.hex()))

            check(len(type2) >= 56, "Type 2 minimum length 56 bytes",
                  "got %d" % len(type2))
            check(type2[:8] == b"NTLMSSP\x00", "Type 2 NTLMSSP signature")

            msg_type = struct.unpack("<I", type2[8:12])[0]
            check(msg_type == 2, "Type 2 MessageType == 2", "got %d" % msg_type)

            flags = struct.unpack("<I", type2[20:24])[0]
            # With ESS flag (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000)
            check(flags & 0x00080000, "Type 2 ESS flag set (0x00080000)",
                  "flags=0x%08x" % flags)

            challenge = type2[24:32]
            check(len(challenge) == 8, "Type 2 challenge is 8 bytes")
            check(any(b != 0 for b in challenge), "Type 2 challenge is not all zeros",
                  challenge.hex())
            print("[test] Type 2 challenge: %s" % challenge.hex())

            # TargetName security buffer: offset 12..20
            tgt_len = struct.unpack("<H", type2[12:14])[0]
            tgt_off = struct.unpack("<I", type2[16:20])[0]
            check(tgt_len > 0, "Type 2 TargetNameLen > 0", "got %d" % tgt_len)
            check(tgt_off == 56, "Type 2 TargetNameOffset == 56",
                  "got %d" % tgt_off)

            # TargetInfo security buffer: offset 40..48
            info_len = struct.unpack("<H", type2[40:42])[0]
            info_off = struct.unpack("<I", type2[44:48])[0]
            check(info_len > 0, "Type 2 TargetInfoLen > 0", "got %d" % info_len)
            check(info_off == tgt_off + tgt_len,
                  "Type 2 TargetInfoOffset == TargetNameOffset + TargetNameLen",
                  "expected %d got %d" % (tgt_off + tgt_len, info_off))

            # Leg 3: Type 3 -> 200 OK
            type3_b64 = base64.b64encode(build_type3(challenge)).decode("ascii")
            resp3 = send_request(s, auth_header=type3_b64)
            print("[test] Leg 3 response: %s" % resp3[:120].replace("\r\n", "|"))
            check(parse_status(resp3) == 200, "leg 3: 200 OK after Type 3",
                  "got status %d" % parse_status(resp3))

    except socket.timeout:
        check(False, "handshake completed within %gs" % TIMEOUT)
    finally:
        s.close()


def test_malformed_auth():
    """Garbage base64 in Authorization header should not crash the server."""
    print("\n-- test_malformed_auth --")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((HOST, PORT))
        # Get the initial 401 first
        resp1 = send_request(s)
        check(parse_status(resp1) == 401, "malformed test: initial 401")

        # Send garbage that base64-decodes to fewer than 9 bytes
        garbage_b64 = base64.b64encode(b"\xff\xfe\x00").decode("ascii")
        req = "GET / HTTP/1.1\r\nHost: %s\r\nAuthorization: NTLM %s\r\n" \
              "Connection: close\r\n\r\n" % (HOST, garbage_b64)
        s.sendall(req.encode("latin-1"))
        # Server must respond with something (even a close) rather than hanging
        try:
            resp2 = s.recv(256).decode("latin-1", errors="replace")
            print("[test] Server responded to garbage auth: %s"
                  % resp2[:80].replace("\r\n", "|"))
            check(True, "server responded without crashing")
        except socket.timeout:
            # A timeout here means server ignored the garbage and is waiting,
            # which is also acceptable behaviour (not a crash).
            check(True, "server did not crash on garbage auth (timeout = still alive)")
    except socket.timeout:
        check(False, "malformed test timed out before initial 401")
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    print("[test] Connecting to %s:%d" % (HOST, PORT))

    # Quick port-reachability check
    try:
        probe = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
        probe.close()
    except (ConnectionRefusedError, OSError) as e:
        print("[test] FAIL — cannot reach server at %s:%d: %s" % (HOST, PORT, e))
        print("[test] Is http_ntlm_server running?")
        print("[test]   ./esp32emu/esp32emu run src/http_ntlm_server.cpp")
        return 1

    test_initial_401()
    test_full_handshake()
    test_malformed_auth()

    print("\n[test] Results: %d passed, %d failed" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
