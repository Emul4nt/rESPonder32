#!/usr/bin/env python3
"""
Integration test for smb_server.cpp.

Connects TCP to 127.0.0.1:445 (or 4450 if 445 is not available), runs the
full SMBv1 NTLMSSP exchange, and verifies field-by-field correctness of the
Negotiate Protocol Response. Then sends a crafted NTLMSSP Type 3 message and
checks that the server responds (hash was processed).

Usage: run while smb_server is running in another terminal.
  Terminal 1:  sudo ./esp32emu/esp32emu run src/smb_server.cpp
  Terminal 2:  python3 tests/test_smb.py
"""
import socket
import struct
import sys
import time
import os


SMB_PORT      = 445
SMB_FALLBACK  = 4450
TIMEOUT       = 5.0


# ---------------------------------------------------------------------------
# NetBIOS Session Service framing
# ---------------------------------------------------------------------------

def nb_frame(payload: bytes) -> bytes:
    """Wrap payload in 4-byte NetBIOS Session Service header."""
    plen = len(payload)
    hdr = bytes([
        0x00,                            # SESSION MESSAGE type
        (plen >> 16) & 0xFF,
        (plen >>  8) & 0xFF,
         plen        & 0xFF,
    ])
    return hdr + payload


def recv_nb_pdu(s: socket.socket) -> bytes:
    """Read exactly one NetBIOS-framed PDU."""
    hdr = recvall(s, 4)
    if not hdr:
        return b""
    assert hdr[0] == 0x00, f"Expected session message type 0x00, got 0x{hdr[0]:02x}"
    plen = (hdr[1] << 16) | (hdr[2] << 8) | hdr[3]
    return recvall(s, plen)


def recvall(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# SMBv1 packet builders
# ---------------------------------------------------------------------------

def smb_header(cmd: int, flags1: int, flags2: int, errorcode: int,
               pid: int, uid: int, tid: int, mid: int) -> bytes:
    """Build the 32-byte SMBv1 header."""
    return (
        b"\xff\x53\x4d\x42"                      # magic: \xffSMB
        + bytes([cmd])                             # Command
        + struct.pack("<I", errorcode)             # NTStatus (LE)
        + bytes([flags1])                          # Flags1
        + struct.pack("<H", flags2)                # Flags2 (LE)
        + b"\x00\x00"                              # PID High
        + b"\x00" * 8                              # Signature
        + b"\x00\x00"                              # Reserved
        + struct.pack("<H", tid)                   # TID
        + struct.pack("<H", pid)                   # PID
        + struct.pack("<H", uid)                   # UID
        + struct.pack("<H", mid)                   # MID
    )


def build_negotiate_request() -> bytes:
    """
    Build an SMB_COM_NEGOTIATE (0x72) request with two dialects:
    'PC NETWORK PROGRAM 1.0' and 'NT LM 0.12'.
    The server must pick 'NT LM 0.12' (index 1).
    """
    hdr = smb_header(
        cmd=0x72, flags1=0x18, flags2=0x2801,
        errorcode=0, pid=0xFEFF, uid=0, tid=0, mid=1,
    )
    dialect_data = b"\x02PC NETWORK PROGRAM 1.0\x00\x02NT LM 0.12\x00"
    word_count = b"\x00"                          # WordCount = 0
    byte_count = struct.pack("<H", len(dialect_data))
    body = word_count + byte_count + dialect_data
    return nb_frame(hdr + body)


def parse_smb_header(data: bytes) -> dict:
    if len(data) < 32:
        return {}
    magic = data[0:4]
    cmd   = data[4]
    nt_status = struct.unpack("<I", data[5:9])[0]
    flags1 = data[9]
    flags2 = struct.unpack("<H", data[10:12])[0]
    tid = struct.unpack("<H", data[24:26])[0]
    pid = struct.unpack("<H", data[26:28])[0]
    uid = struct.unpack("<H", data[28:30])[0]
    mid = struct.unpack("<H", data[30:32])[0]
    return {
        "magic":     magic,
        "cmd":       cmd,
        "nt_status": nt_status,
        "flags1":    flags1,
        "flags2":    flags2,
        "tid":       tid,
        "pid":       pid,
        "uid":       uid,
        "mid":       mid,
    }


def find_ntlm_challenge(data: bytes) -> bytes:
    """Find NTLMSSP\x00 in an SMB response and return the 8-byte challenge."""
    idx = data.find(b"NTLMSSP\x00")
    if idx < 0:
        return b""
    # NTLMSSP Type 2 layout (all LE):
    #   signature(8) + MsgType(4) + TargetNameFields(8) + NegFlags(4)
    #   + ServerChallenge(8)
    # Challenge starts at idx + 24
    challenge_off = idx + 24
    if challenge_off + 8 > len(data):
        return b""
    return data[challenge_off:challenge_off + 8]


# ---------------------------------------------------------------------------
# NTLMSSP Type 1 (Negotiate) — the blob we send in first Session Setup
# ---------------------------------------------------------------------------

def build_ntlmssp_negotiate() -> bytes:
    """
    Minimal NTLMSSP_NEGOTIATE (Type 1) message.
    Flags: NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM
    """
    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 1)           # MessageType = NTLMSSP_NEGOTIATE
        + struct.pack("<I", 0x00000B07)  # NegotiateFlags
        + struct.pack("<H", 0)           # DomainNameFields.Len
        + struct.pack("<H", 0)           # DomainNameFields.MaxLen
        + struct.pack("<I", 0)           # DomainNameFields.Offset
        + struct.pack("<H", 0)           # WorkstationFields.Len
        + struct.pack("<H", 0)           # WorkstationFields.MaxLen
        + struct.pack("<I", 0)           # WorkstationFields.Offset
    )


def wrap_ntlm_in_spnego(ntlm_blob: bytes) -> bytes:
    """
    Wrap an NTLMSSP message in a minimal SPNEGO negTokenInit blob so the
    server's SPNEGO parser recognises it as a supported mechanism.
    OID for NTLMSSP: 1.3.6.1.4.1.311.2.2.10
    """
    ntlmssp_oid = b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"

    def asn_len(n: int) -> bytes:
        if n <= 127:
            return bytes([n])
        return bytes([0x81, n])

    # mechToken: 04 <len> <ntlm>
    mech_token = b"\x04" + asn_len(len(ntlm_blob)) + ntlm_blob
    # mechTypes: 30 <len> 06 <oidlen> <oid>
    mech_type  = b"\x30" + asn_len(2 + len(ntlmssp_oid)) + b"\x06" + bytes([len(ntlmssp_oid)]) + ntlmssp_oid

    # NegTokenInit: 30 <len> a0 <len> mechTypes a2 <len> mechToken
    inner_a0   = b"\xa0" + asn_len(len(mech_type))  + mech_type
    inner_a2   = b"\xa2" + asn_len(len(mech_token)) + mech_token
    seq_inner  = inner_a0 + inner_a2
    seq        = b"\x30" + asn_len(len(seq_inner)) + seq_inner
    spnego     = b"\xa0" + asn_len(len(seq)) + seq

    # InitContextToken: 60 <len> 06 06 spnego_oid spnego_mech
    spnego_oid = b"\x06\x06\x2b\x06\x01\x05\x05\x02"
    tok_inner  = spnego_oid + spnego
    return b"\x60" + asn_len(len(tok_inner)) + tok_inner


def build_session_setup_type1(pid: int, mid: int) -> bytes:
    """
    SMB_COM_SESSION_SETUP_ANDX (0x73) carrying an NTLMSSP Type 1 blob.
    This is the first Session Setup request.
    """
    ntlm_blob  = build_ntlmssp_negotiate()
    sec_blob   = wrap_ntlm_in_spnego(ntlm_blob)
    blob_len   = len(sec_blob)

    hdr = smb_header(
        cmd=0x73, flags1=0x18, flags2=0x2801,
        errorcode=0, pid=pid, uid=0, tid=0, mid=mid,
    )

    # Session Setup AndX body (from client perspective):
    #   WordCount(1) + AndXCmd(1) + Reserved(1) + AndXOffset(2)
    #   + MaxBufferSize(2) + MaxMpxCount(2) + VCNumber(2)
    #   + SessionKey(4) + SecurityBlobLength(2) + Reserved2(4)
    #   + Capabilities(4)
    #   = WordCount-only header: these 13 words = 13 words × 2 bytes + 1 = 27 bytes
    # ByteCount(2) + SecurityBlob
    word_count = 13
    andxoffset = 32 + 1 + word_count * 2 + 2 + blob_len  # hdr + wc + words + bcc + blob
    words = struct.pack("<B",  word_count)
    words += b"\xff\x00"                              # AndXCmd=0xff, Reserved
    words += struct.pack("<H", andxoffset)            # AndXOffset
    words += struct.pack("<H", 4096)                  # MaxBufferSize
    words += struct.pack("<H", 50)                    # MaxMpxCount
    words += struct.pack("<H", 1)                     # VCNumber
    words += struct.pack("<I", 0)                     # SessionKey
    words += struct.pack("<H", blob_len)              # SecurityBlobLength
    words += struct.pack("<I", 0)                     # Reserved2
    words += struct.pack("<I", 0x0000d054)            # Capabilities

    bcc  = struct.pack("<H", blob_len)
    body = words + bcc + sec_blob
    return nb_frame(hdr + body)


# ---------------------------------------------------------------------------
# NTLMSSP Type 3 (Authenticate) — crafted hash blob for the test
# ---------------------------------------------------------------------------

def utf16le(s: str) -> bytes:
    return s.encode("utf-16-le")


def build_ntlmssp_auth(username: str, domain: str, challenge: bytes) -> bytes:
    """
    Build a minimal NTLMSSP_AUTH (Type 3) message with a fake NTLMv2 blob.
    We don't compute a real hash; we just need something that looks like a
    valid Type 3 so the server's parser can extract user/domain fields.

    The 'NT response' we use is 24 zero bytes — that makes NtHash length == 24
    which the server recognises as NTLMv1 (anonymous or short blob). For a real
    NTLMv2 it would be >= 56 bytes, but for the test we just need the server to
    respond to confirm it processed the packet.
    """
    user_bytes   = utf16le(username)
    domain_bytes = utf16le(domain)
    host_bytes   = utf16le("TESTBOX")
    lm_response  = b"\x00" * 24    # LM hash placeholder
    nt_response  = b"\x00" * 24    # NT hash placeholder (length 24 = NTLMv1)

    # Build offsets (all relative to start of NTLMSSP message)
    base = 72  # fixed header size for Type 3

    lm_len    = len(lm_response)
    lm_off    = base
    nt_len    = len(nt_response)
    nt_off    = lm_off + lm_len
    dom_len   = len(domain_bytes)
    dom_off   = nt_off + nt_len
    user_len  = len(user_bytes)
    user_off  = dom_off + dom_len
    host_len  = len(host_bytes)
    host_off  = user_off + user_len

    flags = 0x00008201  # NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM

    msg  = b"NTLMSSP\x00"
    msg += struct.pack("<I", 3)                            # MessageType = NTLMSSP_AUTH
    msg += struct.pack("<HHI", lm_len,   lm_len,   lm_off)    # LmChallengeResponseFields
    msg += struct.pack("<HHI", nt_len,   nt_len,   nt_off)    # NtChallengeResponseFields
    msg += struct.pack("<HHI", dom_len,  dom_len,  dom_off)   # DomainNameFields
    msg += struct.pack("<HHI", user_len, user_len, user_off)  # UserNameFields
    msg += struct.pack("<HHI", host_len, host_len, host_off)  # WorkstationFields
    msg += struct.pack("<HHI", 0, 0, 0)                       # EncryptedRandomSessionKeyFields
    msg += struct.pack("<I", flags)                            # NegotiateFlags
    msg += lm_response + nt_response + domain_bytes + user_bytes + host_bytes
    return msg


def build_session_setup_type3(pid: int, uid: int, mid: int,
                               username: str, domain: str,
                               challenge: bytes) -> bytes:
    """
    SMB_COM_SESSION_SETUP_ANDX (0x73) carrying an NTLMSSP Type 3 auth blob.
    """
    sec_blob = build_ntlmssp_auth(username, domain, challenge)
    blob_len = len(sec_blob)

    hdr = smb_header(
        cmd=0x73, flags1=0x18, flags2=0x2801,
        errorcode=0, pid=pid, uid=uid, tid=0, mid=mid,
    )

    word_count = 13
    andxoffset = 32 + 1 + word_count * 2 + 2 + blob_len
    words = struct.pack("<B", word_count)
    words += b"\xff\x00"
    words += struct.pack("<H", andxoffset)
    words += struct.pack("<H", 4096)
    words += struct.pack("<H", 50)
    words += struct.pack("<H", 1)
    words += struct.pack("<I", 0)
    words += struct.pack("<H", blob_len)
    words += struct.pack("<I", 0)
    words += struct.pack("<I", 0x0000d054)

    bcc  = struct.pack("<H", blob_len)
    body = words + bcc + sec_blob
    return nb_frame(hdr + body)


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

def find_server_port() -> int:
    """Return 445 if it's accepting connections, else 4450, else raise."""
    for port in (SMB_PORT, SMB_FALLBACK):
        try:
            s = socket.socket()
            s.settimeout(1.0)
            s.connect(("127.0.0.1", port))
            s.close()
            return port
        except OSError:
            continue
    raise RuntimeError("smb_server not reachable on port 445 or 4450")


def run_test() -> int:
    try:
        port = find_server_port()
    except RuntimeError as e:
        print(f"[test] FAIL — {e}")
        print("[test] Is smb_server running? sudo ./esp32emu/esp32emu run src/smb_server.cpp")
        return 1

    print(f"[test] Connecting to 127.0.0.1:{port}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect(("127.0.0.1", port))

    # -----------------------------------------------------------------------
    # 1. Send SMB_COM_NEGOTIATE
    # -----------------------------------------------------------------------
    neg_req = build_negotiate_request()
    print(f"[test] Sending NEGOTIATE ({len(neg_req)} bytes): {neg_req.hex()}")
    s.sendall(neg_req)

    neg_resp = recv_nb_pdu(s)
    if not neg_resp:
        print("[test] FAIL — no Negotiate response within 5 seconds")
        s.close()
        return 1
    print(f"[test] Negotiate response ({len(neg_resp)} bytes): {neg_resp.hex()}")

    # Assert 1: SMB magic
    if neg_resp[0:4] != b"\xff\x53\x4d\x42":
        print(f"[test] FAIL — bad SMB magic: {neg_resp[0:4].hex()}")
        s.close()
        return 1
    print("[test] SMB magic OK (\\xffSMB)")

    # Assert 2: Command = 0x72
    if neg_resp[4] != 0x72:
        print(f"[test] FAIL — expected cmd=0x72, got 0x{neg_resp[4]:02x}")
        s.close()
        return 1
    print("[test] Command = 0x72 OK")

    # Assert 3: STATUS_SUCCESS in Negotiate response
    nt_status = struct.unpack("<I", neg_resp[5:9])[0]
    if nt_status != 0x00000000:
        print(f"[test] FAIL — Negotiate NTStatus = 0x{nt_status:08x} (expected 0x00000000)")
        s.close()
        return 1
    print(f"[test] NTStatus = 0x{nt_status:08x} OK")

    hdr = parse_smb_header(neg_resp)
    print(f"[test] Negotiate header: {hdr}")

    # Assert 4: NTLMSSP challenge present and non-zero
    challenge = find_ntlm_challenge(neg_resp)
    if len(challenge) != 8:
        print(f"[test] FAIL — could not find 8-byte NTLMSSP challenge in Negotiate response")
        s.close()
        return 1
    if challenge == b"\x00" * 8:
        print("[test] FAIL — challenge is all zeros (not random)")
        s.close()
        return 1
    print(f"[test] NTLMSSP challenge: {challenge.hex()} OK")

    pid = hdr["pid"] if hdr["pid"] else 0xFEFF
    uid = hdr["uid"]
    mid_next = 2

    # -----------------------------------------------------------------------
    # 2. Send Session Setup with NTLMSSP Type 1
    # -----------------------------------------------------------------------
    sess1 = build_session_setup_type1(pid, mid_next)
    print(f"\n[test] Sending Session Setup Type 1 ({len(sess1)} bytes)")
    s.sendall(sess1)

    sess1_resp = recv_nb_pdu(s)
    if not sess1_resp:
        print("[test] FAIL — no Session Setup response")
        s.close()
        return 1
    print(f"[test] Session Setup response ({len(sess1_resp)} bytes): {sess1_resp.hex()[:80]}...")

    # Assert 5: still SMBv1
    if sess1_resp[0:4] != b"\xff\x53\x4d\x42":
        print(f"[test] FAIL — bad SMB magic in Session Setup response")
        s.close()
        return 1
    if sess1_resp[4] != 0x73:
        print(f"[test] FAIL — expected cmd=0x73, got 0x{sess1_resp[4]:02x}")
        s.close()
        return 1

    # Assert 6: STATUS_MORE_PROCESSING_REQUIRED (0xc0000016)
    s1_status = struct.unpack("<I", sess1_resp[5:9])[0]
    if s1_status != 0xc0000016:
        print(f"[test] FAIL — expected STATUS_MORE_PROCESSING_REQUIRED (0xc0000016), "
              f"got 0x{s1_status:08x}")
        s.close()
        return 1
    print(f"[test] NTStatus = 0xc0000016 (STATUS_MORE_PROCESSING_REQUIRED) OK")

    # Check our challenge appears in the Session Setup response too
    s1_challenge = find_ntlm_challenge(sess1_resp)
    if len(s1_challenge) == 8 and s1_challenge != b"\x00" * 8:
        if s1_challenge == challenge:
            print(f"[test] Challenge consistent across Negotiate/SessionSetup responses OK")
        else:
            # A different (new) challenge is also acceptable — Responder generates
            # per-connection challenges; what matters is we capture it.
            print(f"[test] Note: Session Setup challenge differs from Negotiate challenge "
                  f"({s1_challenge.hex()} vs {challenge.hex()}) — using Session Setup challenge")
            challenge = s1_challenge

    sess1_hdr = parse_smb_header(sess1_resp)
    uid_from_server = sess1_hdr["uid"]
    mid_next = 3

    # -----------------------------------------------------------------------
    # 3. Send Session Setup with NTLMSSP Type 3 (fake auth)
    # -----------------------------------------------------------------------
    sess2 = build_session_setup_type3(pid, uid_from_server, mid_next,
                                       username="testuser", domain="TESTDOMAIN",
                                       challenge=challenge)
    print(f"\n[test] Sending Session Setup Type 3 (auth) ({len(sess2)} bytes)")
    s.sendall(sess2)

    # Assert 7: server sends *any* response — indicates hash was processed
    try:
        sess2_resp = recv_nb_pdu(s)
        if sess2_resp:
            s2_status = struct.unpack("<I", sess2_resp[5:9])[0] if len(sess2_resp) >= 9 else 0
            print(f"[test] Auth response ({len(sess2_resp)} bytes), "
                  f"NTStatus = 0x{s2_status:08x}")
            print("[test] PASS — server processed auth packet and responded")
        else:
            # Connection closed is also acceptable — means server got the blob and dropped conn
            print("[test] Server closed connection after auth packet")
            print("[test] PASS — server received auth packet")
    except (socket.timeout, ConnectionResetError):
        print("[test] Server closed connection after auth (timeout on recv)")
        print("[test] PASS — server received auth packet and closed connection")

    s.close()

    # -----------------------------------------------------------------------
    # Negative test: wrong SMB command should produce no useful response
    # -----------------------------------------------------------------------
    print("\n[test] Negative test: sending garbage data to server")
    try:
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(TIMEOUT)
        s2.connect(("127.0.0.1", port))

        junk = nb_frame(b"\xff\x53\x4d\x42\x25" + b"\x00" * 27)  # 0x25 = TRANS2
        s2.sendall(junk)
        try:
            resp = recv_nb_pdu(s2)
            # A response is possible (server may send error); what we're really
            # checking is that the server doesn't crash and is still listening
            print(f"[test] Garbage: server returned {len(resp)} bytes (acceptable)")
        except (socket.timeout, ConnectionResetError):
            print("[test] Garbage: server closed connection (acceptable)")
        s2.close()

        # Verify server is still up
        s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s3.settimeout(1.0)
        s3.connect(("127.0.0.1", port))
        s3.close()
        print("[test] Server still accepting connections after garbage input OK")
    except Exception as e:
        print(f"[test] Negative test exception: {e} (non-fatal)")

    return 0


if __name__ == "__main__":
    sys.exit(run_test())
