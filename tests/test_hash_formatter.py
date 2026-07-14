#!/usr/bin/env python3
"""
Pure-Python test for the hash_formatter.h parsing logic.

Does NOT require the emulator. Constructs known NTLM Type 3 messages from
scratch, reimplements the same offset logic as formatNTLMHash(), and checks
the output matches the expected hashcat string exactly.

Usage:
  python3 tests/test_hash_formatter.py
"""
import struct
import sys

CHALLENGE = b"\x01\x02\x03\x04\x05\x06\x07\x08"
CHALLENGE_HEX = CHALLENGE.hex()  # "0102030405060708"


# ---------------------------------------------------------------------------
# Python re-implementation of formatNTLMHash() — offsets must stay in sync
# with hash_formatter.h
# ---------------------------------------------------------------------------

def find_ntlmssp(data: bytes) -> int:
    """Return offset of NTLMSSP\\x00 signature, or -1."""
    return data.find(b"NTLMSSP\x00")


def _le16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _decode_utf16le(blob: bytes) -> str:
    """Strip null bytes from UTF-16LE, return ASCII string."""
    return blob.decode("utf-16-le")


def format_ntlm_hash(ntlm_data: bytes, challenge: bytes) -> str:
    """
    Mirrors formatNTLMHash() in hash_formatter.h.
    ntlm_data starts at the NTLMSSP signature (offset 0 = 'N').
    Returns the hashcat-format string or raises ValueError.
    """
    if len(ntlm_data) < 42:
        raise ValueError("blob too short")

    lm_len  = _le16(ntlm_data, 12)
    lm_off  = _le16(ntlm_data, 16)
    nt_len  = _le16(ntlm_data, 20)
    nt_off  = _le16(ntlm_data, 24)
    usr_len = _le16(ntlm_data, 36)
    usr_off = _le16(ntlm_data, 40)

    username = _decode_utf16le(ntlm_data[usr_off:usr_off + usr_len])
    challenge_hex = challenge.hex()

    if nt_len > 24:
        # NTLMv2
        dom_len = _le16(ntlm_data, 28)
        dom_off = _le16(ntlm_data, 32)
        domain  = _decode_utf16le(ntlm_data[dom_off:dom_off + dom_len])

        nt_hash   = ntlm_data[nt_off:nt_off + nt_len]
        nt_proof  = nt_hash[:16].hex()
        blob_hex  = nt_hash[16:].hex()

        return "%s::%s:%s:%s:%s" % (username, domain, challenge_hex, nt_proof, blob_hex)

    elif nt_len == 24:
        # NTLMv1
        host_len = _le16(ntlm_data, 46)
        host_off = _le16(ntlm_data, 48)
        hostname = _decode_utf16le(ntlm_data[host_off:host_off + host_len])

        lm_hex = ntlm_data[lm_off:lm_off + lm_len].hex()
        nt_hex = ntlm_data[nt_off:nt_off + nt_len].hex()

        return "%s::%s:%s:%s:%s" % (username, hostname, lm_hex, nt_hex, challenge_hex)

    else:
        raise ValueError("unexpected NT hash length %d" % nt_len)


# ---------------------------------------------------------------------------
# NTLM Type 3 message builder
# ---------------------------------------------------------------------------

def _le(val: int, size: int) -> bytes:
    return val.to_bytes(size, "little")


def build_ntlmv2_type3(username: str, domain: str,
                        nt_proof: bytes, blob: bytes,
                        challenge: bytes) -> bytes:
    """
    Build a minimal NTLM Type 3 authenticate message.
    Field layout follows MS-NLMP 2.2.1.3.
    All variable fields are appended after the fixed header.
    """
    # Fixed header is 72 bytes (signature 8 + msgtype 4 + 6 security buffers
    # of 8 bytes each = 8 + 4 + 6*8 = 60 bytes, plus 12 for version/flags =
    # 72 total). We keep it simple: lay out each buffer offset explicitly.

    username_utf16 = username.encode("utf-16-le")
    domain_utf16   = domain.encode("utf-16-le")
    nt_hash        = nt_proof + blob
    lm_hash        = b"\x00" * 24  # NTLMv2: LM response is zeroes

    # Workstation (put something plausible)
    workstation_utf16 = "WORKSTATION".encode("utf-16-le")

    # --- calculate offsets ---
    # fixed header size we write below: 72 bytes
    HEADER_SIZE = 72

    lm_off   = HEADER_SIZE
    nt_off   = lm_off   + len(lm_hash)
    dom_off  = nt_off   + len(nt_hash)
    usr_off  = dom_off  + len(domain_utf16)
    host_off = usr_off  + len(username_utf16)

    payload = lm_hash + nt_hash + domain_utf16 + username_utf16 + workstation_utf16

    msg  = b"NTLMSSP\x00"            # signature
    msg += _le(3, 4)                  # MessageType = 3 (Authenticate)

    # LmChallengeResponseFields [12:20]
    msg += _le(len(lm_hash), 2)      # Len
    msg += _le(len(lm_hash), 2)      # MaxLen
    msg += _le(lm_off, 4)            # Offset

    # NtChallengeResponseFields [20:28]
    msg += _le(len(nt_hash), 2)
    msg += _le(len(nt_hash), 2)
    msg += _le(nt_off, 4)

    # DomainNameFields [28:36]
    msg += _le(len(domain_utf16), 2)
    msg += _le(len(domain_utf16), 2)
    msg += _le(dom_off, 4)

    # UserNameFields [36:44]
    msg += _le(len(username_utf16), 2)
    msg += _le(len(username_utf16), 2)
    msg += _le(usr_off, 4)

    # WorkstationFields [44:52]
    msg += _le(len(workstation_utf16), 2)
    msg += _le(len(workstation_utf16), 2)
    msg += _le(host_off, 4)

    # EncryptedRandomSessionKeyFields [52:60] — empty
    msg += _le(0, 2) + _le(0, 2) + _le(0, 4)

    # NegotiateFlags [60:64]
    msg += _le(0x20088215, 4)

    # Version [64:72] (8 bytes)
    msg += b"\x0a\x00\x7c\x4f\x00\x00\x00\x0f"

    assert len(msg) == HEADER_SIZE, "header size mismatch: %d" % len(msg)

    msg += payload
    return msg


def build_ntlmv1_type3(username: str, hostname: str,
                        lm_hash: bytes, nt_hash: bytes,
                        challenge: bytes) -> bytes:
    """Build a minimal NTLM Type 3 for NTLMv1 (24-byte hashes)."""
    assert len(lm_hash) == 24
    assert len(nt_hash) == 24

    username_utf16  = username.encode("utf-16-le")
    # For NTLMv1 the domain field is just empty
    domain_utf16    = b""
    hostname_utf16  = hostname.encode("utf-16-le")

    HEADER_SIZE = 72

    lm_off   = HEADER_SIZE
    nt_off   = lm_off   + len(lm_hash)
    dom_off  = nt_off   + len(nt_hash)
    usr_off  = dom_off  + len(domain_utf16)
    host_off = usr_off  + len(username_utf16)

    payload = lm_hash + nt_hash + domain_utf16 + username_utf16 + hostname_utf16

    msg  = b"NTLMSSP\x00"
    msg += _le(3, 4)

    # LmChallengeResponseFields [12:20]
    msg += _le(len(lm_hash), 2)
    msg += _le(len(lm_hash), 2)
    msg += _le(lm_off, 4)

    # NtChallengeResponseFields [20:28]
    msg += _le(len(nt_hash), 2)
    msg += _le(len(nt_hash), 2)
    msg += _le(nt_off, 4)

    # DomainNameFields [28:36]
    msg += _le(len(domain_utf16), 2)
    msg += _le(len(domain_utf16), 2)
    msg += _le(dom_off, 4)

    # UserNameFields [36:44]
    msg += _le(len(username_utf16), 2)
    msg += _le(len(username_utf16), 2)
    msg += _le(usr_off, 4)

    # WorkstationFields [44:52] — this is the hostname for NTLMv1
    msg += _le(len(hostname_utf16), 2)
    msg += _le(len(hostname_utf16), 2)
    msg += _le(host_off, 4)

    # EncryptedRandomSessionKeyFields [52:60] — empty
    msg += _le(0, 2) + _le(0, 2) + _le(0, 4)

    # NegotiateFlags [60:64]
    msg += _le(0x20088215, 4)

    # Version [64:72]
    msg += b"\x0a\x00\x7c\x4f\x00\x00\x00\x0f"

    assert len(msg) == HEADER_SIZE
    msg += payload
    return msg


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def run_tests() -> int:
    failures = 0

    # --- NTLMv2 test --------------------------------------------------------
    username  = "Administrator"
    domain    = "WORKGROUP"
    nt_proof  = bytes(range(16))                # 16 bytes of known value
    blob      = bytes(range(16, 32))            # 16-byte blob (simple)

    expected_v2 = "%s::%s:%s:%s:%s" % (
        username,
        domain,
        CHALLENGE_HEX,
        nt_proof.hex(),
        blob.hex(),
    )

    blob_v2 = build_ntlmv2_type3(username, domain, nt_proof, blob, CHALLENGE)
    sig_off  = find_ntlmssp(blob_v2)
    if sig_off < 0:
        print("[test] FAIL (NTLMv2) — NTLMSSP signature not found in constructed blob")
        failures += 1
    else:
        try:
            got = format_ntlm_hash(blob_v2[sig_off:], CHALLENGE)
            if got == expected_v2:
                print("[test] PASS (NTLMv2) — %s" % got)
            else:
                print("[test] FAIL (NTLMv2)")
                print("  expected: %s" % expected_v2)
                print("  got:      %s" % got)
                failures += 1
        except Exception as e:
            print("[test] FAIL (NTLMv2) — exception: %s" % e)
            failures += 1

    # --- NTLMv1 test --------------------------------------------------------
    username_v1 = "jsmith"
    hostname_v1 = "CLIENTPC"
    lm_hash     = bytes(range(24))
    nt_hash     = bytes(range(8, 32))  # 24 bytes

    expected_v1 = "%s::%s:%s:%s:%s" % (
        username_v1,
        hostname_v1,
        lm_hash.hex(),
        nt_hash.hex(),
        CHALLENGE_HEX,
    )

    blob_v1 = build_ntlmv1_type3(username_v1, hostname_v1, lm_hash, nt_hash, CHALLENGE)
    sig_off  = find_ntlmssp(blob_v1)
    if sig_off < 0:
        print("[test] FAIL (NTLMv1) — NTLMSSP signature not found in constructed blob")
        failures += 1
    else:
        try:
            got = format_ntlm_hash(blob_v1[sig_off:], CHALLENGE)
            if got == expected_v1:
                print("[test] PASS (NTLMv1) — %s" % got)
            else:
                print("[test] FAIL (NTLMv1)")
                print("  expected: %s" % expected_v1)
                print("  got:      %s" % got)
                failures += 1
        except Exception as e:
            print("[test] FAIL (NTLMv1) — exception: %s" % e)
            failures += 1

    # --- Negative: blob too short ------------------------------------------
    try:
        format_ntlm_hash(b"NTLMSSP\x00" + b"\x00" * 10, CHALLENGE)
        print("[test] FAIL (short blob) — should have raised ValueError")
        failures += 1
    except ValueError:
        print("[test] PASS (short blob rejects correctly)")

    # --- Negative: NTLMSSP not found ---------------------------------------
    dummy = b"\x00" * 100
    if find_ntlmssp(dummy) != -1:
        print("[test] FAIL (no-sig search) — returned non-negative offset for garbage data")
        failures += 1
    else:
        print("[test] PASS (no-sig search rejects correctly)")

    # --- findNTLMSSP with embedded prefix ----------------------------------
    container = b"\x00\x00\x00" + blob_v2
    off = find_ntlmssp(container)
    if off != 3:
        print("[test] FAIL (embedded sig) — expected offset 3, got %s" % off)
        failures += 1
    else:
        print("[test] PASS (embedded NTLMSSP offset detection)")

    return failures


if __name__ == "__main__":
    total_failures = run_tests()
    if total_failures == 0:
        print("\n[test] All tests passed.")
        sys.exit(0)
    else:
        print("\n[test] %d test(s) failed." % total_failures)
        sys.exit(1)
