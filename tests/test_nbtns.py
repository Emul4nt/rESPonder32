#!/usr/bin/env python3
"""
Send a synthetic NBT-NS Name Query Request for 'FILESERVER' to localhost:137
and verify the poisoner replies with a Positive Name Query Response pointing
at our IP.

Usage: run as root while nbtns_poisoner is running:
  sudo /tmp/nbtns_poisoner &
  sudo python3 /tmp/test_nbtns.py
"""
import socket, struct, sys

NBTNS_PORT = 137

def nbt_encode_name(name: str, suffix: int = 0x00) -> bytes:
    """
    First-level NetBIOS name encoding (RFC 1002 s4.1).
    Pads name to 15 bytes, appends suffix byte, then encodes each byte
    as two nibble characters: hi_nibble + 'A', lo_nibble + 'A'.
    Returns: 0x20 + 32 encoded bytes + 0x00 (34 bytes total).
    """
    padded = (name.upper() + ' ' * 15)[:15] + chr(suffix)
    encoded = bytearray()
    for c in padded:
        b = ord(c)
        encoded.append(((b >> 4) & 0xF) + ord('A'))
        encoded.append((b & 0xF) + ord('A'))
    return bytes([0x20]) + bytes(encoded) + bytes([0x00])

def nbt_decode_name(wire: bytes) -> tuple:
    """Decode 34-byte wire-format name. Returns (name_str, suffix_byte)."""
    assert wire[0] == 0x20 and wire[33] == 0x00
    decoded = []
    for i in range(16):
        hi = wire[1 + i*2]     - ord('A')
        lo = wire[1 + i*2 + 1] - ord('A')
        decoded.append((hi << 4) | lo)
    name = ''.join(chr(b) for b in decoded[:15]).rstrip()
    suffix = decoded[15]
    return name, suffix

def build_nbtns_query(txid: int, name: str, suffix: int = 0x00) -> bytes:
    header = struct.pack("!HHHHHH",
        txid,
        0x0110,   # Flags: opcode=0, RD=1, B=1 (broadcast query)
        1,        # QDCOUNT
        0, 0, 0,
    )
    question = nbt_encode_name(name, suffix)
    question += struct.pack("!HH", 0x0020, 0x0001)  # QTYPE=NB, QCLASS=IN
    return header + question

def parse_nbtns_response(data: bytes) -> dict:
    if len(data) < 12:
        return {"ok": False, "error": "too short"}
    txid, flags, qdcnt, ancnt, nscnt, arcnt = struct.unpack("!HHHHHH", data[:12])

    if not (flags & 0x8000):
        return {"ok": False, "error": "QR=0 (not a response)"}
    if ancnt == 0:
        return {"ok": False, "error": "ANCOUNT=0"}

    # Skip any question section (Responder sends QDCOUNT=0, others may differ)
    pos = 12
    for _ in range(qdcnt):
        if pos >= len(data): break
        label_len = data[pos]
        pos += 1 + label_len + 1  # 0x20 + 32 bytes + 0x00
        pos += 4  # QTYPE + QCLASS

    # Answer record
    if pos + 34 + 2 + 2 + 4 + 2 > len(data):
        return {"ok": False, "error": "truncated answer"}

    wire_name = data[pos:pos+34]
    try:
        name, suffix = nbt_decode_name(wire_name)
    except Exception as e:
        return {"ok": False, "error": f"name decode failed: {e}"}
    pos += 34

    rtype, rclass = struct.unpack("!HH", data[pos:pos+4]); pos += 4
    ttl           = struct.unpack("!I", data[pos:pos+4])[0]; pos += 4
    rdlen         = struct.unpack("!H", data[pos:pos+2])[0]; pos += 2

    if rtype != 0x0020:
        return {"ok": False, "error": f"RTYPE={hex(rtype)} (expected 0x0020)"}
    if rdlen != 6:
        return {"ok": False, "error": f"RDLENGTH={rdlen} (expected 6)"}
    if pos + 6 > len(data):
        return {"ok": False, "error": "truncated RDATA"}

    nb_flags = struct.unpack("!H", data[pos:pos+2])[0]; pos += 2
    ip       = ".".join(str(b) for b in data[pos:pos+4])

    return {
        "ok":      True,
        "txid":    hex(txid),
        "flags":   hex(flags),
        "name":    name,
        "suffix":  hex(suffix),
        "ttl":     ttl,
        "nb_flags": hex(nb_flags),
        "ip":      ip,
    }


def selftest_encoding():
    # Verify encode -> decode roundtrip
    wire = nbt_encode_name("FILESERVER", 0x20)
    name, suffix = nbt_decode_name(wire)
    assert name == "FILESERVER", f"roundtrip failed: got '{name}'"
    assert suffix == 0x20
    print(f"[test] Name encoding roundtrip OK: 'FILESERVER<20>'")
    print(f"[test] Wire: {wire.hex()}")


def run_test():
    selftest_encoding()

    txid  = 0xABCD
    name  = "FILESERVER"
    query = build_nbtns_query(txid, name, suffix=0x20)
    print(f"\n[test] Sending NBT-NS query for '{name}<20>' to 127.0.0.1:{NBTNS_PORT}")
    print(f"[test] Query ({len(query)} bytes): {query.hex()}")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)

    try:
        s.sendto(query, ("127.0.0.1", NBTNS_PORT))
        print("[test] Sent, waiting for response...")
        data, addr = s.recvfrom(512)
        print(f"[test] Response ({len(data)} bytes) from {addr}: {data.hex()}")

        result = parse_nbtns_response(data)
        if result["ok"]:
            print(f"[test] PASS — name='{result['name']}{result['suffix']}' ip={result['ip']} ttl={result['ttl']}")
            return 0
        else:
            print(f"[test] FAIL — {result['error']}")
            return 1
    except socket.timeout:
        print("[test] FAIL — no response within 3 seconds")
        print("[test] Is the poisoner running with root? sudo /tmp/nbtns_poisoner")
        return 1
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(run_test())
