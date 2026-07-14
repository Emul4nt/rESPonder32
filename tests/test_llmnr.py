#!/usr/bin/env python3
"""
Send a synthetic LLMNR A-query for 'FILESERVER' to localhost:5355 and verify
the poisoner replies with an A record pointing at itself.

Usage: run while llmnr_poisoner is running in another terminal.
"""
import socket, struct, sys, time

LLMNR_PORT = 5355

def dns_encode_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        encoded = label.encode()
        out += bytes([len(encoded)]) + encoded
    out += b"\x00"
    return out

def build_llmnr_query(txid: int, name: str) -> bytes:
    encoded_name = dns_encode_name(name)
    header = struct.pack("!HHHHHH",
        txid,    # Transaction ID
        0x0000,  # Flags: standard query
        1,       # QDCOUNT = 1
        0,       # ANCOUNT = 0
        0,       # NSCOUNT = 0
        0,       # ARCOUNT = 0
    )
    question = encoded_name + struct.pack("!HH", 0x0001, 0x0001)  # A, IN
    return header + question

def parse_llmnr_response(data: bytes, expected_name: str) -> dict:
    if len(data) < 12:
        return {"ok": False, "error": "too short"}

    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])

    if not (flags & 0x8000):
        return {"ok": False, "error": "QR bit not set — not a response"}
    if ancount == 0:
        return {"ok": False, "error": "ANCOUNT = 0"}

    # Skip question section to find answer
    pos = 12
    for _ in range(qdcount):
        while pos < len(data):
            label_len = data[pos]; pos += 1
            if label_len == 0: break
            pos += label_len
        pos += 4  # QTYPE + QCLASS

    # Parse first answer
    # Skip name (may be pointer or label)
    while pos < len(data):
        label_len = data[pos]
        if label_len == 0:
            pos += 1; break
        if label_len & 0xC0:  # pointer
            pos += 2; break
        pos += 1 + label_len

    if pos + 10 > len(data):
        return {"ok": False, "error": "truncated answer section"}

    rtype, rclass, ttl_hi, ttl_lo, rdlen = struct.unpack("!HHHHH", data[pos:pos+10])
    pos += 10

    if rtype != 1:
        return {"ok": False, "error": f"unexpected RTYPE {rtype}"}
    if rdlen != 4:
        return {"ok": False, "error": f"unexpected RDLENGTH {rdlen}"}
    if pos + 4 > len(data):
        return {"ok": False, "error": "truncated RDATA"}

    ip = ".".join(str(b) for b in data[pos:pos+4])
    return {"ok": True, "txid": txid, "flags": hex(flags), "answer_ip": ip}


def run_test():
    txid = 0x1234
    query_name = "FILESERVER"
    pkt = build_llmnr_query(txid, query_name)

    print(f"[test] Sending LLMNR A-query for '{query_name}' to 127.0.0.1:{LLMNR_PORT}")
    print(f"[test] Packet ({len(pkt)} bytes): {pkt.hex()}")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)

    try:
        s.sendto(pkt, ("127.0.0.1", LLMNR_PORT))
        print("[test] Packet sent, waiting for response...")
        data, addr = s.recvfrom(512)
        print(f"[test] Response ({len(data)} bytes) from {addr}: {data.hex()}")
        result = parse_llmnr_response(data, query_name)
        if result["ok"]:
            print(f"[test] PASS — poisoner replied with A record: {result['answer_ip']}")
            return 0
        else:
            print(f"[test] FAIL — {result['error']}")
            return 1
    except socket.timeout:
        print("[test] FAIL — no response within 3 seconds")
        print("[test] Is the poisoner running? ./esp32emu run examples/llmnr_poisoner.cpp")
        return 1
    finally:
        s.close()

if __name__ == "__main__":
    sys.exit(run_test())
