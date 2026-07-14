#!/usr/bin/env python3
"""
Send synthetic mDNS A-queries for 'DESKTOP-TEST.local' to localhost:5353 and
verify the poisoner replies with an A record pointing at itself.

Negative tests confirm that mDNS responses (QR=1) and AAAA queries produce
no reply, matching Responder's MDNS.py filter behaviour.

Usage: run while mdns_poisoner is running in another terminal.
  Terminal 1: ./esp32emu/esp32emu run src/mdns_poisoner.cpp
  Terminal 2: python3 tests/test_mdns.py
"""
import socket, struct, sys, time

MDNS_PORT = 5353


def dns_encode_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        encoded = label.encode()
        out += bytes([len(encoded)]) + encoded
    out += b"\x00"
    return out


def build_mdns_query(name: str, qtype: int = 0x0001, flags: int = 0x0000) -> bytes:
    encoded_name = dns_encode_name(name)
    header = struct.pack("!HHHHHH",
        0x0000,   # Transaction ID: always 0 in mDNS (RFC 6762 s18.1)
        flags,    # Flags: 0x0000 for query, 0x8000 to simulate a response pkt
        1,        # QDCOUNT = 1
        0,        # ANCOUNT = 0
        0,        # NSCOUNT = 0
        0,        # ARCOUNT = 0
    )
    question = encoded_name + struct.pack("!HH", qtype, 0x0001)  # IN class
    return header + question


def parse_mdns_response(data: bytes) -> dict:
    if len(data) < 12:
        return {"ok": False, "error": "too short"}

    txid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])

    if not (flags & 0x8000):
        return {"ok": False, "error": "QR bit not set — not a response"}
    if not (flags & 0x0400):
        return {"ok": False, "error": "AA bit not set (expected 0x8400)"}
    if ancount == 0:
        return {"ok": False, "error": "ANCOUNT = 0"}
    if txid != 0x0000:
        return {"ok": False, "error": f"Transaction ID {hex(txid)} != 0x0000"}
    if qdcount != 0:
        return {"ok": False, "error": f"QDCOUNT {qdcount} != 0 (mDNS responses suppress question)"}

    # No question section to skip (QDCOUNT=0); answer starts immediately at byte 12.
    pos = 12

    # Parse answer name (may be multi-label)
    while pos < len(data):
        label_len = data[pos]
        if label_len == 0:
            pos += 1
            break
        if label_len & 0xC0:  # pointer compression
            pos += 2
            break
        pos += 1 + label_len

    if pos + 10 > len(data):
        return {"ok": False, "error": "truncated answer section"}

    rtype, rclass, ttl_hi, ttl_lo, rdlen = struct.unpack("!HHHHH", data[pos:pos+10])
    ttl = (ttl_hi << 16) | ttl_lo
    pos += 10

    if rtype != 0x0001:
        return {"ok": False, "error": f"unexpected RTYPE {hex(rtype)} (expected 0x0001 A)"}
    if rdlen != 4:
        return {"ok": False, "error": f"unexpected RDLENGTH {rdlen} (expected 4)"}
    if pos + 4 > len(data):
        return {"ok": False, "error": "truncated RDATA"}

    ip = ".".join(str(b) for b in data[pos:pos+4])
    ip_bytes = data[pos:pos+4]
    if all(b == 0 for b in ip_bytes):
        return {"ok": False, "error": "RDATA is all zeros — poisoner did not fill in an IP"}

    return {
        "ok":    True,
        "txid":  hex(txid),
        "flags": hex(flags),
        "ttl":   ttl,
        "ip":    ip,
    }


def send_and_recv(pkt: bytes, timeout: float = 3.0) -> bytes | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, ("127.0.0.1", MDNS_PORT))
        data, _ = s.recvfrom(512)
        return data
    except socket.timeout:
        return None
    finally:
        s.close()


def run_test() -> int:
    failures = 0

    # --- Positive test: valid A query ---
    name = "DESKTOP-TEST.local"
    pkt  = build_mdns_query(name, qtype=0x0001, flags=0x0000)
    print(f"[test] Sending mDNS A-query for '{name}' to 127.0.0.1:{MDNS_PORT}")
    print(f"[test] Packet ({len(pkt)} bytes): {pkt.hex()}")

    data = send_and_recv(pkt, timeout=3.0)
    if data is None:
        print("[test] FAIL — no response within 3 seconds")
        print("[test] Is the poisoner running? ./esp32emu/esp32emu run src/mdns_poisoner.cpp")
        return 1

    print(f"[test] Response ({len(data)} bytes): {data.hex()}")
    result = parse_mdns_response(data)
    if result["ok"]:
        print(f"[test] PASS (A query) — txid={result['txid']} flags={result['flags']} "
              f"ttl={result['ttl']} ip={result['ip']}")
        if result["ttl"] != 120:
            print(f"[test] FAIL — TTL is {result['ttl']}, expected 120 (0x78)")
            failures += 1
    else:
        print(f"[test] FAIL (A query) — {result['error']}")
        failures += 1

    # --- Negative test: QR=1 (response packet) should produce no reply ---
    pkt_resp = build_mdns_query(name, qtype=0x0001, flags=0x8000)
    print(f"\n[test] Sending mDNS packet with QR=1 (should be ignored)...")
    data = send_and_recv(pkt_resp, timeout=0.5)
    if data is None:
        print("[test] PASS (QR=1 ignored) — no reply as expected")
    else:
        print(f"[test] FAIL (QR=1 ignored) — got unexpected reply: {data.hex()}")
        failures += 1

    # --- Negative test: QTYPE AAAA (0x001c) should produce no reply ---
    pkt_aaaa = build_mdns_query(name, qtype=0x001c, flags=0x0000)
    print(f"\n[test] Sending mDNS AAAA query (should be ignored)...")
    data = send_and_recv(pkt_aaaa, timeout=0.5)
    if data is None:
        print("[test] PASS (AAAA ignored) — no reply as expected")
    else:
        print(f"[test] FAIL (AAAA ignored) — got unexpected reply: {data.hex()}")
        failures += 1

    # --- Negative test: QDCOUNT=0 packet should produce no reply ---
    pkt_noq = struct.pack("!HHHHHH", 0x0000, 0x0000, 0, 0, 0, 0)
    print(f"\n[test] Sending mDNS packet with QDCOUNT=0 (should be ignored)...")
    data = send_and_recv(pkt_noq, timeout=0.5)
    if data is None:
        print("[test] PASS (QDCOUNT=0 ignored) — no reply as expected")
    else:
        print(f"[test] FAIL (QDCOUNT=0 ignored) — got unexpected reply: {data.hex()}")
        failures += 1

    # --- Negative test: truncated packet (< 12 bytes) should produce no reply ---
    pkt_short = b"\x00\x00\x00\x00\x00"
    print(f"\n[test] Sending truncated mDNS packet (5 bytes, should be ignored)...")
    data = send_and_recv(pkt_short, timeout=0.5)
    if data is None:
        print("[test] PASS (short packet ignored) — no reply as expected")
    else:
        print(f"[test] FAIL (short packet ignored) — got unexpected reply: {data.hex()}")
        failures += 1

    print(f"\n[test] {'PASS' if failures == 0 else 'FAIL'} — {failures} failure(s)")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(run_test())
