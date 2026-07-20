# rESPonder32

An ESP32 port of [Responder](https://github.com/lgandx/Responder) by Laurent Gaffié. Poisons LLMNR, NBT-NS, and mDNS on a local network, serves fake SMB and HTTP auth endpoints, captures NTLMv2 hashes from Windows clients, and exposes them over serial and a local `/hashes` endpoint. Runs on a microcontroller with no laptop required.

## How it works

Windows resolves hostnames in order: DNS, then LLMNR (UDP multicast 224.0.0.252:5355), then NBT-NS (UDP broadcast 137). When DNS fails, Windows broadcasts the name on the fallback protocols. rESPonder32 answers every broadcast with its own IP.

The client connects to that IP and tries to authenticate over SMB or HTTP. rESPonder32 runs a fake SMBv1 Negotiate/Session Setup exchange and a fake HTTP WWW-Authenticate: NTLM three-step handshake. In both cases it sends an 8-byte random challenge and captures the NTLMv2 blob from the client's response. The blob is formatted as a hashcat-ready string and stored.

mDNS (UDP multicast 224.0.0.251:5353) runs in parallel and catches the same class of Windows broadcast, plus Apple and Linux clients doing `.local` lookups.

Packet formats and field values are taken field-by-field from Responder's `packets.py`, `servers/SMB.py`, `servers/HTTP.py`, and `utils/NTLM.py`. Flags, TTLs, AvPairs order, and NTLM negotiate bytes match Responder's output exactly.

## Hardware

Any ESP32-WROOM-32 dev board. Flash usage is around 1MB out of 4MB. Runtime RAM sits at roughly 120KB (WiFi stack plus six FreeRTOS tasks plus buffers), leaving about 180KB of heap free. The SMB and HTTP tasks do the most work per connection; if you see crashes under sustained load, instrument them with `uxTaskGetStackHighWaterMark` and bump their stack sizes from 8192 to 12288.

## Building and flashing

Open `src/responder32.cpp`, set `WIFI_SSID` and `WIFI_PASS`, and flash with the ESP32 Arduino core. Board: `ESP32 Dev Module`, partition scheme: `Default 4MB with spiffs` or `Default 4MB`.

PlatformIO:

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
```

## Project layout

```
src/
  llmnr_poisoner.cpp       LLMNR poisoner, standalone sketch
  nbtns_poisoner.cpp       NBT-NS poisoner, standalone sketch
  mdns_poisoner.cpp        mDNS poisoner, standalone sketch
  smb_server.cpp           fake SMBv1 server, standalone sketch
  http_ntlm_server.cpp     fake HTTP NTLM server, standalone sketch
  hash_formatter.h         NTLMv2/v1 to hashcat format, header-only
  output_layer.cpp         in-memory hash store and WebServer /hashes endpoint
  responder32.cpp          all modules combined as FreeRTOS tasks

tests/
  test_llmnr.py
  test_nbtns.py
  test_mdns.py
  test_smb.py
  test_http.py
  test_hash_formatter.py
```

Each file under `src/` except `hash_formatter.h` and `output_layer.cpp` is a complete standalone sketch. Any of them can be flashed individually for isolated testing.

## Output

Hashes are printed to serial and stored in memory. Retrieve them over the network:

```bash
curl http://<esp32-ip>:8080/hashes
```

Format:

```
# NTLMv2
Username::Domain:ServerChallenge:NTProofStr:Blob

# NTLMv1
Username::Hostname:LMResponse:NTResponse:ServerChallenge
```

Crack with:

```bash
hashcat -m 5600 hashes.txt wordlist.txt
```

## Legal

For authorised penetration testing and security research only. Do not run on networks you do not own or have written permission to test.

## License

WTFPL - https://www.wtfpl.net/

```
            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                    Version 2, December 2004

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. You just DO WHAT THE FUCK YOU WANT TO.
```
