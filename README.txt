
EECE 644 — TLS Echo to Time-Converter Lab (mbedTLS)

Baseline:
- TLS client and server that exchange a single ASCII line.
- Server ECHOs back what the client sent (already working).

Your task:
- Transform echo into a time-conversion protocol:
  Client (PT) -> Server converts to ET -> Client prints.

Where to edit (look for //TODO markers):
- src/proto.c : define message formats and helpers for PT/ET.
- src/client.c: build PT message, send; parse ET reply, print nicely.
- src/server.c: parse PT, convert to ET, format and send.

Certificates:
- cd certs && ./gen_self_signed.sh

Build & run:
- cd src && make
- Terminal 1: ./server 127.0.0.1 44330 ../certs/server.crt.pem ../certs/server.key.pem
- Terminal 2: ./client 127.0.0.1 44330 ../certs/server.crt.pem

Testing:
- Echo baseline:   python3 test_echo.py
- Time converter:  python3 test_time.py   (after completing TODOs)
