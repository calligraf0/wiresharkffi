# wiresharkffi

Python bindings for `libwireshark` - use Wireshark's dissectors from Python without spawning a subprocess.

If you've ever processed pcap files in Python you know the options aren't great: pyshark wraps `tshark` and requires spawning a subprocess, scapy is great - but it has its own dissectors and quirks. wiresharkffi takes a different approach and links directly against ``libwireshark`` via CFFI, so you get the exact same dissection output as Wireshark itself. Every protocol Wireshark supports, every field it extracts - available as a Python dict, per packet.

## Requirements

`libwireshark` 4.2.x, 4.4.x, 4.6.x, or 4.7.x must be installed before building:

```bash
# Ubuntu / Debian
sudo apt install `libwireshark`-dev libglib2.0-dev pkg-config

# Arch Linux
sudo pacman -S wireshark-qt pkgconf

# macOS (Homebrew)
brew install wireshark
```

## Installation

```bash
pip install wiresharkffi
```

From source:

```bash
git clone https://github.com/calligraf0/wiresharkffi
cd wiresharkffi
pip install -e .
```

The C extension is compiled at install time and links against the system `libwireshark`. No pre-built wheels.

## Quick start

```python
from wiresharkffi import PcapReader

with PcapReader("capture.pcapng") as pcap:
    for pkt in pcap:
        print(pkt["_num"], pkt.get("ip.src"), pkt.get("tcp.stream"))
```

Each packet is a plain dict with JSON-compatible values. Fields are keyed by Wireshark abbreviation (`ip.src`, `tcp.stream`, `http.request.uri`, etc.) - the same names you'd use in a Wireshark display filter.

## Display filters

Pass any Wireshark display filter expression to skip non-matching packets:

```python
with PcapReader("capture.pcapng", display_filter="tcp") as pcap:
    for pkt in pcap:
        print(pkt["tcp.stream"], pkt["tcp.srcport"])

with PcapReader("capture.pcapng", display_filter="http.response.code >= 400") as pcap:
    for pkt in pcap:
        print(pkt["http.response.code"])
```

The syntax is identical to tshark's `-Y` flag. An invalid filter raises `ValueError` at construction time, before any packets are read.

## Field whitelist

If you only need a few fields, pass `fields=` to discard everything else:

```python
with PcapReader("capture.pcapng", fields={"ip.src", "ip.dst", "tcp.stream"}) as pcap:
    for pkt in pcap:
        print(pkt.get("ip.src"), pkt.get("ip.dst"))
```

`_num`, `_ts`, `_caplen`, and `_len` are always included. `_streams` is included only when at least one of its source fields appears in `fields`. Note that `libwireshark` still fully dissects every packet - `fields=` filters the returned dict, it doesn't short-circuit the dissector.

## Preferences

Set any Wireshark dissector preference before packets are read:

```python
with PcapReader("capture.pcapng", prefs={"tcp.desegment_tcp_streams": "TRUE"}) as pcap:
    for pkt in pcap:
        ...
```

Keys and values use the same format as tshark's `-o` flag. You can also change preferences after construction:

```python
from wiresharkffi import set_preference
set_preference("tcp.desegment_tcp_streams", "FALSE")
```

`set_preference()` must be called after at least one `PcapReader` has been created. For initial setup use the `prefs=` dict instead.

## TLS decryption

Wireshark's TLS dissector runs automatically. Point it at a key log file and decrypted fields appear in the packet dict like any other field:

```python
with PcapReader("capture.pcapng",
                prefs={"tls.keylog_file": "/path/to/sslkeylog.txt"}) as pcap:
    for pkt in pcap:
        print(pkt.get("http.request.uri"), pkt.get("http.response.code"))
```

Most TLS clients write a key log when `SSLKEYLOGFILE` is set in the environment. For RSA sessions (no forward secrecy) you can supply the private key instead:

```python
prefs={"tls.keys_list": "192.168.1.1,443,http,/path/to/server.key"}
```

## Async

```python
import asyncio
from wiresharkffi import PcapReader

async def main():
    async with PcapReader("capture.pcapng") as pcap:
        async for pkt in pcap.async_packets():
            print(pkt["_num"], pkt.get("ip.src"))

asyncio.run(main())
```

`async_packets()` dispatches each read to a thread-pool executor so it plays nicely with an event loop, but it does not parallelize dissection.

## Packet dict format

```python
{
    "_num"    : 1,                    # 1-based frame number
    "_ts"     : 1655239250.367184,    # Unix timestamp, float seconds (~µs resolution)
    "_caplen" : 98,                   # captured bytes
    "_len"    : 98,                   # on-wire bytes
    "_streams": {"tcp": 3},           # stream IDs (omitted if none present)

    "eth.src" : "00:0c:29:fa:a3:37",
    "ip.src"  : "192.168.1.1",
    "ip.dst"  : "8.8.8.8",
    "tcp.stream": 3,
    "tcp.srcport": 52431,
    "frame.protocols": "eth:ethertype:ip:tcp:http",
    # ... every field Wireshark dissects, keyed by abbreviation
}
```

Field types map to Python types based on the Wireshark field type:

| Wireshark type | Python type | Notes |
|---|---|---|
| `FT_UINT*`, `FT_INT*` | `int` | |
| `FT_FLOAT`, `FT_DOUBLE` | `float` | |
| `FT_STRING*` | `str` | |
| `FT_BYTES`, `FT_UINT_BYTES` | `bytes` or `str` | controlled by `bytes_repr=` |
| everything else (IPs, MACs, OIDs, …) | `str` | Wireshark's human-readable label |
| repeated field (e.g. multiple TCP options) | `list` | |

## Capture metadata

`reader.metadata` returns pcapng block options as a dict. Plain `.pcap` files always return `{}` since pcapng blocks don't exist in that format. `reader.file_type` (e.g. `'pcapng'`) and `reader.snaplen` (per-packet capture byte limit, `0` = unlimited) are available for both formats.

```python
with PcapReader("capture.pcapng") as pcap:
    print(pcap.metadata)
    # {
    #   'shb_userappl': 'Dumpcap (Wireshark) 4.6.x',
    #   'shb_os': 'Linux ...',
    #   'interfaces': [{'name': 'eth0'}, {'name': 'wlan0'}]
    # }
```

## Concurrency

wiresharkffi is **one reader per process** - `libwireshark` uses a process-global memory scope that can only be entered once at a time. Creating two `PcapReader` instances simultaneously crashes with a GLib assertion. The context manager handles this correctly.

For parallel processing across multiple files, use separate processes:

```python
from multiprocessing import Pool
from wiresharkffi import PcapReader

def count_tcp(path):
    with PcapReader(path, display_filter="tcp") as pcap:
        return sum(1 for _ in pcap)

with Pool() as pool:
    counts = pool.map(count_tcp, ["a.pcapng", "b.pcapng", "c.pcapng"])
```

**Threads are not safe** - Wireshark dissectors are **not thread-safe** as the memory scope is process-global, not thread-local. In case you missed it: **not thread safe**.

## Bytes representation

`FT_BYTES` / `FT_UINT_BYTES` fields (e.g. `tcp.options`, `tcp.payload`) are returned as raw
Python `bytes` by default. Use the `bytes_repr` parameter to change the representation:

| Value | Result type | Example |
|---|---|---|
| `'bytes'` (default) | `bytes` | `b'\x01\x01\x08\x0a'` |
| `'hexstring'` | `str` | `'0101080a'` |
| `'ascii'` | `str` | `'ab\x08\x0a'` (printable as-is, non-printable as `\xXX`) |
| `'asciidump'` | `str` | `'ab..'` (printable as-is, non-printable as `.`) |

```python
# JSON-friendly output - no default= workaround needed
with PcapReader("capture.pcapng", bytes_repr="hexstring") as pcap:
    for pkt in pcap:
        print(json.dumps(pkt))

# Human-readable dump
with PcapReader("capture.pcapng", bytes_repr="asciidump") as pcap:
    for pkt in pcap:
        if "tcp.payload" in pkt:
            print(pkt["tcp.payload"])
```

## JSON output

```python
import json
from wiresharkffi import PcapReader

# Option 1: use bytes_repr for fully JSON-serializable output
with PcapReader("capture.pcapng", bytes_repr="hexstring") as pcap:
    for pkt in pcap:
        print(json.dumps(pkt))

# Option 2: keep raw bytes and use default=str as a fallback
with PcapReader("capture.pcapng") as pcap:
    for pkt in pcap:
        print(json.dumps(pkt, default=str))
```

## Architecture

```
src/wiresharkffi/
  _constants.py   - buffer sizes and stream-field table
  _fields.py      - translates the C ws_field_t array into Python dicts
  _prefs.py       - standalone set_preference() function
  _version.py     - version check at import time
  _reader.py      - PcapReader (sync iterator + async generator)
  _ws_build.py    - CFFI build script (cdef + path detection)
  _ws_impl.c      - C helper layer (abstracts WS 4.2 / 4.4 / 4.6 API differences)
```

See [`docs/internals.md`](docs/internals.md) for a detailed walkthrough of how the packet pipeline works.

## Running tests

```bash
pip install -e .[dev]
pytest tests/ -v
```
