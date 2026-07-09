# Recipes

Common patterns and examples.

## Basic iteration

```python
from wiresharkffi import PcapReader

with PcapReader("capture.pcapng") as pcap:
    for pkt in pcap:
        print(pkt["_num"], pkt.get("ip.src"), pkt.get("ip.dst"))
```

## Count packets matching a filter

```python
with PcapReader("capture.pcapng", display_filter="tcp") as pcap:
    count = sum(1 for _ in pcap)
print(f"{count} TCP packets")
```

## Extract specific fields only

```python
with PcapReader("capture.pcapng", fields={"ip.src", "ip.dst", "tcp.stream"}) as pcap:
    for pkt in pcap:
        # only ip.src, ip.dst, tcp.stream (+ _num, _ts, _caplen, _len) are present
        print(pkt.get("ip.src"), "->", pkt.get("ip.dst"))
```

## Collect all unique IPs in a capture

```python
from wiresharkffi import PcapReader

src_ips = set()
with PcapReader("capture.pcapng", fields={"ip.src"}) as pcap:
    for pkt in pcap:
        if "ip.src" in pkt:
            src_ips.add(pkt["ip.src"])
print(src_ips)
```

## Reconstruct TCP stream contents

The `tcp.stream` field is an integer that uniquely identifies a TCP connection within the
capture. Group packets by stream ID to work with individual connections:

```python
from collections import defaultdict
from wiresharkffi import PcapReader

streams = defaultdict(list)
with PcapReader("capture.pcapng", display_filter="tcp", fields={"tcp.stream", "tcp.payload"}) as pcap:
    for pkt in pcap:
        if "tcp.payload" in pkt:
            stream_id = pkt["tcp.stream"]
            streams[stream_id].append(pkt["tcp.payload"])

for sid, chunks in streams.items():
    data = b"".join(chunks)
    print(f"stream {sid}: {len(data)} bytes")
```

## TLS decryption with SSLKEYLOGFILE

Most TLS clients (browsers, curl, Python's `ssl` module) can log session keys when
`SSLKEYLOGFILE` is set in the environment. Once you have the log file:

```python
with PcapReader("tls-capture.pcapng",
                prefs={"tls.keylog_file": "/path/to/sslkeylog.txt"}) as pcap:
    for pkt in pcap:
        uri = pkt.get("http.request.uri")
        code = pkt.get("http.response.code")
        if uri:
            print("GET", uri)
        if code:
            print("HTTP", code)
```

## TLS decryption with RSA private key

Only works for sessions without forward secrecy (static RSA key exchange):

```python
prefs = {
    "tls.keys_list": "192.168.1.1,443,http,/path/to/server.key"
}
with PcapReader("tls-capture.pcapng", prefs=prefs) as pcap:
    for pkt in pcap:
        print(pkt.get("http.request.uri"))
```

## Setting preferences at runtime

Useful when you need to change a preference between readers without recreating the full
reader infrastructure:

```python
from wiresharkffi import PcapReader, set_preference

# Create first reader (this also initializes epan)
with PcapReader("a.pcapng") as pcap:
    packets_a = list(pcap)

# Now change a preference
set_preference("tcp.desegment_tcp_streams", "FALSE")

with PcapReader("b.pcapng") as pcap:
    packets_b = list(pcap)
```

## Processing multiple files in parallel

`libwireshark` is single-reader-per-process, so parallelism requires multiple processes:

```python
from multiprocessing import Pool
from wiresharkffi import PcapReader

def extract_http_uris(path):
    uris = []
    with PcapReader(path, display_filter="http.request", fields={"http.request.uri"}) as pcap:
        for pkt in pcap:
            if "http.request.uri" in pkt:
                uris.append(pkt["http.request.uri"])
    return uris

paths = ["capture1.pcapng", "capture2.pcapng", "capture3.pcapng"]
with Pool() as pool:
    results = pool.map(extract_http_uris, paths)

all_uris = [uri for batch in results for uri in batch]
```

## Async processing

```python
import asyncio
from wiresharkffi import PcapReader

async def process(path):
    async with PcapReader(path) as pcap:
        async for pkt in pcap.async_packets():
            if "http.request.uri" in pkt:
                print(pkt["http.request.uri"])

asyncio.run(process("capture.pcapng"))
```

`async_packets()` dispatches each read to a background thread so the event loop is not
blocked, but it does not parallelise dissection. For CPU-bound parallel dissection,
combine `multiprocessing` with `async` inside each worker.

## JSON output

All packet fields except `bytes` are JSON-serializable. Pass `default=str` to render
byte fields as their `repr`:

```python
import json
from wiresharkffi import PcapReader

with PcapReader("capture.pcapng") as pcap:
    for pkt in pcap:
        print(json.dumps(pkt, default=str))
```

## Checking capture metadata

```python
with PcapReader("capture.pcapng") as pcap:
    m = pcap.metadata
    if "shb_userappl" in m:
        print("Captured with:", m["shb_userappl"])
    for i, iface in enumerate(m.get("interfaces", [])):
        print(f"  Interface {i}: {iface.get('name', 'unknown')}")
    for pkt in pcap:
        ...
```

## Handling truncated or corrupt captures

By default, a read error mid-stream raises `IOError`. Wrap the iteration if you want to
process whatever packets were successfully captured:

```python
from wiresharkffi import PcapReader

with PcapReader("truncated.pcap") as pcap:
    try:
        for pkt in pcap:
            process(pkt)
    except IOError as e:
        print(f"Read stopped early: {e}")
```

## Loading Wireshark plugins

Pass `load_plugins=True` on the **first** `PcapReader` created in the process:

```python
with PcapReader("capture.pcapng", load_plugins=True) as pcap:
    for pkt in pcap:
        ...
```

This must be the first reader. Subsequent readers ignore `load_plugins` because
`libwireshark`'s init is a one-shot singleton.
