# API Reference

## PcapReader

```python
class PcapReader(path, *, prefs=None, fields=None, display_filter=None,
                 argv0="tshark", load_plugins=False, bytes_repr='bytes')
```

Opens a pcap or pcapng file and exposes its packets as a sync iterator or async generator.
Implements the context manager protocol (`with`/`async with`). Closing the reader, either
by exiting the context manager or calling `close()` directly, releases all libwireshark
resources.

### Parameters

**`path`** `str`  
Path to the capture file. Accepts `.pcap`, `.pcapng`, and compressed variants supported
by the installed libwireshark (typically `.gz`, `.lz4`). Raises `FileNotFoundError` if the
path does not exist, or `OSError` if the file exists but cannot be opened (corrupt,
truncated, unsupported format, permission denied).

**`prefs`** `dict[str, str] | None`  
Wireshark dissector preferences to apply before the first packet is read. Keys and values
use the same format as tshark's `-o` flag: `"module.preference"` and its string value. For
example `{"tcp.desegment_tcp_streams": "TRUE", "tls.keylog_file": "/path/to/keys.log"}`.
Overrides any preferences loaded from the user's Wireshark profile. Raises `ValueError`
for unknown or syntactically invalid preference names.

**`fields`** `set[str] | None`  
Whitelist of field abbreviations. When set, only the listed fields appear in each packet
dict (plus the `_num`, `_ts`, `_caplen`, `_len` metadata keys, and `_streams` if any
whitelisted field is a stream identifier). All other dissected fields are discarded before
the dict is returned. When `None`, every dissected field is included.

Note: libwireshark still fully dissects every packet regardless of this setting - `fields=`
filters the result, it does not skip dissection. To limit which protocols are decoded,
combine `fields=` with a `display_filter=`.

**`display_filter`** `str | None`  
A Wireshark display filter expression. Packets that do not match the filter are skipped
entirely and do not appear in the iteration. The syntax is identical to tshark's `-Y` flag.
Raises `ValueError` at construction time if the expression is syntactically invalid.

When both `display_filter=` and `fields=` are set, the filter is evaluated against the
full dissected tree (all fields available for matching), and `fields=` then limits what
appears in the returned dict.

**`argv0`** `str`  
Program name passed to libwireshark's global init. Affects log messages and certain
path lookups inside Wireshark. **Only the first `PcapReader` created in a process uses
this value** - libwireshark's global init is a one-shot singleton, and subsequent readers
silently ignore `argv0`.

**`load_plugins`** `bool`  
Whether to load Wireshark dissector plugins from the system plugin directory. Same
singleton caveat as `argv0` - only the first reader's value takes effect. Pass
`load_plugins=True` on the very first `PcapReader` created in the process if you need
plugins.

**`bytes_repr`** `str`  
Controls how `FT_BYTES` / `FT_UINT_BYTES` fields are represented in the returned packet
dicts. Accepted values:

| Value | Result type | Description |
|---|---|---|
| `'bytes'` (default) | `bytes` | Raw Python bytes object - current behaviour |
| `'hexstring'` | `str` | Lowercase hex string, e.g. `'0101080a'` |
| `'ascii'` | `str` | Printable ASCII characters as-is; non-printable bytes rendered as `\xXX` - fully JSON-serializable |
| `'asciidump'` | `str` | Printable ASCII characters as-is; non-printable bytes replaced by `.` |

Raises `ValueError` at construction time if an unrecognised value is supplied.

### Iteration

```python
with PcapReader("capture.pcapng") as pcap:
    for pkt in pcap:          # sync
        ...

async with PcapReader("capture.pcapng") as pcap:
    async for pkt in pcap.async_packets():   # async
        ...
```

`__next__` raises `StopIteration` on clean EOF. Raises `IOError` with the wtap error
code if a real read error occurs (truncated file, decompression failure, etc.).

Non-packet records (interface description blocks, statistics blocks, etc.) are silently
skipped - only `REC_TYPE_PACKET` records produce dict entries.

### `async_packets()`

```python
async def async_packets() -> AsyncIterator[dict]
```

Async generator that dispatches each `next()` call to a single-threaded
`ThreadPoolExecutor`. Suitable for use in an `asyncio` event loop without blocking it.
Does not parallelize dissection - libwireshark is not thread-safe.

### `file_type`

```python
@property
def file_type(self) -> str
```

The capture's format name as detected by libwireshark, e.g. `'pcapng'` or `'pcap'`. Available
for both pcap and pcapng files (unlike `metadata`, which is pcapng-only). Raises `RuntimeError`
if the reader is closed.

### `snaplen`

```python
@property
def snaplen(self) -> int
```

The snapshot length (per-packet capture byte limit) recorded in the file header. `0` means
unlimited or not recorded. A packet whose original length exceeds this value was truncated at
capture time (`_caplen < _len`). Raises `RuntimeError` if the reader is closed.

### `metadata`

```python
@property
def metadata(self) -> dict
```

Returns pcapng block options as a dict. The SHB (Section Header Block) fields appear at
the top level; per-interface data is under `"interfaces"` as a list of dicts.

```python
{
    "shb_hardware": "...",          # hardware description (optional)
    "shb_os":       "Linux ...",    # OS where the capture was taken (optional)
    "shb_userappl": "Dumpcap ...",  # application that created the file (optional)
    "interfaces": [                  # one entry per IDB, in order
        {"name": "eth0"},
        {"name": "wlan0", "description": "Wireless adapter"},
    ]
}
```

Absent options are omitted. Plain `.pcap` files always return `{}` - pcapng blocks are
required for any metadata to be present. Raises `RuntimeError` if called on a closed
reader.

### `close()`

```python
def close(self) -> None
```

Releases all libwireshark resources: display filter, dissect state, capture buffer, packet
record, frame data, wtap handle, epan session, and provider funcs - in that order.
Safe to call multiple times; subsequent calls are no-ops. Also called automatically by
`__exit__`, `__aexit__`, and `__del__`.

### `__repr__`

```python
PcapReader('/path/to/file.pcapng', frame 42)
PcapReader('/path/to/file.pcapng', closed)
```

---

## set_preference()

```python
from wiresharkffi import set_preference

def set_preference(name: str, value: str) -> None
```

Sets a single Wireshark dissector preference and applies it immediately. Equivalent to
`prefs={"name": "value"}` on a new `PcapReader`, but usable after the reader is already
created.

**`name`** - preference key in `"module.preference"` format (e.g. `"tcp.desegment_tcp_streams"`)  
**`value`** - preference value as a string (e.g. `"TRUE"`, `"FALSE"`, a file path, etc.)

Raises `RuntimeError` if called before any `PcapReader` has been constructed (libwireshark
must be initialized first). Raises `ValueError` for unknown preference names or
syntactically invalid values. Preferences set with this function are process-global and
affect all subsequent dissection.

---

## Packet dict format

Every packet is a plain `dict` with string keys and JSON-compatible values (except `bytes`
fields, which require `default=str` in `json.dumps`).

### Metadata keys (always present)

| Key | Type | Description |
|---|---|---|
| `_num` | `int` | 1-based frame number |
| `_ts` | `float` | Unix timestamp, float seconds. Wireshark records the time at nanosecond resolution, but packing seconds + nanoseconds into a single IEEE-754 double caps effective precision at roughly a microsecond for present-day timestamps. |
| `_caplen` | `int` | Number of bytes captured |
| `_len` | `int` | Original on-wire packet length |

### `_streams` (present when stream fields are found)

```python
"_streams": {"tcp": 3, "http2": 1}
```

Maps protocol names to stream/conversation identifiers. Populated from the following fields:

| Field | `_streams` key |
|---|---|
| `tcp.stream` | `"tcp"` |
| `udp.stream` | `"udp"` |
| `http2.streamid` | `"http2"` |
| `quic.stream_id` | `"quic"` |
| `sctp.assoc_index` | `"sctp"` |
| `dcerpc.cn_call_id` | `"dcerpc"` |
| `diameter.Session-Id` | `"diameter"` |
| `smb.uid` | `"smb"` |
| `smb2.sesid` | `"smb2"` |

### Protocol field types

| Wireshark field type | Python type | Notes |
|---|---|---|
| `FT_UINT8` … `FT_UINT64`, `FT_CHAR`, `FT_FRAMENUM` | `int` | always unsigned |
| `FT_INT8` … `FT_INT64` | `int` | signed |
| `FT_FLOAT`, `FT_DOUBLE`, `FT_IEEE_11073_*` | `float` | |
| `FT_STRING`, `FT_STRINGZ`, `FT_UINT_STRING`, `FT_STRINGZPAD`, `FT_STRINGZTRUNC` | `str` | |
| `FT_BYTES`, `FT_UINT_BYTES` | `bytes` or `str` | controlled by `bytes_repr=`; default is raw `bytes` |
| `FT_IPv4`, `FT_IPv6`, `FT_ETHER`, `FT_OID`, timestamps, … | `str` | Wireshark's human-readable label |
| repeated field (same abbrev in one packet) | `list` | e.g. multiple TCP options of the same type |

---

## Exceptions

| Exception | Raised when |
|---|---|
| `FileNotFoundError` | the capture path does not exist |
| `OSError` | the file exists but cannot be opened (corrupt, truncated, unsupported format, permission denied) |
| `ValueError` | invalid display filter expression, unknown or bad preference name, unrecognised `bytes_repr` value |
| `RuntimeError` | libwireshark init failed, `set_preference` called before init, metadata accessed on closed reader |
| `IOError` | a wtap read error occurs mid-stream (truncated file, decompression failure) |
| `RuntimeError` (import) | the linked libwireshark version is not 4.2.x, 4.4.x, 4.6.x, or 4.7.x |
