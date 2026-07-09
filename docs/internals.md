# Internals

This document explains how `wiresharkffi` works under the hood: the design of the C/Python
boundary, why each layer exists, and how a pcap file becomes a Python dict.

## The problem with alternatives

The standard way to use Wireshark from Python is to call `tshark -T json` via subprocess.

The lower-level alternative is to call `libwireshark` directly via ctypes or CFFI. `libwireshark`
is the shared library that both tshark and the Wireshark GUI use internally - all the
dissectors live there. Calling it directly eliminates spawning a subprocess and the JSON round-trip,
giving you access to the typed field values instead of parsing Wireshark's string representation.

The main drawback is that `libwireshark`'s API is C, and changes between releases. 
`wiresharkffi` wraps it in a thin C helper layer and attempts to mitigate version differences
exposing a stable interface to Python.

## Layers

```
Python (_reader.py)
    |
    |  CFFI
    v
C helpers (_ws_impl.c)          <- version-adaptive wrappers
    |
    |  function calls
    v
libwireshark / libwiretap       <- Wireshark's own shared libraries
```

**CFFI** compiles a C extension at install time. The `cdef` in `_ws_build.py`
declares the types and function signatures Python can call; the C source in `_ws_impl.c`
provides the implementations. This is faster than `ctypes` (no runtime type overhead) and
"safer" than raw ctypes.

**`_ws_impl.c`** exists because `libwireshark`'s API is not stable across minor versions. A
non-exhaustive list of things that changed between 4.2 and 4.4:

- `wtap_read` lost its `Buffer *` parameter (the buffer became internal to wtap)
- `epan_dissect_run` lost its `tvbuff_t *` parameter (the tvb is now created internally)
- `wtap_rec_init` gained a size hint parameter
- `packet_provider_funcs` callback signatures changed
- `proto_item_fill_label` gained a `value_offset` output parameter
- `ws_log_init` and `configuration_init` changed signatures

And between 4.6 and 4.7:

- `ws_log_init` gained a `console_title` parameter (Windows-only)
- `configuration_init` gained an `app_flavor_lower` parameter (config subdir name)
- `wtap_init` gained `app_env_var_prefix` and file-extension registration parameters
- `wtap_open_offline` gained the same `app_env_var_prefix`
- `epan_init` gained an `epan_app_data_t *app_data` parameter that carries the env-var
  prefix and the dissector registration callbacks (previously hard-coded inside
  `libwireshark`)

Rather than putting `#if` guards throughout Python or the cdef, all version-sensitive code
is isolated in `_ws_impl.c` behind a single macro:

```c
#define _WS_VERSION_GE(maj, min) \
    (WIRESHARK_VERSION_MAJOR > (maj) || \
     (WIRESHARK_VERSION_MAJOR == (maj) && WIRESHARK_VERSION_MINOR >= (min)))
```

The cdef and `_reader.py` see a stable API regardless of which Wireshark version is
installed. Adding support for a new Wireshark release typically means touching only
`_ws_impl.c` and `_version.py`.

## Initialization

`libwireshark` has process-global state that must be set up once before any dissection. This
includes logging, process policies, configuration paths, the wtap file type registry, the
epan dissector registry, and user preferences. `_ws_global_init` in `_ws_impl.c` performs
all of it and uses a GLib mutex to make the one-shot guarantee thread-safe:

```c
G_LOCK(ws_init_lock);
if (_ws_init_done) { G_UNLOCK(ws_init_lock); return 0; }
_ws_init_done = 1;
G_UNLOCK(ws_init_lock);
// epan_init called here, outside the lock
```

The lock is released before `epan_init` runs. This is intentional: `epan_init` is slow
(it registers every built-in dissector) and must not be called re-entrantly. A racing
thread that sees `_ws_init_done = 1` and calls an epan API before init completes is an
accepted hazard - in practice PcapReaders are not constructed simultaneously from multiple
threads.

Beyond global init, each `PcapReader` owns:

- an `epan_t` session (one per reader, wraps the global epan state)
- a `wtap *` handle (the open file)
- a pre-allocated `wtap_rec` (packet record, reused across all packets in the file)
- a pre-allocated `Buffer` (capture buffer for WS 4.2; WS 4.4+ manages it internally)
- a pre-allocated `epan_dissect_t` (the dissect engine, reset between packets)
- a pre-allocated `frame_data` (frame metadata, reinitialized between packets)
- a pre-allocated `ws_field_t[]` array and label buffer (for tree walking)
- optionally a compiled `dfilter_t` (display filter)

To avoid per-packet `malloc`/`free` calls we pre-allocate whenever possible. 

## Per-packet pipeline

For each packet, `__next__` and `_dissect` together execute this sequence:

### 1. Read

```c
wtap_read(wth, rec, err, err_info, offset)   // WS 4.4+
```

`wtap_read` fills the `wtap_rec` with the packet's raw bytes, timestamp, lengths, and record
type. It returns `false` on both clean EOF and real I/O errors; the caller distinguishes them
by checking `*err` (0 = EOF, non-zero = error code).

Non-`REC_TYPE_PACKET` records (interface description updates, statistics, etc.) are skipped
with `continue` - only actual packet records proceed to dissection.

### 2. Reinitialize frame_data

`frame_data` holds Wireshark's frame-level metadata: frame number, timestamps, cumulative
byte count, flags. It must be reinitialized for each packet. Rather than allocating a new
`frame_data` per packet:

```c
frame_data_destroy(fd);
memset(fd, 0, sizeof(*fd));
frame_data_init(fd, num, rec, offset, cum_bytes);
```

The same allocation is reused across all packets in the file.

### 3. Prime the display filter

If a display filter was compiled at construction time, it must be "primed" into the dissect
state before each dissection call:

```c
epan_dissect_prime_with_dfilter(edt, dfilter);
```

Priming tells epan which fields the filter references so they are guaranteed to be populated
during dissection. This must happen before every `epan_dissect_run` call because
`epan_dissect_reset` clears it.

### 4. Dissect

```c
epan_dissect_run(edt, ftype, rec, fd, NULL);   // WS 4.4+
```

This is the main Wireshark dissection call. It runs the full dissector stack for the packet,
populating the `proto_tree` inside `edt` with every field and value at every protocol layer.
The `NULL` column info argument means we don't pay the cost of rendering the display columns.

### 5. Filter check

After dissection (not before - the tree must be fully populated for the filter to evaluate):

```c
dfilter_apply_edt(dfilter, edt)
```

If this returns false, `epan_dissect_reset` discards the tree and the packet is skipped.
No Python object is created for it.

### 6. Tree walk

The proto_tree is a GLib n-ary tree where each node is a `proto_node` containing a
`field_info` with the field's header, type, and value. Walking it with CFFI calls would
mean one Python -> C call, per node - potentially thousands per packet.

Instead, `_ws_walk_tree` in `_ws_impl.c` walks the entire tree in a single C call and
fills a pre-allocated `ws_field_t[]` array:

```c
typedef struct {
    const char *abbrev;   // points into hfinfo table (permanent storage)
    const char *s_val;    // string pointer (wmem pool or label_buf)
    uint64_t    u_val;    // unsigned integer or byte count
    int64_t     i_val;    // signed integer
    double      d_val;    // float/double
    int         ftype;    // ftenum_t
    int         vtype;    // 0=none 1=u32 2=u64 3=i32 4=i64 5=dbl 6=str 7=bytes
} ws_field_t;
```

The `abbrev` pointer is a permanent string in the hfinfo registry - safe to hold across
`epan_dissect_reset`. String values (`s_val` for `vtype=6`) point into wmem pool memory
that is valid until `epan_dissect_reset`, which happens in the same Python frame.

For fields with a pre-rendered representation (most nodes when `proto_tree_visible=TRUE`),
`s_val` points directly to `fi->rep->representation` - zero copy. For the rare node that
has no pre-rendered rep, `proto_item_fill_label` writes into a 240-byte slot of the
pre-allocated `label_buf`.

### 7. Field collection

`collect_fields` in `_fields.py` iterates the `ws_field_t[]` array and builds the Python
dict. All value extraction happens here - integers via `f.u_val`/`f.i_val`, floats via
`f.d_val`, strings via `ffi.string(f.s_val)`, bytes via `ffi.buffer(f.s_val, f.u_val)`.

Duplicate abbreviations (the same field key appearing more than once in a packet, e.g.
multiple TCP options of the same type) are coerced to `list` at this point.

Stream fields (`tcp.stream`, `udp.stream`, etc.) are detected during the same loop and
accumulated into the `streams` dict.

### 8. Reset

`epan_dissect_reset(edt)` discards the proto_tree and releases wmem packet memory. The
`epan_dissect_t` is then ready for the next packet. This is why all string pointers into
wmem memory must be copied to Python strings before this call - which `collect_fields`
guarantees.

## Memory management

`libwireshark` uses wmem (Wireshark memory manager), which manages memory in scopes:

- **file scope** - lives for the duration of the open file (entered on `epan_new`, exited
  on `epan_free`)
- **packet scope** - lives for the duration of one dissection (entered inside
  `epan_dissect_run`, exited by `epan_dissect_reset`)

The `abbrev` strings returned in `ws_field_t` point to hfinfo-registered strings (permanent,
outside wmem). The `s_val` strings for label-based fields point into packet-scope wmem and
are only valid until `epan_dissect_reset`. `collect_fields` runs before the reset and copies
all strings to Python objects, so there are no dangling pointers after reset.

Python-owned memory (`ffi.new(...)` objects) is managed by CFFI and Python's GC. All C
resources are freed in `close()` in reverse-acquisition order: display filter -> dissect
state -> capture buffer -> packet record -> frame data -> wtap handle -> epan session ->
provider funcs. This order matters because each layer may reference the ones below it.

`__del__` calls `close()` as a safety net for readers that are abandoned without a context
manager, preventing wmem scope leaks that would crash any subsequent reader.

## Display filter compilation

Wireshark's display filter compiler (`dfilter_compile_full`) requires `dfilter-loc.h`, an
internal generated header that is not installed by ``libwireshark`-dev`. To work around this,
`_ws_impl.c` forward-declares only the pieces it needs - the opaque `dfilter_t` struct, a
partial `df_error_t` (omitting the `df_loc_t loc` field), and the function signatures with
`extern` linkage. This is safe as long as we never access the `loc` field or pass
`df_error_t` by value.

The error message is written into a caller-supplied `char[4096]` buffer by `_ws_dfilter_compile`
so that Python can read it without needing a separate `g_free` call for the error object.

## Version support policy

The library supports `libwireshark` 4.2.x, 4.4.x, 4.6.x, and 4.7.x. The version check in
`_version.py` runs at import time. Adding a new minor version (e.g. 4.8) requires:

1. Auditing `_ws_impl.c` for API changes and adding `_WS_VERSION_GE(4, 8)` guards where needed
2. Adding `8` to `_SUPPORTED_MINORS` in `_version.py`
3. Updating version strings in `_ws_build.py` docstring and `_ws_impl.c` header comment
4. Testing against the new version

The cdef in `_ws_build.py` rarely needs changes for new versions - the whole point of the C
helper layer is to absorb version differences before they reach the cdef. When a version does
change a signature Python calls directly, wrap it in a new `_ws_*` helper (see
`_ws_wtap_open_offline` for 4.7's `app_env_var_prefix` addition).

Some `libwireshark` parameters look optional but are dereferenced deep in init; when in doubt,
pass the same values tshark's `main()` passes.
