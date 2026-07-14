"""
_reader.py - PcapReader: sync iterator and async generator over pcap/pcapng packets.
"""

from __future__ import annotations

import asyncio
import os
import warnings
from concurrent.futures import ThreadPoolExecutor
from typing import AsyncIterator, Iterator

import wiresharkffi._guard as _guard

try:
    from wiresharkffi._ws import ffi, lib as ws
except ImportError as exc:
    raise ImportError(
        "wiresharkffi._ws extension not found or unloadable. "
        "Run `pip install -e .` or `python3 src/wiresharkffi/_ws_build.py` first."
    ) from exc

from wiresharkffi._constants import (
    CAP_BUF_SIZE, LABEL_BUF_SIZE, MAX_FIELDS, REC_TYPE_PACKET, STREAM_FIELDS,
)
from wiresharkffi._fields import collect_fields, decode_ffi_err

_VALID_BYTES_REPR = frozenset({'bytes', 'asciidump', 'ascii', 'hexstring'})


class PcapReader:
    """
    Sync iterator / async generator over packets in a pcap or pcapng file.

    Uses libwireshark directly via CFFI - no subprocess, full dissector stack.

    Parameters
    ----------
    path           : path to the capture file (pcap or pcapng)
    prefs          : dict of Wireshark preferences to set before dissection
                     (same "module.pref: value" format as tshark -o)
    fields         : set of field abbreviations to include in each packet dict;
                     all other dissected fields are discarded. None returns all fields.
    display_filter : Wireshark display filter expression (same syntax as tshark -Y);
                     non-matching packets are skipped entirely.
    argv0          : program name passed to libwireshark init. Only the first
                     PcapReader created in a process uses this; subsequent readers
                     silently ignore it (libwireshark init is a one-shot singleton).
    load_plugins   : whether to load Wireshark plugins. Same singleton caveat as argv0.
    bytes_repr     : how FT_BYTES / FT_UINT_BYTES fields are represented in the
                     returned packet dicts. One of:
                       'bytes'     - raw Python bytes (default)
                       'hexstring' - lowercase hex string, e.g. '0a0065ff'
                       'ascii'     - printable ASCII as-is, non-printable as \\xXX
                                     (JSON-serializable)
                       'asciidump' - printable ASCII as-is, non-printable as '.'
    """

    def __init__(self, path: str, *, prefs: dict[str, str] | None = None,
                 fields: set[str] | None = None,
                 display_filter: str | None = None,
                 argv0: str = "tshark", load_plugins: bool = False,
                 bytes_repr: str = 'bytes') -> None:
        # Establish everything close()/__del__ touch before any statement that
        # can raise. Argument validation below (and __del__ on a rejected object)
        # would otherwise hit a half-constructed instance. All nullable C pointers
        # start as NULL so close() can free only what was actually allocated.
        self._closed     = False
        self._prov_funcs = ffi.NULL
        self._session    = ffi.NULL
        self._wth        = ffi.NULL
        self._rec        = ffi.NULL
        self._buf        = ffi.NULL
        self._edt        = ffi.NULL
        self._fdata      = ffi.NULL
        self._dfilter    = ffi.NULL

        if bytes_repr not in _VALID_BYTES_REPR:
            raise ValueError(
                f"bytes_repr must be one of {sorted(_VALID_BYTES_REPR)}, got {bytes_repr!r}"
            )
        self._bytes_repr  = bytes_repr
        self._path        = path
        self._prefs       = prefs or {}
        self._fields      = frozenset(fields) if fields else None
        self._filter_text = display_filter
        self._frame_num   = 0
        self._cum_bytes   = 0
        self._iterating   = False   # guards against concurrent async iteration


        _guard.acquire(self)
        try:
            self._init(path, argv0, load_plugins)
        except Exception:
            self.close()
            raise

    def _init(self, path: str, argv0: str, load_plugins: bool) -> None:
        if ws._ws_global_init(argv0.encode(), int(load_plugins)) != 0:
            raise RuntimeError("epan_init failed - is libwireshark installed?")

        for name, value in self._prefs.items():
            result = ws._ws_set_pref(name.encode(), str(value).encode())
            if result == 1:   # PREFS_SET_SYNTAX_ERR
                raise ValueError(f"Syntax error in preference {name!r} = {value!r}")
            if result == 2:   # PREFS_SET_NO_SUCH_PREF
                raise ValueError(f"Unknown Wireshark preference: {name!r}")
            # result == 3 (PREFS_SET_OBSOLETE) - silently ignore removed prefs

        self._prov_funcs = ws._ws_alloc_prov_funcs()
        self._session    = ws.epan_new(ffi.NULL, self._prov_funcs)
        if self._session == ffi.NULL:
            raise RuntimeError("epan_new failed")

        err      = ffi.new("int *")
        err_info = ffi.new("char **")
        self._wth = ws._ws_wtap_open_offline(path.encode(), 0, err, err_info, 0)
        if self._wth == ffi.NULL:
            msg = decode_ffi_err(err_info[0]) or f"error code {err[0]}"
            if err_info[0] != ffi.NULL:
                ws.g_free(err_info[0])
            # Only a genuinely missing path is a FileNotFoundError. A file that
            # exists but can't be opened (corrupt, truncated, unsupported format,
            # permission denied) is a different failure - reporting it as
            # FileNotFoundError would let callers silently swallow real errors.
            if not os.path.exists(path):
                raise FileNotFoundError(f"No such capture file: {path!r}")
            raise OSError(f"Cannot open {path!r}: {msg}")

        self._ftype  = ws.wtap_file_type_subtype(self._wth)
        self._rec    = ws._ws_alloc_rec()
        self._buf    = ffi.new("Buffer *")
        ws.ws_buffer_init(self._buf, CAP_BUF_SIZE)
        self._offset   = ffi.new("gint64 *")
        self._err      = ffi.new("int *")
        self._err_info = ffi.new("char **")
        self._edt      = ws.epan_dissect_new(self._session, True, True)

        if self._filter_text:
            err_buf = ffi.new("char[]", 4096)
            self._dfilter = ws._ws_dfilter_compile(
                self._filter_text.encode(), err_buf, 4096
            )
            if self._dfilter == ffi.NULL:
                msg = ffi.string(err_buf).decode("utf-8", "replace") or "unknown error"
                raise ValueError(f"Invalid display filter {self._filter_text!r}: {msg}")

        # Pre-allocated buffers reused across all packets.
        self._fdata     = ws._ws_alloc_fdata()
        self._field_buf = ffi.new("ws_field_t[]", MAX_FIELDS)
        self._label_buf = ffi.new("char[]",        LABEL_BUF_SIZE)
        self._dropped   = ffi.new("int *")   # label-buffer overflow counter

    def __repr__(self) -> str:
        state = "closed" if self._closed else f"frame {self._frame_num}"
        return f"PcapReader({self._path!r}, {state})"

    def __enter__(self) -> "PcapReader":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    async def __aenter__(self) -> "PcapReader":
        return self

    async def __aexit__(self, *_) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def __iter__(self) -> Iterator[dict]:
        return self

    def __next__(self) -> dict:
        if self._closed:
            raise StopIteration

        while True:
            ok = ws._ws_read(
                self._wth, self._rec, self._buf,
                self._err, self._err_info, self._offset,
            )
            if not ok:
                err_code = self._err[0]
                if err_code != 0:
                    # Real I/O error - free the wtap-allocated error string and raise.
                    if self._err_info[0] != ffi.NULL:
                        ws.g_free(self._err_info[0])
                        self._err_info[0] = ffi.NULL
                    raise IOError(f"capture read error (wtap error code {err_code})")
                raise StopIteration

            if ws._ws_rec_type(self._rec) != REC_TYPE_PACKET:
                continue

            self._frame_num += 1
            pkt = self._dissect()
            if pkt is not None:
                return pkt

    async def async_packets(self) -> AsyncIterator[dict]:
        """Yield packets asynchronously; each read is dispatched to a thread-pool executor.

        A reader wraps a single libwireshark dissect state, so it can only be
        consumed by one iterator at a time. The ``_iterating`` guard rejects a
        second overlapping ``async_packets()`` call on the same reader, which
        would otherwise drive the C state from two contexts at once and corrupt
        it. Note the guard covers async re-entrancy only; the plain sync
        iterator does not set it, so mixing a sync loop and an ``async_packets``
        loop on one reader is still the caller's responsibility to avoid.
        """
        if self._iterating:
            raise RuntimeError(
                "this PcapReader is already being iterated; a reader cannot be "
                "consumed concurrently (one libwireshark dissect state per reader)"
            )
        self._iterating = True
        loop  = asyncio.get_running_loop()
        _stop = object()
        it    = iter(self)
        pool  = ThreadPoolExecutor(max_workers=1)
        try:
            while True:
                pkt = await loop.run_in_executor(pool, lambda: next(it, _stop))
                if pkt is _stop:
                    break
                yield pkt
        finally:
            pool.shutdown(wait=False)
            self._iterating = False

    def _dissect(self) -> dict | None:
        rec  = self._rec
        num  = self._frame_num
        cap  = ws._ws_rec_caplen(rec)
        wlen = ws._ws_rec_len(rec)
        # float can't preserve the full nanosecond resolution wtap carries for
        # present-day epoch seconds; effective precision here is ~microsecond.
        ts   = ws._ws_rec_ts_secs(rec) + ws._ws_rec_ts_nsecs(rec) * 1e-9

        # Reinitialize frame metadata for this packet.
        self._cum_bytes += wlen
        ws._ws_reinit_fdata(self._fdata, num, rec, self._offset[0], self._cum_bytes)

        # Prime the display filter (must happen before each dissect call) and dissect.
        if self._dfilter != ffi.NULL:
            ws.epan_dissect_prime_with_dfilter(self._edt, self._dfilter)
        ws._ws_dissect_run(self._edt, self._ftype, rec, self._buf, self._fdata)

        # Skip packet if it doesn't match the display filter.
        if self._dfilter != ffi.NULL and not ws._ws_dfilter_apply(self._dfilter, self._edt):
            ws.epan_dissect_reset(self._edt)
            return None

        # Walk the dissected tree and collect typed field values.
        fields  = {}
        streams = {}
        tree = ws._ws_edt_tree(self._edt)
        if tree != ffi.NULL:
            count = ws._ws_walk_tree(
                tree, self._field_buf, self._label_buf,
                MAX_FIELDS, LABEL_BUF_SIZE, self._dropped,
            )
            if count == MAX_FIELDS:
                warnings.warn(
                    f"Packet {num}: field extraction reached the {MAX_FIELDS}-entry limit; "
                    "some fields were dropped. Increase MAX_FIELDS in _constants.py if needed.",
                    stacklevel=3,
                )
            if self._dropped[0]:
                warnings.warn(
                    f"Packet {num}: {self._dropped[0]} field(s) dropped because the "
                    f"{LABEL_BUF_SIZE}-byte label buffer was exhausted. "
                    "Increase LABEL_BUF_SIZE in _constants.py if needed.",
                    stacklevel=3,
                )
            collect_fields(self._field_buf, count, fields, streams, self._bytes_repr)

        ws.epan_dissect_reset(self._edt)

        pkt = {
            "_num"    : num,
            "_ts"     : ts,
            "_caplen" : cap,
            "_len"    : wlen,
        }
        if self._fields is not None:
            fields  = {k: v for k, v in fields.items()  if k in self._fields}
            streams = {v: streams[v] for k, v in STREAM_FIELDS.items()
                       if k in self._fields and v in streams}

        if streams:
            pkt["_streams"] = streams
        pkt.update(fields)
        return pkt

    @property
    def file_type(self) -> str:
        """Capture file format name, e.g. 'pcapng' or 'pcap'.

        Reflects the format libwireshark detected when opening the file, which
        is available for both pcap and pcapng captures (unlike metadata, which
        is pcapng-only). Raises RuntimeError if the reader is closed.
        """
        if self._closed:
            raise RuntimeError("reader is closed")
        name = ws._ws_file_type_name(self._wth)
        return ffi.string(name).decode("utf-8", "replace") if name != ffi.NULL else "unknown"

    @property
    def snaplen(self) -> int:
        """Snapshot length (per-packet capture byte limit) from the file header.

        0 means unlimited or not recorded. A packet whose original length
        exceeds this value was truncated at capture time (its _caplen < _len).
        Raises RuntimeError if the reader is closed.
        """
        if self._closed:
            raise RuntimeError("reader is closed")
        return int(ws._ws_snaplen(self._wth))

    @property
    def metadata(self) -> dict:
        """Return pcapng SHB/IDB options as a dict.

        SHB keys (shb_hardware, shb_os, shb_userappl) appear at the top level.
        Interface data appears under 'interfaces': a list of dicts, each with optional
        'name' and 'description' keys, one entry per interface in the capture.
        Absent options are omitted. Plain .pcap files always return {} - pcapng blocks
        are required for any metadata to be present.
        """
        if self._closed:
            raise RuntimeError("reader is closed")
        m = ffi.new("ws_metadata_t *")
        ws._ws_get_metadata(self._wth, m)
        result = {}
        for field in ("shb_hardware", "shb_os", "shb_userappl"):
            ptr = getattr(m, field)
            if ptr != ffi.NULL:
                result[field] = ffi.string(ptr).decode("utf-8", "replace")

        idb_count = ws._ws_get_idb_count(self._wth)
        interfaces = []
        for i in range(idb_count):
            name_p = ffi.new("const char **")
            desc_p = ffi.new("const char **")
            ws._ws_get_idb_strings(self._wth, i, name_p, desc_p)
            entry: dict[str, str] = {}
            if name_p[0] != ffi.NULL:
                entry["name"] = ffi.string(name_p[0]).decode("utf-8", "replace")
            if desc_p[0] != ffi.NULL:
                entry["description"] = ffi.string(desc_p[0]).decode("utf-8", "replace")
            interfaces.append(entry)
        if interfaces:
            result["interfaces"] = interfaces

        return result

    def close(self) -> None:
        """Release all libwireshark resources. Safe to call more than once."""
        try:
            if self._closed:
                return
            self._closed = True
            # Free in reverse-acquisition order: each resource depends on the ones below it.
            if self._dfilter != ffi.NULL:
                ws._ws_dfilter_free(self._dfilter)
                self._dfilter = ffi.NULL
            if self._edt != ffi.NULL:
                ws.epan_dissect_free(self._edt)
                self._edt = ffi.NULL
            if self._buf != ffi.NULL:
                ws.ws_buffer_free(self._buf)
                self._buf = ffi.NULL
            if self._rec != ffi.NULL:
                ws._ws_free_rec(self._rec)
                self._rec = ffi.NULL
            if self._fdata != ffi.NULL:
                ws._ws_free_fdata(self._fdata)
                self._fdata = ffi.NULL
            if self._wth != ffi.NULL:
                ws.wtap_close(self._wth)
                self._wth = ffi.NULL
            if self._session != ffi.NULL:
                ws.epan_free(self._session)
                self._session = ffi.NULL
            if self._prov_funcs != ffi.NULL:
                ws._ws_free_prov_funcs(self._prov_funcs)
                self._prov_funcs = ffi.NULL
        finally:
            _guard.release(self)

    def __del__(self):
        self.close()