"""
_fields.py - Field extraction from the C-populated ws_field_t array.
"""

from wiresharkffi._ws import ffi
from wiresharkffi._constants import STREAM_FIELDS


def decode_ffi_err(ptr) -> str | None:
    """Return a decoded Python string from a CFFI char* error pointer, or None if NULL."""
    return ffi.string(ptr).decode("utf-8", "replace") if ptr != ffi.NULL else None


def _bytes_asciidump(b: bytes) -> str:
    return ''.join(chr(c) if 32 <= c < 127 else '.' for c in b)


def _bytes_ascii(b: bytes) -> str:
    return ''.join(chr(c) if 32 <= c < 127 else f'\\x{c:02x}' for c in b)


def collect_fields(field_buf, count: int, out: dict, streams: dict,
                   bytes_repr: str = 'bytes') -> None:
    """Translate the ws_field_t array from _ws_walk_tree into `out` and `streams` dicts."""
    _null = ffi.NULL
    _ffi_string = ffi.string
    _ffi_buffer = ffi.buffer

    for i in range(count):
        f = field_buf[i]
        vtype = f.vtype
        if vtype == 0:
            continue

        abbrev = _ffi_string(f.abbrev).decode("utf-8", "replace")

        if vtype <= 2:
            value = int(f.u_val)
        elif vtype <= 4:
            value = int(f.i_val)
        elif vtype == 5:
            value = float(f.d_val)
        elif vtype == 7:
            ptr = f.s_val
            if ptr == _null:
                value = None
            else:
                raw = bytes(_ffi_buffer(ptr, f.u_val))
                if bytes_repr == 'asciidump':
                    value = _bytes_asciidump(raw)
                elif bytes_repr == 'ascii':
                    value = _bytes_ascii(raw)
                elif bytes_repr == 'hexstring':
                    value = raw.hex()
                else:
                    value = raw
        else:
            s = f.s_val
            value = _ffi_string(s).decode("utf-8", "replace") if s != _null else None

        if value is None:
            continue

        existing = out.get(abbrev)
        if existing is None:
            out[abbrev] = value
        elif isinstance(existing, list):
            existing.append(value)
        else:
            out[abbrev] = [existing, value]

        stream_key = STREAM_FIELDS.get(abbrev)
        if stream_key is not None:
            existing_s = streams.get(stream_key)
            if existing_s is None:
                streams[stream_key] = value
            elif isinstance(existing_s, list):
                existing_s.append(value)
            else:
                streams[stream_key] = [existing_s, value]
