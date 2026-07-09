"""
Tests for field extraction behaviour, exercised through real packet data.

Rather than mocking CFFI internals, we open real capture files and assert on
the Python-side results produced by collect_fields.
"""

import pytest
from wiresharkffi import PcapReader


def _all_packets(path: str) -> list[dict]:
    with PcapReader(path) as r:
        return list(r)


# type coercion

def test_string_field_ip_src(pcap_path):
    """ip.src must be decoded as a str (WSF_STR via label fallback)."""
    for pkt in _all_packets(pcap_path):
        if "ip.src" in pkt:
            assert isinstance(pkt["ip.src"], str)
            return


def test_int_field_tcp_srcport(pcap_path):
    """tcp.srcport is FT_UINT16 - must arrive as int."""
    for pkt in _all_packets(pcap_path):
        if "tcp.srcport" in pkt:
            assert isinstance(pkt["tcp.srcport"], int)
            return


def test_int_field_udp_srcport(pcap_path):
    """udp.srcport is FT_UINT16 - must arrive as int."""
    for pkt in _all_packets(pcap_path):
        if "udp.srcport" in pkt:
            assert isinstance(pkt["udp.srcport"], int)
            return


def test_http_request_method_is_string(pcap_path):
    """http.request.method is FT_STRING - must arrive as str."""
    for pkt in _all_packets(pcap_path):
        if "http.request.method" in pkt:
            assert isinstance(pkt["http.request.method"], str)
            assert pkt["http.request.method"] in {"GET", "POST", "PUT", "PATCH",
                                                   "DELETE", "HEAD", "OPTIONS",
                                                   "NOTIFY"}
            return


def test_http_response_code_is_int(pcap_path):
    """http.response.code is FT_UINT16 - must arrive as int."""
    for pkt in _all_packets(pcap_path):
        if "http.response.code" in pkt:
            assert isinstance(pkt["http.response.code"], int)
            assert 100 <= pkt["http.response.code"] < 600
            return


# duplicate fields become a list

def test_duplicate_fields_become_list(pcap_path):
    """
    Protocols with repeated sub-fields (e.g. multiple TCP options of the
    same type) must be stored as a list, not overwritten.
    """
    for pkt in _all_packets(pcap_path):
        for v in pkt.values():
            if isinstance(v, list):
                assert len(v) >= 2
                return
    # Passes vacuously if the fixture has no duplicate fields.


# _streams mirrors the field values

def test_stream_field_matches_streams_dict(pcap_path):
    """tcp.stream value must match _streams["tcp"] in every TCP packet."""
    found = False
    for pkt in _all_packets(pcap_path):
        if "tcp.stream" in pkt and "_streams" in pkt:
            assert pkt["_streams"]["tcp"] == pkt["tcp.stream"]
            found = True
    assert found, "no TCP stream packets found in cap fixture"


def test_no_streams_key_when_no_stream_fields(pcap_path):
    """Packets without any known stream field must not carry _streams."""
    stream_keys = {"tcp.stream", "udp.stream", "http2.streamid",
                   "quic.stream_id", "sctp.assoc_index"}
    for pkt in _all_packets(pcap_path):
        if not stream_keys.intersection(pkt):
            assert "_streams" not in pkt
            return


# FT_BYTES fields return raw bytes

def test_bytes_field_is_bytes_type(pcap_path):
    """FT_BYTES fields (e.g. tcp.options) must be returned as Python bytes, not str."""
    for pkt in _all_packets(pcap_path):
        for key, val in pkt.items():
            if isinstance(val, bytes):
                assert len(val) >= 0  # sanity: valid bytes object
                return
    pytest.fail("no FT_BYTES fields found in cap fixture")


def test_bytes_field_not_label_string(pcapng2_path):
    """tcp.options must be raw bytes, not the old label string like '01 01 08 0a ...'."""
    for pkt in _all_packets(pcapng2_path):
        if "tcp.options" in pkt:
            val = pkt["tcp.options"]
            assert isinstance(val, bytes), f"expected bytes, got {type(val)}: {val!r}"
            return
    pytest.skip("no packets with tcp.options in cap fixture")


# bytes_repr modes

def _packets_with_repr(path: str, mode: str) -> list[dict]:
    with PcapReader(path, bytes_repr=mode) as r:
        return list(r)


def test_bytes_repr_invalid(pcap_path):
    """An unrecognised bytes_repr value must raise ValueError immediately."""
    with pytest.raises(ValueError, match="bytes_repr"):
        PcapReader(pcap_path, bytes_repr="base64")


def test_bytes_repr_bytes_default(pcap_path):
    """Default mode (bytes_repr='bytes') must still produce bytes objects for FT_BYTES."""
    for pkt in _packets_with_repr(pcap_path, 'bytes'):
        for val in pkt.values():
            if isinstance(val, list):
                for item in val:
                    assert not isinstance(item, (bytearray,)), "unexpected bytearray"
            # bytes objects are fine - that's the expected type
    # verify at least one bytes value exists (same assertion as test_bytes_field_is_bytes_type)
    found = any(
        isinstance(v, bytes)
        for pkt in _packets_with_repr(pcap_path, 'bytes')
        for v in pkt.values()
    )
    assert found, "no FT_BYTES fields found; cannot verify 'bytes' mode"


def test_bytes_repr_hexstring(pcap_path):
    """bytes_repr='hexstring' must return lowercase hex strings for FT_BYTES fields."""
    import re
    hex_re = re.compile(r'^[0-9a-f]*$')
    # Collect field keys that carry bytes in default mode
    bytes_keys = {
        k for pkt in _all_packets(pcap_path) for k, v in pkt.items()
        if isinstance(v, bytes)
    }
    if not bytes_keys:
        pytest.skip("no FT_BYTES fields found in cap fixture")
    for pkt in _packets_with_repr(pcap_path, 'hexstring'):
        for k in bytes_keys:
            if k in pkt:
                vals = pkt[k] if isinstance(pkt[k], list) else [pkt[k]]
                for v in vals:
                    assert isinstance(v, str), f"{k}: expected str, got {type(v)}"
                    assert hex_re.match(v), f"{k}: not a hex string: {v!r}"


def test_bytes_repr_ascii(pcap_path):
    """bytes_repr='ascii' must return str with \\xXX escapes for non-printable bytes."""
    import re
    # printable ASCII or \xNN sequences only
    ascii_re = re.compile(r'^([ -~]|\\x[0-9a-f]{2})*$')
    bytes_keys = {
        k for pkt in _all_packets(pcap_path) for k, v in pkt.items()
        if isinstance(v, bytes)
    }
    if not bytes_keys:
        pytest.skip("no FT_BYTES fields found in cap fixture")
    for pkt in _packets_with_repr(pcap_path, 'ascii'):
        for k in bytes_keys:
            if k in pkt:
                vals = pkt[k] if isinstance(pkt[k], list) else [pkt[k]]
                for v in vals:
                    assert isinstance(v, str), f"{k}: expected str, got {type(v)}"
                    assert ascii_re.match(v), f"{k}: unexpected chars in ascii repr: {v!r}"


def test_bytes_repr_asciidump(pcap_path):
    """bytes_repr='asciidump' must return str containing only printable ASCII and '.'."""
    bytes_keys = {
        k for pkt in _all_packets(pcap_path) for k, v in pkt.items()
        if isinstance(v, bytes)
    }
    if not bytes_keys:
        pytest.skip("no FT_BYTES fields found in cap fixture")
    for pkt in _packets_with_repr(pcap_path, 'asciidump'):
        for k in bytes_keys:
            if k in pkt:
                vals = pkt[k] if isinstance(pkt[k], list) else [pkt[k]]
                for v in vals:
                    assert isinstance(v, str), f"{k}: expected str, got {type(v)}"
                    assert all(
                        32 <= ord(c) < 127 for c in v
                    ), f"{k}: non-printable char in asciidump: {v!r}"


def test_bytes_repr_no_raw_bytes_in_non_bytes_modes(pcap_path):
    """In hexstring/ascii/asciidump modes no packet value should be a raw bytes object."""
    for mode in ('hexstring', 'ascii', 'asciidump'):
        for pkt in _packets_with_repr(pcap_path, mode):
            for v in pkt.values():
                items = v if isinstance(v, list) else [v]
                for item in items:
                    assert not isinstance(item, bytes), (
                        f"mode={mode!r}: unexpected bytes object for value {item!r}"
                    )


# frame.protocols

def test_frame_protocols_is_string(pcap_path):
    """frame.protocols must be a colon-separated string."""
    for pkt in _all_packets(pcap_path):
        if "frame.protocols" in pkt:
            assert isinstance(pkt["frame.protocols"], str)
            assert ":" in pkt["frame.protocols"]
            return
