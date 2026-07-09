"""
Integration tests for PcapReader.  Each test opens a real capture file so
the full CFFI/libwireshark stack is exercised.
"""

import asyncio
import pytest
from wiresharkffi import PcapReader


# helpers

def _all_packets(path: str) -> list[dict]:
    with PcapReader(path) as r:
        return list(r)


# basic iteration

def test_context_manager_closes(pcapng_path):
    with PcapReader(pcapng_path) as r:
        assert not r._closed
    assert r._closed


def test_iter_yields_packets(pcapng_path):
    pkts = _all_packets(pcapng_path)
    assert len(pkts) > 0


def test_packet_required_keys(pcapng_path):
    for pkt in _all_packets(pcapng_path):
        assert "_num"    in pkt
        assert "_ts"     in pkt
        assert "_caplen" in pkt
        assert "_len"    in pkt


def test_packet_types(pcapng_path):
    for pkt in _all_packets(pcapng_path):
        assert isinstance(pkt["_num"],    int)
        assert isinstance(pkt["_ts"],     float)
        assert isinstance(pkt["_caplen"], int)
        assert isinstance(pkt["_len"],    int)


def test_packet_numbering_is_sequential(pcapng_path):
    pkts = _all_packets(pcapng_path)
    for i, pkt in enumerate(pkts, start=1):
        assert pkt["_num"] == i


def test_timestamps_are_positive(pcapng_path):
    for pkt in _all_packets(pcapng_path):
        assert pkt["_ts"] > 0


def test_captured_length_within_wire_length(pcapng_path):
    """Captured bytes are positive and never exceed the original on-wire length."""
    for pkt in _all_packets(pcapng_path):
        assert pkt["_caplen"] > 0
        assert pkt["_caplen"] <= pkt["_len"]


# stream tracking

def test_streams_dict_present_for_tcp(pcap_path):
    """Every TCP packet must carry _streams["tcp"] equal to tcp.stream."""
    found = False
    for pkt in _all_packets(pcap_path):
        if "tcp.stream" in pkt:
            assert "_streams" in pkt
            assert pkt["_streams"]["tcp"] == pkt["tcp.stream"]
            found = True
    assert found, "no TCP stream packets found in cap fixture"


def test_streams_dict_present_for_udp(gz2_path):
    """Every UDP packet that exposes udp.stream must carry _streams["udp"]."""
    found = False
    for pkt in _all_packets(gz2_path):
        if "udp.stream" in pkt:
            assert "_streams" in pkt
            assert pkt["_streams"]["udp"] == pkt["udp.stream"]
            found = True
    assert found, "no UDP stream packets found in cap fixture"


# HTTP field tests

def test_http_request_fields(pcap_path):
    """HTTP GET packets must carry string method and URI fields."""
    for pkt in _all_packets(pcap_path):
        if pkt.get("http.request.method") == "GET":
            assert isinstance(pkt["http.request.uri"], str)
            assert pkt["http.request.uri"].startswith("/")
            return
    pytest.fail("no HTTP GET packets found in cap fixture")


def test_http_response_code_range(pcap_path):
    """HTTP response codes must be valid 3-digit integers."""
    found = False
    for pkt in _all_packets(pcap_path):
        if "http.response.code" in pkt:
            code = pkt["http.response.code"]
            assert isinstance(code, int)
            assert 100 <= code < 600
            found = True
    assert found, "no HTTP response packets found in cap fixture"


# preferences

def test_prefs_unknown_pref_raises(pcapng_path):
    """An unknown preference name must raise ValueError before any packets are read."""
    with pytest.raises(ValueError, match="Unknown Wireshark preference"):
        PcapReader(pcapng_path, prefs={"nonexistent.nosuchpref": "1"})


def test_prefs_valid_pref_reads_packets(pcapng_path):
    """A reader created with a valid prefs dict must still yield packets normally."""
    with PcapReader(pcapng_path, prefs={"tcp.desegment_tcp_streams": "TRUE"}) as r:
        pkts = list(r)
    assert len(pkts) > 0


def test_set_preference_unknown_raises(pcap_path):
    """Standalone set_preference must raise ValueError for an unknown preference."""
    from wiresharkffi import set_preference
    with PcapReader(pcap_path):
        pass   # ensures epan init has run
    with pytest.raises(ValueError):
        set_preference("nonexistent.nosuchpref", "1")


def test_set_preference_valid(pcap_path):
    """Standalone set_preference must not raise for a known, valid preference."""
    from wiresharkffi import set_preference
    with PcapReader(pcap_path):
        pass
    # Toggle and restore so this test doesn't pollute the global epan preference state.
    # "TRUE" is the Wireshark default for tcp.desegment_tcp_streams.
    set_preference("tcp.desegment_tcp_streams", "FALSE")
    set_preference("tcp.desegment_tcp_streams", "TRUE")


# error handling

def test_file_not_found_raises():
    with pytest.raises(FileNotFoundError):
        PcapReader("/no/such/file.pcap")


def test_double_close_is_safe(pcapng_path):
    r = PcapReader(pcapng_path)
    r.close()
    r.close()  # must not raise


# compressed format support

def test_gz_compressed_format(gz_path, pcapng_path):
    """A gzip-compressed pcapng must yield the same packet count as the plain file."""
    assert len(_all_packets(gz_path)) == len(_all_packets(pcapng_path))


def test_lz4_compressed_format(lz4_path, pcapng_path):
    """An lz4-compressed pcapng must yield the same packet count as the plain file."""
    assert len(_all_packets(lz4_path)) == len(_all_packets(pcapng_path))


# .pcap format

def test_legacy_pcap_format(pcap_path):
    """Read the first few packets from a classic .pcap file."""
    count = 0
    with PcapReader(pcap_path) as r:
        for pkt in r:
            count += 1
            assert "_num" in pkt
            if count >= 5:
                break
    assert count == 5


# async interface

def test_async_packets_yields_same_count(pcapng_path):
    sync_count = len(_all_packets(pcapng_path))

    async def _count():
        n = 0
        async with PcapReader(pcapng_path) as r:
            async for _ in r.async_packets():
                n += 1
        return n

    assert asyncio.run(_count()) == sync_count


def test_async_context_manager_closes(pcapng_path):
    async def _run():
        async with PcapReader(pcapng_path) as r:
            assert not r._closed
        return r._closed

    assert asyncio.run(_run())


# display filter

def test_filter_tcp_only(pcap_path):
    """display_filter='tcp' must return only packets that carry a TCP layer."""
    with PcapReader(pcap_path, display_filter="tcp") as r:
        pkts = list(r)
    assert len(pkts) > 0
    for pkt in pkts:
        assert any(k == "tcp" or k.startswith("tcp.") for k in pkt), \
            f"packet {pkt['_num']} matched 'tcp' filter but has no tcp.* field"


def test_filter_reduces_packet_count(pcapng2_path):
    """Filtered reader must yield fewer packets than the unfiltered reader."""
    with PcapReader(pcapng2_path, display_filter="http") as r:
        http_count = sum(1 for _ in r)
    with PcapReader(pcapng2_path) as r:
        all_count = sum(1 for _ in r)
    assert 0 < http_count < all_count


def test_filter_invalid_raises(pcap_path):
    """An invalid display filter expression must raise ValueError at construction."""
    with pytest.raises(ValueError, match="Invalid display filter"):
        PcapReader(pcap_path, display_filter="!!not_valid_syntax!!!")


# field whitelist

def test_fields_whitelist_limits_keys(pcap_path):
    """fields= must return only the requested keys (plus _num/_ts/_caplen/_len)."""
    wanted = {"ip.src", "ip.dst"}
    with PcapReader(pcap_path, fields=wanted) as r:
        for pkt in r:
            pkt_fields = {k for k in pkt if not k.startswith("_")}
            assert pkt_fields <= wanted, f"unexpected fields: {pkt_fields - wanted}"
            break  # check just the first packet


def test_fields_whitelist_non_matching_empty(pcap_path):
    """Requesting a field not present in any packet yields empty field sets."""
    with PcapReader(pcap_path, fields={"x.no.such.field"}) as r:
        for pkt in r:
            assert "x.no.such.field" not in pkt
            break


# metadata

def test_metadata_is_dict(pcap_path):
    """metadata property must return a dict (may be empty for plain pcap)."""
    with PcapReader(pcap_path) as r:
        m = r.metadata
    assert isinstance(m, dict)


def test_metadata_pcapng_has_app(pcapng_path):
    """A pcapng captured with Wireshark must expose shb_userappl."""
    with PcapReader(pcapng_path) as r:
        m = r.metadata
    assert "shb_userappl" in m
    assert isinstance(m["shb_userappl"], str)


def test_metadata_closed_raises(pcap_path):
    """Accessing metadata on a closed reader must raise RuntimeError."""
    r = PcapReader(pcap_path)
    r.close()
    with pytest.raises(RuntimeError, match="closed"):
        _ = r.metadata


def test_metadata_idempotent(pcap_path):
    """Calling metadata twice must return the same result."""
    with PcapReader(pcap_path) as r:
        m1 = r.metadata
        m2 = r.metadata
    assert m1 == m2


# second pcapng fixture (HTTP traffic)

def test_pcapng2_yields_http_fields(pcapng2_path):
    """The medium HTTP fixture must yield packets that include HTTP fields."""
    pkts = _all_packets(pcapng2_path)
    assert len(pkts) > 0
    assert any(
        any(k == "http" or k.startswith("http.") for k in pkt)
        for pkt in pkts
    ), "expected HTTP fields in test2.pcapng"


# file_type / snaplen accessors

def test_file_type_pcapng(pcapng_path):
    """file_type must report the pcapng format for a pcapng capture."""
    with PcapReader(pcapng_path) as r:
        assert "pcapng" in r.file_type.lower()


def test_file_type_pcap(pcap_path):
    """file_type must report the pcap format for a legacy .pcap capture."""
    with PcapReader(pcap_path) as r:
        assert "pcap" in r.file_type.lower()


def test_snaplen_is_non_negative_int(pcapng_path):
    """snaplen must be a non-negative int (0 = unlimited/unrecorded)."""
    with PcapReader(pcapng_path) as r:
        assert isinstance(r.snaplen, int)
        assert r.snaplen >= 0


def test_file_type_closed_raises(pcap_path):
    """Accessing file_type on a closed reader must raise RuntimeError."""
    r = PcapReader(pcap_path)
    r.close()
    with pytest.raises(RuntimeError, match="closed"):
        _ = r.file_type


def test_snaplen_closed_raises(pcap_path):
    """Accessing snaplen on a closed reader must raise RuntimeError."""
    r = PcapReader(pcap_path)
    r.close()
    with pytest.raises(RuntimeError, match="closed"):
        _ = r.snaplen
