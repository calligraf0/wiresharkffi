import pathlib
import pytest

_DATA = pathlib.Path(__file__).parent / "data"


@pytest.fixture(scope="session")
def pcapng_path():
    """Small pcapng file used for basic iteration/format tests."""
    return str(_DATA / "test.pcapng")


@pytest.fixture(scope="session")
def pcapng2_path():
    """Medium pcapng file with HTTP traffic."""
    return str(_DATA / "test2.pcapng")


@pytest.fixture(scope="session")
def pcap_path():
    """Legacy .pcap file for format-compatibility tests."""
    return str(_DATA / "test3.pcap")

@pytest.fixture(scope="session")
def gz_path():
    """Same capture as pcapng_path, gzip-compressed."""
    return str(_DATA / "test.pcapng.gz")

@pytest.fixture(scope="session")
def gz2_path():
    """Small gzip compressed pcapng file with UDP streams."""
    return str(_DATA / "test4.pcapng.gz")


@pytest.fixture(scope="session")
def lz4_path():
    """Same capture as pcapng_path, lz4-compressed."""
    return str(_DATA / "test.pcapng.lz4")
