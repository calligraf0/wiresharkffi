"""
wiresharkffi - libwireshark-backed pcap/pcapng reader via CFFI.

Full dissector stack, no subprocess, sync and async interfaces.
"""

from wiresharkffi._reader import PcapReader
from wiresharkffi._prefs import set_preference
from wiresharkffi._version import check_libwireshark_version

check_libwireshark_version()

__all__ = ["PcapReader", "set_preference"]
__version__ = "0.1.0"
