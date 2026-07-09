"""
_version.py - Runtime libwireshark version check.
"""

import sys

# The only minor versions tested and known to work.
_SUPPORTED_MINORS = frozenset({2, 4, 6, 7})


def check_libwireshark_version() -> None:
    """Raise RuntimeError early (at import time) if the linked libwireshark is unsupported."""
    try:
        from wiresharkffi._ws import lib as ws
        major = ws._ws_version_major()
        minor = ws._ws_version_minor()
    except (ImportError, AttributeError):
        # Extension not compiled or too old to have version accessors - skip.
        return

    if major != 4 or minor not in _SUPPORTED_MINORS:
        raise RuntimeError(
            f"wiresharkffi requires libwireshark 4.2.x, 4.4.x, 4.6.x or 4.7.x; "
            f"found {major}.{minor}.x. "
            f"Install a supported version and reinstall wiresharkffi."
        )
