"""
_prefs.py - Programmatic Wireshark preference access.
"""

from wiresharkffi._ws import lib as ws


def set_preference(name: str, value: str) -> None:
    """
    Set a Wireshark dissector preference. Equivalent to tshark -o 'name:value'.

    Must be called after at least one PcapReader has been created. Takes effect
    immediately (process-global). Raises ValueError for unknown preference names.
    """
    result = ws._ws_set_pref(name.encode(), str(value).encode())
    if result == -1:  # not initialized
        raise RuntimeError(
            "set_preference() requires epan to be initialized. "
            "Create a PcapReader instance before calling set_preference()."
        )
    if result == 1:   # PREFS_SET_SYNTAX_ERR
        raise ValueError(f"Syntax error in preference {name!r} = {value!r}")
    if result == 2:   # PREFS_SET_NO_SUCH_PREF
        raise ValueError(f"Unknown Wireshark preference: {name!r}")
    # result == 3 (PREFS_SET_OBSOLETE) - silently ignore removed prefs
