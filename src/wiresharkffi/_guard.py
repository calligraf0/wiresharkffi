import threading

_mu = threading.Lock()
_active: int | None = None # id() of the active reader

def acquire(reader) -> None:
    global _active 
    with _mu:
        if _active is not None:
            raise RuntimeError(
                "Another PcapReader is already active. Libwireshark's epan-state is per process. " \
                "Close the previous reader first or use multiprocessing for parallel dissection."
            )
        _active = id(reader)

def release(reader) -> None:
    global _active
    with _mu:
        if _active == id(reader):
            _active = None