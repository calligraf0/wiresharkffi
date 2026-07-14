"""
Tests for the process-global "one active PcapReader" guard.

Split into two groups:
  - direct unit tests against wiresharkffi._guard using plain sentinel objects
    (fast, no libwireshark needed)
  - integration tests through PcapReader that exercise acquire/release via the
    reader lifecycle (open/close, context managers, failed construction).
"""

import threading

import pytest

import wiresharkffi._guard as _guard
from wiresharkffi import PcapReader


@pytest.fixture(autouse=True)
def _reset_guard():
    """Ensure the process-global guard is clean before and after every test.

    Unit tests that pass raw sentinel objects have no __del__/close() path
    that would clear _active on their own, so we reset explicitly to keep
    tests independent.
    """
    _guard._active = None
    yield
    _guard._active = None


# direct unit tests on _guard

def test_acquire_sets_active():
    sentinel = object()
    _guard.acquire(sentinel)
    assert _guard._active == id(sentinel)


def test_release_clears_active():
    sentinel = object()
    _guard.acquire(sentinel)
    _guard.release(sentinel)
    assert _guard._active is None


def test_second_acquire_raises():
    first, second = object(), object()
    _guard.acquire(first)
    with pytest.raises(RuntimeError, match="Another PcapReader is already active"):
        _guard.acquire(second)


def test_release_mismatched_reader_is_noop():
    """release() must only clear _active when it matches the caller's id."""
    holder, imposter = object(), object()
    _guard.acquire(holder)
    _guard.release(imposter)     # different id — must NOT release
    assert _guard._active == id(holder)


def test_acquire_after_release_succeeds():
    """Full acquire/release cycle must be repeatable."""
    for _ in range(3):
        s = object()
        _guard.acquire(s)
        _guard.release(s)
        assert _guard._active is None


def test_release_when_idle_is_noop():
    """release() on an already-clear guard must not raise."""
    _guard.release(object())     # nothing acquired
    assert _guard._active is None


def test_concurrent_acquire_only_one_wins():
    """Under thread contention, exactly one acquire succeeds and the rest raise."""
    barrier = threading.Barrier(8)
    successes: list[object] = []
    failures: list[BaseException] = []
    lock = threading.Lock()

    def worker():
        s = object()
        barrier.wait()           # release all threads together
        try:
            _guard.acquire(s)
        except RuntimeError as exc:
            with lock:
                failures.append(exc)
        else:
            with lock:
                successes.append(s)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(successes) == 1
    assert len(failures) == 7
    assert _guard._active == id(successes[0])


# integration through PcapReader

def test_second_reader_raises_while_first_alive(pcap_path):
    with PcapReader(pcap_path):
        with pytest.raises(RuntimeError, match="Another PcapReader is already active"):
            PcapReader(pcap_path)


def test_reader_releases_on_normal_close(pcap_path):
    """After a reader closes, a fresh one must be constructible."""
    r = PcapReader(pcap_path)
    r.close()
    # Would raise RuntimeError from the guard if release hadn't run.
    with PcapReader(pcap_path):
        pass


def test_context_manager_releases_on_exception(pcap_path):
    """Guard must be released even if the with-block body raises."""
    with pytest.raises(ValueError):
        with PcapReader(pcap_path):
            raise ValueError("boom")
    # Guard should be free again — new reader must succeed.
    with PcapReader(pcap_path):
        pass


def test_failed_construction_releases_guard():
    """A construction that fails inside _init must not leak the guard."""
    with pytest.raises(FileNotFoundError):
        PcapReader("/no/such/file.pcap")
    assert _guard._active is None


def test_failed_construction_via_bad_filter_releases_guard(pcap_path):
    """Same as above but for the display-filter compile failure path."""
    with pytest.raises(ValueError, match="Invalid display filter"):
        PcapReader(pcap_path, display_filter="!!not_valid_syntax!!!")
    assert _guard._active is None


def test_double_close_leaves_guard_clear(pcap_path):
    """close() is idempotent and must not toggle the guard back on."""
    r = PcapReader(pcap_path)
    r.close()
    r.close()
    assert _guard._active is None
