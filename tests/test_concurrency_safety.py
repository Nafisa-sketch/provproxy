from concurrent.futures import ThreadPoolExecutor

from provproxy.config import CrossCallWindowConfig
from provproxy.crosscall import CrossCallRegistry


def test_registry_window_creation_is_atomic():
    registry = CrossCallRegistry(CrossCallWindowConfig())

    def get_window(_):
        return registry.window_for("s", "d", "src")

    with ThreadPoolExecutor(max_workers=32) as pool:
        windows = list(pool.map(get_window, range(256)))

    assert len({id(w) for w in windows}) == 1
    assert len(registry) == 1


def test_crosscall_record_and_measure_is_thread_safe():
    config = CrossCallWindowConfig(window_max_calls=2000)
    registry = CrossCallRegistry(config)
    window = registry.window_for("s", "d", "src")
    secret = "SYNTHETIC_SHARED_THREAD_SECRET_0123456789"
    chunks = [secret[i:i+3] for i in range(0, len(secret), 3)]
    payloads = (chunks * 40)[:512]

    def record(piece):
        return window.record_and_measure(piece, secret, 4)

    with ThreadPoolExecutor(max_workers=32) as pool:
        transitions = list(pool.map(record, payloads))

    # Calls must complete without deque/dict mutation races, coverage should be
    # monotonic per atomic transition, and enough unique evidence should build.
    assert all(after >= before for before, after in transitions)
    assert (window.accumulated_coverage(secret, 4) or 0.0) >= 0.60


def test_destination_windows_remain_isolated_under_threads():
    registry = CrossCallRegistry(CrossCallWindowConfig())
    secret = "SYNTHETIC_DESTINATION_THREAD_ISOLATION_ABCDEF"
    pieces = [secret[i:i+2] for i in range(0, 16, 2)]

    def record(item):
        i, piece = item
        window = registry.window_for("s", f"dest-{i}", "src")
        return window.record_and_measure(piece, secret, 4)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(record, enumerate(pieces)))

    for i in range(len(pieces)):
        window = registry.window_for("s", f"dest-{i}", "src")
        assert (window.accumulated_coverage(secret, 4) or 0.0) < 0.30
