"""Lightweight tests for the Socket adapter's output parsing.

Run with:  python -m tests.test_socket_parser   (no pytest required)
"""

from arena.adapters.socket import _collect_alerts, _parse_json

SOCKET_LIKE = (
    "fetching scan...\n"
    '{"packages":[{"name":"color-parser-pro","alerts":['
    '{"type":"installScript","severity":"middle","category":"supplyChainRisk"},'
    '{"type":"networkAccess","severity":"high","category":"supplyChainRisk"}]}]}'
)

BENIGN_LIKE = '{"packages":[{"name":"tinylog","alerts":[]}]}'


def test_parses_json_with_progress_noise():
    payload = _parse_json(SOCKET_LIKE)
    assert payload is not None, "should salvage JSON after a progress line"


def test_collects_alerts_and_flags():
    alerts = _collect_alerts(_parse_json(SOCKET_LIKE))
    assert len(alerts) == 2, alerts
    assert {a["type"] for a in alerts} == {"installScript", "networkAccess"}
    assert all(a["severity"] for a in alerts)


def test_benign_has_no_alerts():
    alerts = _collect_alerts(_parse_json(BENIGN_LIKE))
    assert alerts == []


def test_garbage_returns_none():
    assert _parse_json("not json at all") is None
    assert _parse_json("") is None


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    raise SystemExit(failures)
