"""Tests for authorization-gated ACTIVE mode. All offline: MockScanner only,
never a real radio or external host.

The boundary under test:
  * OFF by default (no --authorized -> refuse, exit 2)
  * Non-empty allowlist required (open scope -> refuse)
  * Out-of-scope devices skipped, never probed
  * Rate limit enforced and configurable
  * Loud authorized-use banner emitted before any active op
"""
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from blescope.active import (
    AUTHORIZED_BANNER,
    ActiveConfig,
    ActiveResult,
    MockScanner,
    NullScanner,
    RateLimiter,
    ScopeError,
    load_allowlist,
    normalize_addr,
    run_active,
)
from blescope.cli import main

LOCK_ADDR = "AA:BB:CC:DD:EE:01"
ROGUE_ADDR = "AA:BB:CC:DD:EE:02"

LOCK_CAPTURE = {
    "device": {"name": "DemoLock", "address": LOCK_ADDR},
    "gatt": [{"service": "1815", "characteristic": "2a56",
              "properties": ["read", "write", "notify"]}],
    "smp": {"method": "just_works", "io_capability": "NoInputNoOutput",
            "mitm": False, "secure_connections": False, "max_enc_key_size": 7},
    "att_ops": [{"op": "write", "characteristic": "2a56",
                 "value": "01", "encrypted": False}],
}


def _devices():
    return [
        {"address": LOCK_ADDR, "name": "DemoLock"},
        {"address": ROGUE_ADDR, "name": "RoguePhone"},
    ]


def _scanner():
    return MockScanner(_devices(), {LOCK_ADDR: LOCK_CAPTURE})


# --------------------------------------------------------------------------- #
# normalize_addr
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,expected", [
    ("aa:bb:cc:dd:ee:01", "AA:BB:CC:DD:EE:01"),
    ("AA-BB-CC-DD-EE-01", "AA:BB:CC:DD:EE:01"),
    ("  aa:bb:cc:dd:ee:01  ", "AA:BB:CC:DD:EE:01"),
])
def test_normalize_addr(raw, expected):
    assert normalize_addr(raw) == expected


# --------------------------------------------------------------------------- #
# load_allowlist
# --------------------------------------------------------------------------- #
def test_allowlist_from_comma_list():
    al = load_allowlist("aa:bb:cc:dd:ee:01, AA-BB-CC-DD-EE-02")
    assert al == {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}


def test_allowlist_empty_spec_is_empty():
    assert load_allowlist(None) == set()
    assert load_allowlist("") == set()


def test_allowlist_from_file(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("# my scope\naa:bb:cc:dd:ee:01\nAA:BB:CC:DD:EE:02\n\n",
                 encoding="utf-8")
    al = load_allowlist(str(f))
    assert al == {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}


def test_allowlist_file_ignores_comment_lines(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("#comment only\n", encoding="utf-8")
    assert load_allowlist(str(f)) == set()


# --------------------------------------------------------------------------- #
# ActiveConfig.ensure_gated — the core boundary
# --------------------------------------------------------------------------- #
def test_gate_refuses_without_authorized():
    cfg = ActiveConfig(authorized=False, allowlist={LOCK_ADDR})
    with pytest.raises(ScopeError, match="disabled by default"):
        cfg.ensure_gated()


def test_gate_refuses_empty_allowlist():
    cfg = ActiveConfig(authorized=True, allowlist=set())
    with pytest.raises(ScopeError, match="allowlist"):
        cfg.ensure_gated()


def test_gate_refuses_nonpositive_rate():
    cfg = ActiveConfig(authorized=True, allowlist={LOCK_ADDR}, rate=0)
    with pytest.raises(ScopeError, match="rate"):
        cfg.ensure_gated()


def test_gate_passes_when_fully_specified():
    cfg = ActiveConfig(authorized=True, allowlist={LOCK_ADDR}, rate=5.0)
    cfg.ensure_gated()  # no raise


def test_in_scope_is_case_insensitive():
    cfg = ActiveConfig(authorized=True, allowlist={LOCK_ADDR})
    assert cfg.in_scope("aa:bb:cc:dd:ee:01")
    assert not cfg.in_scope(ROGUE_ADDR)


# --------------------------------------------------------------------------- #
# RateLimiter
# --------------------------------------------------------------------------- #
def test_rate_limiter_rejects_nonpositive():
    with pytest.raises(ScopeError):
        RateLimiter(rate=0)
    with pytest.raises(ScopeError):
        RateLimiter(rate=-1)


def test_rate_limiter_sleeps_when_bucket_empty():
    slept = []
    clock = [0.0]
    rl = RateLimiter(rate=1.0, _clock=lambda: clock[0], _sleep=slept.append)
    rl.acquire()  # first token free
    rl.acquire()  # bucket empty -> must wait
    assert slept and slept[-1] > 0


def test_rate_limiter_no_sleep_when_time_passes():
    slept = []
    clock = [0.0]

    def tick():
        clock[0] += 2.0  # plenty of time between calls
        return clock[0]

    rl = RateLimiter(rate=1.0, _clock=tick, _sleep=slept.append)
    rl.acquire()
    rl.acquire()
    assert slept == []  # refilled enough, never slept


# --------------------------------------------------------------------------- #
# run_active
# --------------------------------------------------------------------------- #
def test_run_active_scopes_and_skips_rogue():
    cfg = ActiveConfig(authorized=True, allowlist={LOCK_ADDR}, rate=1000.0)
    res = run_active(cfg, _scanner(), banner_stream=None)
    assert res.scanned == [LOCK_ADDR]
    assert ROGUE_ADDR in res.skipped_out_of_scope
    assert LOCK_ADDR in res.results
    assert ROGUE_ADDR not in res.results


def test_run_active_analysis_matches_passive():
    cfg = ActiveConfig(authorized=True, allowlist={LOCK_ADDR}, rate=1000.0)
    res = run_active(cfg, _scanner(), banner_stream=None)
    result = res.results[LOCK_ADDR]
    ids = {f.id for f in result.findings}
    assert {"SMP-JUSTWORKS", "ATT-PLAINTEXT-CTRL"} <= ids
    assert result.profile == "smart_lock"
    assert res.to_dict()["insecure"] is True


def test_run_active_emits_banner():
    cfg = ActiveConfig(authorized=True, allowlist={LOCK_ADDR}, rate=1000.0)
    buf = io.StringIO()
    run_active(cfg, _scanner(), banner_stream=buf)
    assert "AUTHORIZED USE ONLY" in buf.getvalue()
    assert buf.getvalue().startswith(AUTHORIZED_BANNER.splitlines()[0])


def test_run_active_refuses_unauthorized_before_io():
    cfg = ActiveConfig(authorized=False, allowlist={LOCK_ADDR})
    with pytest.raises(ScopeError):
        run_active(cfg, _scanner(), banner_stream=None)


def test_run_active_in_scope_but_no_capture_is_empty_analysis():
    # in-scope device that the scanner can't enumerate -> empty capture analysis
    cfg = ActiveConfig(authorized=True, allowlist={ROGUE_ADDR}, rate=1000.0)
    res = run_active(cfg, _scanner(), banner_stream=None)
    assert res.scanned == [ROGUE_ADDR]
    # empty capture -> SMP-NONE
    assert any(f.id == "SMP-NONE" for f in res.results[ROGUE_ADDR].findings)


def test_active_result_to_dict_shape():
    cfg = ActiveConfig(authorized=True, allowlist={LOCK_ADDR}, rate=1000.0)
    d = run_active(cfg, _scanner(), banner_stream=None).to_dict()
    assert d["mode"] == "active"
    assert set(d) == {"mode", "scanned", "skipped_out_of_scope", "results", "insecure"}


# --------------------------------------------------------------------------- #
# NullScanner refuses to fabricate
# --------------------------------------------------------------------------- #
def test_null_scanner_refuses():
    with pytest.raises(ScopeError, match="no BLE backend"):
        NullScanner().discover()
    with pytest.raises(ScopeError):
        NullScanner().connect_and_enumerate(LOCK_ADDR)


# --------------------------------------------------------------------------- #
# CLI scan-live wiring
# --------------------------------------------------------------------------- #
def test_cli_scan_live_requires_authorized(capsys):
    rc = main(["scan-live", "--target-allowlist", LOCK_ADDR])
    assert rc == 2
    assert "authorized" in capsys.readouterr().err.lower()


def test_cli_scan_live_requires_allowlist(capsys):
    rc = main(["scan-live", "--authorized"])
    assert rc == 2
    assert "allowlist" in capsys.readouterr().err.lower()


def test_cli_scan_live_demo_json(capsys):
    rc = main(["scan-live", "--authorized", "--target-allowlist", LOCK_ADDR,
               "--demo", "--format", "json"])
    out = capsys.readouterr().out
    import json as _json
    payload = _json.loads(out)
    assert rc == 1  # demo lock is insecure
    assert payload["mode"] == "active"
    assert LOCK_ADDR in payload["scanned"]
    assert ROGUE_ADDR in payload["skipped_out_of_scope"]


def test_cli_scan_live_demo_table(capsys):
    rc = main(["scan-live", "--authorized", "--target-allowlist", LOCK_ADDR,
               "--demo"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "active report" in out
    assert "out of scope" in out.lower()


def test_cli_scan_live_no_backend_without_demo(capsys):
    # Authorized + scoped but no --demo => NullScanner refuses (no fabrication).
    rc = main(["scan-live", "--authorized", "--target-allowlist", LOCK_ADDR])
    assert rc == 2
    assert "no ble backend" in capsys.readouterr().err.lower()


def test_cli_scan_live_only_rogue_in_scope_clean(capsys):
    # If the only in-scope address never resolves a real lock, exit reflects it.
    rc = main(["scan-live", "--authorized", "--target-allowlist", ROGUE_ADDR,
               "--demo", "--format", "json"])
    assert rc == 1  # rogue resolves to empty capture -> SMP-NONE (medium)
    capsys.readouterr()


def test_cli_scan_live_rate_validation(capsys):
    rc = main(["scan-live", "--authorized", "--target-allowlist", LOCK_ADDR,
               "--rate", "0", "--demo"])
    assert rc == 2
    assert "rate" in capsys.readouterr().err.lower()
