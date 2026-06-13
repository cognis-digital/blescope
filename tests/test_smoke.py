"""Smoke tests for BLESCOPE: import the core engine, run it on the demo capture,
and assert real, behavior-driven outcomes. No network access.
"""
import json
import os
import sys


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from blescope import (
    TOOL_NAME,
    TOOL_VERSION,
    analyze_capture,
    load_capture,
    decode_uuid,
    fingerprint_profile,
)
from blescope.cli import main

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "frontdoor_lock.json")


def _load_demo():
    with open(DEMO, "r", encoding="utf-8") as fh:
        return load_capture(fh.read())


def test_metadata():
    assert TOOL_NAME == "blescope"
    assert TOOL_VERSION.count(".") == 2


def test_decode_uuid_known_and_unknown():
    assert decode_uuid("1815", "service") == "Automation IO"
    assert decode_uuid("0x2a56", "characteristic") == "Digital"
    # 128-bit Bluetooth-base UUID reduces to short form
    assert decode_uuid("0000180a-0000-1000-8000-00805f9b34fb", "service") == "Device Information"
    assert "Unknown" in decode_uuid("ffff", "service")


def test_fingerprint_smart_lock():
    capture = _load_demo()
    profile, confidence = fingerprint_profile(capture)
    assert profile == "smart_lock"
    assert confidence > 0.5


def test_analyze_finds_insecure_pairing():
    capture = _load_demo()
    result = analyze_capture(capture)

    assert result.profile == "smart_lock"
    assert result.insecure() is True
    assert result.worst_severity == "critical"

    ids = {f.id for f in result.findings}
    # The headline issues for this lock teardown:
    assert "SMP-JUSTWORKS" in ids
    assert "SMP-LEGACY" in ids
    assert "SMP-WEAKKEY" in ids
    assert "ATT-PLAINTEXT-CTRL" in ids

    # Findings sorted worst-first.
    from blescope.core import SEVERITY_ORDER
    sev_idx = [SEVERITY_ORDER.index(f.severity) for f in result.findings]
    assert sev_idx == sorted(sev_idx)

    # Decoded service/characteristic names present.
    svc_names = {s["name"] for s in result.services}
    assert "Automation IO" in svc_names
    char_names = {c["name"] for c in result.characteristics}
    assert "Digital" in char_names


def test_secure_capture_is_clean():
    secure = {
        "device": {"name": "SecureBand", "address": "11:22:33:44:55:66"},
        "gatt": [
            {"service": "180d", "characteristic": "2a37", "properties": ["notify"]},
            {"service": "180f", "characteristic": "2a19", "properties": ["read"]},
        ],
        "smp": {
            "method": "numeric_comparison",
            "io_capability": "DisplayYesNo",
            "mitm": True,
            "secure_connections": True,
            "bonding": True,
            "max_enc_key_size": 16,
            "oob": False,
        },
        "att_ops": [],
    }
    result = analyze_capture(secure)
    assert result.profile == "fitness_tracker"
    assert result.insecure() is False
    assert result.findings == []


def test_text_capture_fallback():
    text = (
        "device.name: TextLock\n"
        "char: 1815 2a56 read,write,notify\n"
        "smp.method: just_works\n"
        "smp.mitm: false\n"
        "smp.secure_connections: false\n"
        "smp.max_enc_key_size: 7\n"
        "write: 2a56 01\n"
    )
    capture = load_capture(text)
    result = analyze_capture(capture)
    assert result.profile == "smart_lock"
    assert result.insecure()


def test_cli_json_and_exit_code(capsys):
    rc = main(["scan", DEMO, "--format", "json"])
    assert rc == 1  # insecure -> non-zero for CI gate
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["profile"] == "smart_lock"
    assert payload["insecure"] is True
    assert any(f["id"] == "SMP-JUSTWORKS" for f in payload["findings"])


def test_cli_table_runs(capsys):
    rc = main(["scan", DEMO])
    assert rc == 1
    out = capsys.readouterr().out
    assert "VERDICT: INSECURE" in out
    assert "smart_lock" in out


def test_cli_min_severity_gate(capsys):
    # Raising the bar to 'critical' still fails (critical findings exist).
    assert main(["scan", DEMO, "--min-severity", "critical"]) == 1
    capsys.readouterr()


def test_cli_no_command_returns_usage():
    assert main([]) == 2
