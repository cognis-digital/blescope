"""Tests for SARIF export, the VERSION-file wiring, and the demo corpus.

Every demo capture is scanned through the real CLI and asserted to produce
its intended profile/finding/exit-code, so a broken demo fails CI.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from blescope import TOOL_NAME, TOOL_VERSION, analyze_capture, load_capture
from blescope.cli import main

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEMOS = os.path.join(ROOT, "demos")


def _scan_json(path, capsys):
    rc = main(["scan", path, "--format", "json"])
    out = capsys.readouterr().out
    return rc, json.loads(out)


def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return load_capture(fh.read())


# --------------------------------------------------------------------------- #
# VERSION wiring
# --------------------------------------------------------------------------- #
def test_version_matches_version_file():
    with open(os.path.join(ROOT, "VERSION"), "r", encoding="utf-8") as fh:
        file_version = fh.read().strip()
    assert TOOL_VERSION == file_version
    assert TOOL_NAME == "blescope"


# --------------------------------------------------------------------------- #
# SARIF export
# --------------------------------------------------------------------------- #
def test_sarif_shape_and_levels(capsys):
    demo = os.path.join(DEMOS, "01-basic", "frontdoor_lock.json")
    rc = main(["scan", demo, "--format", "sarif"])
    assert rc == 1
    sarif = json.loads(capsys.readouterr().out)

    assert sarif["version"] == "2.1.0"
    assert "sarif-2.1.0" in sarif["$schema"]
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "blescope"
    assert driver["version"] == TOOL_VERSION

    # One rule per distinct finding id; one result per finding.
    result_ids = [r["ruleId"] for r in run["results"]]
    rule_ids = [r["id"] for r in driver["rules"]]
    assert set(rule_ids) == set(result_ids)
    assert len(rule_ids) == len(set(rule_ids))  # rules are de-duplicated
    assert "SMP-JUSTWORKS" in rule_ids

    # critical/high -> error, medium -> warning.
    levels = {r["level"] for r in run["results"]}
    assert levels <= {"error", "warning", "note"}
    assert "error" in levels  # this capture has critical findings

    # GitHub code-scanning security-severity is present and numeric-looking.
    for rule in driver["rules"]:
        sev = rule["properties"]["security-severity"]
        float(sev)  # raises if not numeric

    # artifactLocation reflects the scanned path.
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.endswith("frontdoor_lock.json")


def test_sarif_clean_capture_has_no_results(capsys):
    demo = os.path.join(DEMOS, "09-secure-lock", "secure_deadbolt.json")
    rc = main(["scan", demo, "--format", "sarif"])
    assert rc == 0
    sarif = json.loads(capsys.readouterr().out)
    run = sarif["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_sarif_stdin_uses_fallback_uri(capsys, monkeypatch):
    import io
    cap = '{"smp": {}}'
    monkeypatch.setattr("sys.stdin", io.StringIO(cap))
    main(["scan", "-", "--format", "sarif"])
    sarif = json.loads(capsys.readouterr().out)
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.endswith("-capture.json")  # synthesized, not "-"


# --------------------------------------------------------------------------- #
# Demo corpus — each demo must fire its intended outcome.
# --------------------------------------------------------------------------- #
# (relative path, expected profile, expected exit code, required finding ids)
DEMO_CASES = [
    ("01-basic/frontdoor_lock.json", "smart_lock", 1,
     {"SMP-JUSTWORKS", "SMP-LEGACY", "SMP-WEAKKEY", "ATT-PLAINTEXT-CTRL"}),
    ("02-clean/secure_hrm.json", "fitness_tracker", 0, set()),
    ("03-mixed/smart_plug.json", "smart_lock", 1,
     {"ATT-PLAINTEXT-CTRL", "GATT-UNAUTH-WRITE"}),
    ("04-debug-keys/smartbulb_debugkey.json", "smart_lock", 1,
     {"SMP-DEBUGKEY", "GATT-UNAUTH-WRITE"}),
    ("05-fitness-legacy/fitband_legacy.json", "fitness_tracker", 1,
     {"SMP-LEGACY"}),
    ("06-hid-keyboard/ble_keyboard.json", "hid_peripheral", 1,
     {"SMP-JUSTWORKS", "SMP-IOCAP"}),
    ("07-no-smp-sensor/warehouse_sensor.json", "environmental_sensor", 1,
     {"SMP-NONE"}),
    ("08-beacon-open/eddystone_beacon.json", "beacon", 1,
     {"SMP-NONE"}),
    ("09-secure-lock/secure_deadbolt.json", "smart_lock", 0, set()),
    ("10-text-relay/garage_relay.capture.txt", "smart_lock", 1,
     {"SMP-JUSTWORKS", "ATT-PLAINTEXT-CTRL", "SMP-WEAKKEY", "GATT-UNAUTH-WRITE"}),
]


@pytest.mark.parametrize("rel,profile,exit_code,required_ids", DEMO_CASES)
def test_demo_fires(rel, profile, exit_code, required_ids, capsys):
    path = os.path.join(DEMOS, *rel.split("/"))
    assert os.path.exists(path), f"missing demo capture: {rel}"
    rc, payload = _scan_json(path, capsys)
    assert rc == exit_code, f"{rel}: exit {rc} != {exit_code}"
    assert payload["profile"] == profile, f"{rel}: profile {payload['profile']}"
    got = {f["id"] for f in payload["findings"]}
    assert required_ids <= got, f"{rel}: missing {required_ids - got}"
    if exit_code == 0:
        assert payload["insecure"] is False
        assert payload["findings"] == []


def test_every_demo_dir_has_scenario_and_capture():
    for name in sorted(os.listdir(DEMOS)):
        d = os.path.join(DEMOS, name)
        if not os.path.isdir(d):
            continue
        files = os.listdir(d)
        assert "SCENARIO.md" in files, f"{name}: no SCENARIO.md"
        captures = [f for f in files if f.endswith((".json", ".txt"))]
        assert captures, f"{name}: no capture file"
