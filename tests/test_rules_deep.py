"""Deep, exhaustive, offline coverage of the blescope audit rules and engine.

This suite complements ``test_core_engine.py`` with a much larger matrix of
real assertions: every finding rule under both lock and non-lock profiles,
severity escalation boundaries, evidence payloads, UUID normalization corner
cases, fingerprint scoring, the SARIF rendering contract, and invariants that
must hold across the entire bundled demo corpus.

Everything runs offline with the standard library only — no radio, no network.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from blescope import TOOL_NAME, TOOL_VERSION
from blescope.core import (
    SEVERITY_ORDER,
    AnalysisResult,
    Finding,
    analyze_capture,
    audit_pairing,
    decode_uuid,
    fingerprint_profile,
    load_capture,
    _is_random_private,
    _normalize_uuid,
)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEMOS_DIR = os.path.join(REPO_ROOT, "demos")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def ids(findings):
    return {f.id for f in findings}


def by_id(findings, fid):
    for f in findings:
        if f.id == fid:
            return f
    return None


def base_lock_smp(**over):
    smp = {
        "method": "numeric_comparison",
        "io_capability": "DisplayYesNo",
        "mitm": True,
        "secure_connections": True,
        "max_enc_key_size": 16,
        "oob": False,
    }
    smp.update(over)
    return smp


def cap(profile_svc=None, smp=None, gatt=None, att=None, device=None):
    c = {"device": device or {"name": "TestDev"}}
    g = list(gatt or [])
    if profile_svc:
        g.append({"service": profile_svc, "characteristic": None, "properties": []})
    if g:
        c["gatt"] = g
    if smp is not None:
        c["smp"] = smp
    if att is not None:
        c["att_ops"] = att
    return c


# --------------------------------------------------------------------------- #
# SMP-JUSTWORKS — escalates to critical on locks, high otherwise
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("method", ["just_works", "justworks", "JUST_WORKS", "JustWorks"])
def test_justworks_detected_for_each_spelling(method):
    fs = audit_pairing(cap(smp={"method": method}), "fitness_tracker")
    assert "SMP-JUSTWORKS" in ids(fs)


def test_justworks_high_for_non_lock():
    fs = audit_pairing(cap(smp={"method": "just_works"}), "fitness_tracker")
    assert by_id(fs, "SMP-JUSTWORKS").severity == "high"


def test_justworks_critical_for_lock():
    fs = audit_pairing(cap(smp={"method": "just_works"}), "smart_lock")
    assert by_id(fs, "SMP-JUSTWORKS").severity == "critical"


def test_justworks_inferred_when_no_mitm_no_oob():
    # No explicit method, but mitm=False and oob=False implies Just Works.
    fs = audit_pairing(cap(smp={"secure_connections": True, "mitm": False, "oob": False,
                                "max_enc_key_size": 16}), "fitness_tracker")
    assert "SMP-JUSTWORKS" in ids(fs)


def test_justworks_not_flagged_when_mitm_true():
    fs = audit_pairing(cap(smp=base_lock_smp()), "fitness_tracker")
    assert "SMP-JUSTWORKS" not in ids(fs)


def test_justworks_evidence_carries_method_and_iocap():
    fs = audit_pairing(cap(smp={"method": "just_works", "io_capability": "KeyboardOnly"}),
                       "fitness_tracker")
    ev = by_id(fs, "SMP-JUSTWORKS").evidence
    assert ev["method"] == "just_works"
    assert ev["io_capability"] == "KeyboardOnly"
    assert ev["mitm"] is False


# --------------------------------------------------------------------------- #
# SMP-LEGACY — no secure connections
# --------------------------------------------------------------------------- #
def test_legacy_flagged_when_sc_false():
    fs = audit_pairing(cap(smp=base_lock_smp(secure_connections=False)), "fitness_tracker")
    assert "SMP-LEGACY" in ids(fs)


def test_legacy_not_flagged_when_sc_true():
    fs = audit_pairing(cap(smp=base_lock_smp(secure_connections=True)), "fitness_tracker")
    assert "SMP-LEGACY" not in ids(fs)


def test_legacy_high_on_lock_medium_otherwise():
    lock = audit_pairing(cap(smp=base_lock_smp(secure_connections=False)), "smart_lock")
    other = audit_pairing(cap(smp=base_lock_smp(secure_connections=False)), "beacon")
    assert by_id(lock, "SMP-LEGACY").severity == "high"
    assert by_id(other, "SMP-LEGACY").severity == "medium"


# --------------------------------------------------------------------------- #
# SMP-WEAKKEY — key size boundary behavior
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("ks,expected_present,expected_sev", [
    (16, False, None),
    (15, True, "medium"),
    (8, True, "medium"),
    (7, True, "high"),
    (5, True, "high"),
    (1, True, "high"),
])
def test_weakkey_boundaries(ks, expected_present, expected_sev):
    fs = audit_pairing(cap(smp=base_lock_smp(max_enc_key_size=ks)), "fitness_tracker")
    if not expected_present:
        assert "SMP-WEAKKEY" not in ids(fs)
    else:
        f = by_id(fs, "SMP-WEAKKEY")
        assert f is not None
        assert f.severity == expected_sev
        assert f.evidence["max_enc_key_size"] == ks


def test_weakkey_ignores_non_int_key_size():
    fs = audit_pairing(cap(smp=base_lock_smp(max_enc_key_size="sixteen")), "fitness_tracker")
    assert "SMP-WEAKKEY" not in ids(fs)


def test_weakkey_title_includes_byte_count():
    fs = audit_pairing(cap(smp=base_lock_smp(max_enc_key_size=7)), "fitness_tracker")
    assert "7 bytes" in by_id(fs, "SMP-WEAKKEY").title


# --------------------------------------------------------------------------- #
# SMP-IOCAP — NoInputNoOutput
# --------------------------------------------------------------------------- #
def test_iocap_flagged_for_noinputnooutput():
    fs = audit_pairing(cap(smp=base_lock_smp(io_capability="NoInputNoOutput")), "fitness_tracker")
    assert "SMP-IOCAP" in ids(fs)


@pytest.mark.parametrize("io", ["DisplayYesNo", "KeyboardDisplay", "KeyboardOnly", "DisplayOnly"])
def test_iocap_not_flagged_for_capable_io(io):
    fs = audit_pairing(cap(smp=base_lock_smp(io_capability=io)), "fitness_tracker")
    assert "SMP-IOCAP" not in ids(fs)


def test_iocap_severity_is_medium():
    fs = audit_pairing(cap(smp=base_lock_smp(io_capability="NoInputNoOutput")), "smart_lock")
    assert by_id(fs, "SMP-IOCAP").severity == "medium"


# --------------------------------------------------------------------------- #
# SMP-DEBUGKEY — well-known debug keys
# --------------------------------------------------------------------------- #
def test_debugkey_via_flag():
    fs = audit_pairing(cap(smp=base_lock_smp(debug_keys=True)), "fitness_tracker")
    assert "SMP-DEBUGKEY" in ids(fs)
    assert by_id(fs, "SMP-DEBUGKEY").severity == "critical"


def test_debugkey_via_public_key_marker():
    fs = audit_pairing(cap(smp=base_lock_smp(public_key="debug")), "fitness_tracker")
    assert "SMP-DEBUGKEY" in ids(fs)


def test_debugkey_via_public_key_marker_case_insensitive():
    fs = audit_pairing(cap(smp=base_lock_smp(public_key="DEBUG")), "fitness_tracker")
    assert "SMP-DEBUGKEY" in ids(fs)


def test_no_debugkey_with_real_public_key():
    fs = audit_pairing(cap(smp=base_lock_smp(public_key="20b003d2f297be2c5e2c83a7e9f9a5b9")),
                       "fitness_tracker")
    assert "SMP-DEBUGKEY" not in ids(fs)


# --------------------------------------------------------------------------- #
# SMP-WEAKBOND — bonded unauthenticated LTK
# --------------------------------------------------------------------------- #
def test_weakbond_flagged_for_bonded_justworks():
    fs = audit_pairing(cap(smp={"method": "just_works", "bonding": True, "mitm": False}),
                       "fitness_tracker")
    assert "SMP-WEAKBOND" in ids(fs)


def test_weakbond_not_flagged_when_authenticated():
    fs = audit_pairing(cap(smp=base_lock_smp(bonding=True)), "fitness_tracker")
    assert "SMP-WEAKBOND" not in ids(fs)


def test_weakbond_not_flagged_without_bonding():
    fs = audit_pairing(cap(smp={"method": "just_works", "bonding": False, "mitm": False}),
                       "fitness_tracker")
    assert "SMP-WEAKBOND" not in ids(fs)


# --------------------------------------------------------------------------- #
# SMP-NONE — no SMP exchange at all
# --------------------------------------------------------------------------- #
def test_smp_none_when_absent():
    fs = audit_pairing({"device": {"name": "x"}, "gatt": []}, "environmental_sensor")
    assert "SMP-NONE" in ids(fs)
    assert by_id(fs, "SMP-NONE").severity == "medium"


def test_smp_none_when_empty_dict():
    fs = audit_pairing({"device": {"name": "x"}, "smp": {}}, "environmental_sensor")
    assert "SMP-NONE" in ids(fs)


def test_smp_none_excludes_other_smp_findings():
    fs = audit_pairing({"device": {"name": "x"}}, "smart_lock")
    assert "SMP-JUSTWORKS" not in ids(fs)
    assert "SMP-LEGACY" not in ids(fs)


# --------------------------------------------------------------------------- #
# ATT-PLAINTEXT-CTRL — plaintext writes to control characteristics
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("op", ["write", "write_command", "write_request", "WRITE"])
def test_plaintext_ctrl_for_each_write_op(op):
    fs = audit_pairing(cap(smp=base_lock_smp(),
                           att=[{"op": op, "characteristic": "2a56", "encrypted": False}]),
                       "fitness_tracker")
    assert "ATT-PLAINTEXT-CTRL" in ids(fs)


def test_plaintext_ctrl_skipped_when_encrypted():
    fs = audit_pairing(cap(smp=base_lock_smp(),
                           att=[{"op": "write", "characteristic": "2a56", "encrypted": True}]),
                       "fitness_tracker")
    assert "ATT-PLAINTEXT-CTRL" not in ids(fs)


def test_plaintext_ctrl_skipped_for_read():
    fs = audit_pairing(cap(smp=base_lock_smp(),
                           att=[{"op": "read", "characteristic": "2a56", "encrypted": False}]),
                       "fitness_tracker")
    assert "ATT-PLAINTEXT-CTRL" not in ids(fs)


def test_plaintext_ctrl_skipped_for_non_sensitive_char():
    fs = audit_pairing(cap(smp=base_lock_smp(),
                           att=[{"op": "write", "characteristic": "2a19", "encrypted": False}]),
                       "fitness_tracker")
    assert "ATT-PLAINTEXT-CTRL" not in ids(fs)


def test_plaintext_ctrl_critical_on_lock():
    fs = audit_pairing(cap(smp=base_lock_smp(),
                           att=[{"op": "write", "characteristic": "2a56", "encrypted": False}]),
                       "smart_lock")
    assert by_id(fs, "ATT-PLAINTEXT-CTRL").severity == "critical"


def test_plaintext_ctrl_normalizes_128bit_char():
    fs = audit_pairing(cap(smp=base_lock_smp(),
                           att=[{"op": "write",
                                 "characteristic": "00002a56-0000-1000-8000-00805f9b34fb",
                                 "encrypted": False}]),
                       "fitness_tracker")
    f = by_id(fs, "ATT-PLAINTEXT-CTRL")
    assert f is not None
    assert f.evidence["characteristic"] == "2a56"


# --------------------------------------------------------------------------- #
# GATT-UNAUTH-WRITE — writable sensitive char without auth/signed requirement
# --------------------------------------------------------------------------- #
def test_gatt_unauth_write_flagged():
    fs = audit_pairing(cap(smp=base_lock_smp(),
                           gatt=[{"service": "1815", "characteristic": "2a56",
                                  "properties": ["read", "write", "notify"]}]),
                       "smart_lock")
    assert "GATT-UNAUTH-WRITE" in ids(fs)


def test_gatt_unauth_write_cleared_by_authenticated_write():
    fs = audit_pairing(cap(smp=base_lock_smp(),
                           gatt=[{"service": "1815", "characteristic": "2a56",
                                  "properties": ["read", "authenticated_write"]}]),
                       "smart_lock")
    assert "GATT-UNAUTH-WRITE" not in ids(fs)


def test_gatt_unauth_write_cleared_by_signed_write():
    fs = audit_pairing(cap(smp=base_lock_smp(),
                           gatt=[{"service": "1815", "characteristic": "2a56",
                                  "properties": ["read", "signed_write"]}]),
                       "smart_lock")
    assert "GATT-UNAUTH-WRITE" not in ids(fs)


def test_gatt_unauth_write_not_for_readonly():
    fs = audit_pairing(cap(smp=base_lock_smp(),
                           gatt=[{"service": "1815", "characteristic": "2a56",
                                  "properties": ["read", "notify"]}]),
                       "smart_lock")
    assert "GATT-UNAUTH-WRITE" not in ids(fs)


def test_gatt_unauth_write_high_on_lock_medium_otherwise():
    g = [{"service": "1815", "characteristic": "2a56", "properties": ["write"]}]
    lock = audit_pairing(cap(smp=base_lock_smp(), gatt=g), "smart_lock")
    other = audit_pairing(cap(smp=base_lock_smp(), gatt=g), "fitness_tracker")
    assert by_id(lock, "GATT-UNAUTH-WRITE").severity == "high"
    assert by_id(other, "GATT-UNAUTH-WRITE").severity == "medium"


# --------------------------------------------------------------------------- #
# PRIV-STATIC-ADDR — fixed address tracking
# --------------------------------------------------------------------------- #
def test_static_public_address_flagged():
    fs = audit_pairing({"device": {"name": "x", "address": "00:11:22:33:44:55",
                                   "address_type": "public"}, "smp": base_lock_smp()},
                       "fitness_tracker")
    assert "PRIV-STATIC-ADDR" in ids(fs)
    assert by_id(fs, "PRIV-STATIC-ADDR").severity == "low"


def test_resolvable_private_address_not_flagged():
    # 0xC0 -> top bits 0b11... actually resolvable private is 0b10 prefix.
    fs = audit_pairing({"device": {"name": "x", "address": "80:11:22:33:44:55",
                                   "address_type": "public"}, "smp": base_lock_smp()},
                       "fitness_tracker")
    # top two bits of 0x80 == 0b10 -> resolvable private -> not flagged
    assert "PRIV-STATIC-ADDR" not in ids(fs)


def test_no_address_no_privacy_finding():
    fs = audit_pairing({"device": {"name": "x"}, "smp": base_lock_smp()}, "fitness_tracker")
    assert "PRIV-STATIC-ADDR" not in ids(fs)


# --------------------------------------------------------------------------- #
# _is_random_private bit math
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("addr,expected", [
    ("40:00:00:00:00:00", True),   # 0b01 non-resolvable
    ("80:00:00:00:00:00", True),   # 0b10 resolvable
    ("C0:00:00:00:00:00", False),  # 0b11 static random (trackable)
    ("00:00:00:00:00:00", False),  # 0b00 public
    ("nonsense", False),
])
def test_is_random_private(addr, expected):
    assert _is_random_private(addr) is expected


# --------------------------------------------------------------------------- #
# fingerprint scoring
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("svc,name,profile", [
    ("1815", "FrontDoorLock", "smart_lock"),
    ("fd5a", "BoltGuard", "smart_lock"),
    ("180d", "FitBand", "fitness_tracker"),
    ("1816", "CycleCadence", "fitness_tracker"),
    ("feaa", "Eddystone Beacon", "beacon"),
    ("1812", "BT Keyboard", "hid_peripheral"),
    ("181a", "TempSensor", "environmental_sensor"),
])
def test_fingerprint_profiles(svc, name, profile):
    p, conf = fingerprint_profile({"device": {"name": name},
                                   "gatt": [{"service": svc}]})
    assert p == profile
    assert 0.0 < conf <= 1.0


def test_fingerprint_unknown_for_empty():
    p, conf = fingerprint_profile({})
    assert p == "unknown"
    assert conf == 0.0


def test_fingerprint_name_alone_scores_lower_than_with_service():
    name_only = fingerprint_profile({"device": {"name": "smart lock"}})
    with_svc = fingerprint_profile({"device": {"name": "smart lock"},
                                    "gatt": [{"service": "1815"}]})
    assert with_svc[1] > name_only[1]


def test_fingerprint_uses_advertised_service_uuids():
    p, conf = fingerprint_profile({"device": {"name": "?"},
                                   "advertisements": [
                                       {"type": "service_uuids", "value": ["feaa"]}]})
    assert p == "beacon"


def test_fingerprint_confidence_capped_at_one():
    p, conf = fingerprint_profile({"device": {"name": "door lock bolt"},
                                   "gatt": [{"service": "1815"}, {"service": "fd5a"}]})
    assert conf <= 1.0


# --------------------------------------------------------------------------- #
# decode_uuid
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("uuid,kind,expected_substr", [
    ("1815", "service", "Automation IO"),
    ("180d", "service", "Heart Rate"),
    ("180f", "service", "Battery"),
    ("1812", "service", "Human Interface"),
    ("2a56", "characteristic", "Digital"),
    ("2a19", "characteristic", "Battery Level"),
    ("2a37", "characteristic", "Heart Rate Measurement"),
])
def test_decode_known_uuids(uuid, kind, expected_substr):
    assert expected_substr in decode_uuid(uuid, kind)


def test_decode_unknown_uuid():
    out = decode_uuid("ffff", "service")
    assert "Unknown" in out and "ffff" in out


# --------------------------------------------------------------------------- #
# ordering invariant
# --------------------------------------------------------------------------- #
def test_findings_sorted_worst_first():
    c = {
        "device": {"name": "FrontDoorLock", "address": "AA:BB:CC:DD:EE:FF"},
        "gatt": [{"service": "1815", "characteristic": "2a56",
                  "properties": ["read", "write", "notify"]}],
        "smp": {"method": "just_works", "io_capability": "NoInputNoOutput",
                "mitm": False, "secure_connections": False, "max_enc_key_size": 7,
                "bonding": True},
        "att_ops": [{"op": "write", "characteristic": "2a56", "encrypted": False}],
    }
    res = analyze_capture(c)
    ranks = [SEVERITY_ORDER.index(f.severity) for f in res.findings]
    assert ranks == sorted(ranks)
    assert res.worst_severity == "critical"
    assert res.insecure() is True


# --------------------------------------------------------------------------- #
# SARIF contract
# --------------------------------------------------------------------------- #
def test_sarif_schema_shape():
    res = analyze_capture({"device": {"name": "x"}})
    sarif = res.to_sarif(TOOL_NAME, TOOL_VERSION)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == TOOL_NAME
    assert driver["version"] == TOOL_VERSION


def test_sarif_one_result_per_finding():
    res = analyze_capture({
        "device": {"name": "FrontDoorLock"},
        "gatt": [{"service": "1815", "characteristic": "2a56", "properties": ["write"]}],
        "smp": {"method": "just_works", "mitm": False, "secure_connections": False,
                "max_enc_key_size": 7},
    })
    sarif = res.to_sarif(TOOL_NAME, TOOL_VERSION)
    results = sarif["runs"][0]["results"]
    assert len(results) == len(res.findings)


def test_sarif_levels_mapped():
    res = analyze_capture({
        "device": {"name": "FrontDoorLock"},
        "smp": {"method": "just_works", "mitm": False, "secure_connections": False,
                "max_enc_key_size": 16},
    })
    sarif = res.to_sarif(TOOL_NAME, TOOL_VERSION)
    levels = {r["level"] for r in sarif["runs"][0]["results"]}
    assert levels <= {"error", "warning", "note"}


def test_sarif_security_severity_present():
    res = analyze_capture({
        "device": {"name": "FrontDoorLock"},
        "smp": {"method": "just_works", "mitm": False, "secure_connections": False},
    })
    sarif = res.to_sarif(TOOL_NAME, TOOL_VERSION)
    for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
        assert "security-severity" in rule["properties"]


def test_sarif_is_json_serializable():
    res = analyze_capture({"device": {"name": "x"},
                           "smp": {"method": "just_works"}})
    # must round-trip through json with no exceptions
    blob = json.dumps(res.to_sarif(TOOL_NAME, TOOL_VERSION))
    assert json.loads(blob)["version"] == "2.1.0"


def test_sarif_uses_source_path_when_given():
    res = analyze_capture({"device": {"name": "x"}})
    sarif = res.to_sarif(TOOL_NAME, TOOL_VERSION, "captures/foo.json")
    loc = sarif["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "captures/foo.json"


# --------------------------------------------------------------------------- #
# AnalysisResult.to_dict completeness
# --------------------------------------------------------------------------- #
def test_to_dict_keys():
    res = analyze_capture({"device": {"name": "x"}})
    d = res.to_dict()
    for key in ("device", "profile", "profile_confidence", "services",
                "characteristics", "findings", "worst_severity", "insecure"):
        assert key in d


def test_clean_capture_not_insecure():
    res = analyze_capture({
        "device": {"name": "SecureBand", "address": "AC:00:00:00:00:01",
                   "address_type": "static_random"},
        "gatt": [{"service": "180d", "characteristic": "2a37", "properties": ["notify"]}],
        "smp": base_lock_smp(),
    })
    # static_random with 0xAC top bits 0b10 -> resolvable -> no privacy finding
    assert res.insecure() is False
    assert res.findings == []


# --------------------------------------------------------------------------- #
# load_capture — text fallback
# --------------------------------------------------------------------------- #
def test_load_capture_json():
    c = load_capture('{"device": {"name": "x"}}')
    assert c["device"]["name"] == "x"


def test_load_capture_empty():
    assert load_capture("") == {}


def test_load_capture_rejects_json_array():
    with pytest.raises(ValueError):
        load_capture("[1, 2, 3]")


def test_load_capture_text_form_full():
    text = (
        "device.name: GarageRelay\n"
        "device.address: AA:BB:CC:DD:EE:10\n"
        "service: 1815\n"
        "char: 1815 2a56 read,write,notify\n"
        "smp.method: just_works\n"
        "smp.mitm: false\n"
        "smp.secure_connections: false\n"
        "write: 2a56 01\n"
    )
    c = load_capture(text)
    assert c["device"]["name"] == "GarageRelay"
    assert c["smp"]["method"] == "just_works"
    assert c["smp"]["mitm"] is False
    assert any(e.get("characteristic") == "2a56" for e in c["gatt"])
    assert c["att_ops"][0]["op"] == "write"


def test_text_capture_then_analyze_flags_insecure():
    text = (
        "device.name: GarageDoor\n"
        "char: 1815 2a56 read,write\n"
        "smp.method: just_works\n"
        "smp.mitm: false\n"
        "smp.secure_connections: false\n"
        "write: 2a56 01\n"
    )
    res = analyze_capture(load_capture(text))
    assert res.insecure() is True
    assert "SMP-JUSTWORKS" in {f.id for f in res.findings}


# --------------------------------------------------------------------------- #
# Demo-corpus invariants — every bundled capture stays parseable & stable
# --------------------------------------------------------------------------- #
def _demo_json_files():
    out = []
    for root, _dirs, files in os.walk(DEMOS_DIR):
        for fn in files:
            if fn.endswith(".json"):
                out.append(os.path.join(root, fn))
    return sorted(out)


@pytest.mark.parametrize("path", _demo_json_files())
def test_every_demo_parses_and_analyzes(path):
    with open(path, "r", encoding="utf-8") as fh:
        capture = load_capture(fh.read())
    res = analyze_capture(capture)
    # round-trips through dict + json cleanly
    blob = json.dumps(res.to_dict())
    assert json.loads(blob)["profile"] == res.profile
    # every finding has the mandatory shape
    for f in res.findings:
        assert f.id and f.severity in SEVERITY_ORDER and f.title


@pytest.mark.parametrize("path", _demo_json_files())
def test_every_demo_sarif_valid(path):
    with open(path, "r", encoding="utf-8") as fh:
        res = analyze_capture(load_capture(fh.read()))
    sarif = res.to_sarif(TOOL_NAME, TOOL_VERSION, path)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == len(res.findings)


def test_known_insecure_demos_are_insecure():
    expect_insecure = {
        "01-basic": True,
        "02-clean": False,
        "04-debug-keys": True,
        "09-secure-lock": False,
    }
    for name, insecure in expect_insecure.items():
        d = os.path.join(DEMOS_DIR, name)
        f = [os.path.join(d, x) for x in os.listdir(d) if x.endswith(".json")][0]
        with open(f, "r", encoding="utf-8") as fh:
            res = analyze_capture(load_capture(fh.read()))
        assert res.insecure() is insecure, f"{name} insecure={res.insecure()} expected {insecure}"
