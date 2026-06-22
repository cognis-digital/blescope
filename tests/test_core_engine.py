"""Deep, offline coverage of the core analysis engine: UUID handling, text
capture parsing, profile fingerprinting, every finding rule, severity escalation
for locks, ordering, and SARIF mapping edge cases.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from blescope.core import (
    SEVERITY_ORDER,
    AnalysisResult,
    Finding,
    analyze_capture,
    audit_pairing,
    decode_uuid,
    fingerprint_profile,
    load_capture,
    _coerce,
    _is_random_private,
    _normalize_uuid,
)


# --------------------------------------------------------------------------- #
# _normalize_uuid / decode_uuid
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,norm", [
    ("1815", "1815"),
    ("0x1815", "1815"),
    ("0X1815", "1815"),
    ("  1815 ", "1815"),
    ("0000180a-0000-1000-8000-00805f9b34fb", "180a"),
    ("0000180A-0000-1000-8000-00805F9B34FB", "180a"),
    ("00001815", "1815"),
])
def test_normalize_uuid(raw, norm):
    assert _normalize_uuid(raw) == norm


@pytest.mark.parametrize("uuid,kind,name", [
    ("1800", "service", "Generic Access"),
    ("180a", "service", "Device Information"),
    ("1815", "service", "Automation IO"),
    ("1812", "service", "Human Interface Device"),
    ("feaa", "service", "Eddystone (Google)"),
    ("2a00", "characteristic", "Device Name"),
    ("2a19", "characteristic", "Battery Level"),
    ("2a56", "characteristic", "Digital"),
    ("2a37", "characteristic", "Heart Rate Measurement"),
])
def test_decode_uuid_known(uuid, kind, name):
    assert decode_uuid(uuid, kind) == name


def test_decode_uuid_unknown():
    assert decode_uuid("abcd", "service") == "Unknown service (0xabcd)"
    assert decode_uuid("abcd", "characteristic") == "Unknown characteristic (0xabcd)"


def test_decode_uuid_default_kind_is_service():
    assert decode_uuid("1815") == "Automation IO"


# --------------------------------------------------------------------------- #
# _coerce
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,val", [
    ("true", True), ("yes", True), ("on", True), ("TRUE", True),
    ("false", False), ("no", False), ("off", False), ("False", False),
    ("7", 7), ("-3", -3), ("0", 0),
    ("just_works", "just_works"), ("0x06", "0x06"),
])
def test_coerce(raw, val):
    assert _coerce(raw) == val


# --------------------------------------------------------------------------- #
# _is_random_private (privacy address classification)
# --------------------------------------------------------------------------- #
def test_is_random_private_resolvable():
    # 0x80 -> top two bits 0b10 = resolvable private
    assert _is_random_private("80:11:22:33:44:55")


def test_is_random_private_nonresolvable():
    # 0x40 -> 0b01 = non-resolvable private
    assert _is_random_private("40:11:22:33:44:55")


def test_is_random_private_public_false():
    # 0xAA -> 0b10... actually 0xAA top bits = 0b10, resolvable. Use a public one.
    assert not _is_random_private("00:11:22:33:44:55")  # 0b00 = public
    assert not _is_random_private("C0:11:22:33:44:55")  # 0b11 = static random


def test_is_random_private_bad_input():
    assert not _is_random_private("")
    assert not _is_random_private("zz:11")


# --------------------------------------------------------------------------- #
# load_capture
# --------------------------------------------------------------------------- #
def test_load_capture_json_object():
    cap = load_capture('{"device": {"name": "X"}}')
    assert cap["device"]["name"] == "X"


def test_load_capture_empty_is_empty_dict():
    assert load_capture("") == {}
    assert load_capture("   ") == {}


def test_load_capture_json_array_raises():
    with pytest.raises(ValueError):
        load_capture("[1, 2, 3]")


def test_load_capture_text_fallback_full():
    text = (
        "# comment line\n"
        "device.name: TextLock\n"
        "device.address: AA:BB:CC:DD:EE:FF\n"
        "service: 1815\n"
        "char: 1815 2a56 read,write\n"
        "smp.method: just_works\n"
        "smp.mitm: false\n"
        "write: 2a56 01\n"
    )
    cap = load_capture(text)
    assert cap["device"]["name"] == "TextLock"
    assert any(g.get("characteristic") == "2a56" for g in cap["gatt"])
    assert cap["smp"]["method"] == "just_works"
    assert cap["smp"]["mitm"] is False
    assert cap["att_ops"][0]["characteristic"] == "2a56"


def test_load_capture_text_skips_blank_and_colonless():
    cap = load_capture("\n\nnocolon line\ndevice.name: Y\n")
    assert cap["device"]["name"] == "Y"


# --------------------------------------------------------------------------- #
# fingerprint_profile
# --------------------------------------------------------------------------- #
def test_fingerprint_unknown_empty():
    profile, conf = fingerprint_profile({})
    assert profile == "unknown"
    assert conf == 0.0


def test_fingerprint_by_service_uuid():
    cap = {"gatt": [{"service": "1812"}]}
    profile, conf = fingerprint_profile(cap)
    assert profile == "hid_peripheral"
    assert conf >= 0.6


def test_fingerprint_by_advertisement():
    cap = {"advertisements": [{"type": "service_uuids", "value": ["feaa"]}]}
    profile, _ = fingerprint_profile(cap)
    assert profile == "beacon"


def test_fingerprint_name_keyword_boost():
    cap = {"device": {"name": "Garage Door Lock"}, "gatt": [{"service": "1815"}]}
    profile, conf = fingerprint_profile(cap)
    assert profile == "smart_lock"
    assert conf == 1.0  # service + keyword


def test_fingerprint_name_only_weak():
    cap = {"device": {"name": "my front door"}}
    profile, conf = fingerprint_profile(cap)
    assert profile == "smart_lock"
    assert conf == pytest.approx(0.4)


# --------------------------------------------------------------------------- #
# audit_pairing — each rule in isolation
# --------------------------------------------------------------------------- #
def _ids(findings):
    return {f.id for f in findings}


def test_rule_justworks_lock_critical():
    fs = audit_pairing({"smp": {"method": "just_works", "secure_connections": True,
                                "max_enc_key_size": 16}}, "smart_lock")
    jw = next(f for f in fs if f.id == "SMP-JUSTWORKS")
    assert jw.severity == "critical"


def test_rule_justworks_nonlock_high():
    fs = audit_pairing({"smp": {"method": "just_works", "secure_connections": True,
                                "max_enc_key_size": 16}}, "fitness_tracker")
    jw = next(f for f in fs if f.id == "SMP-JUSTWORKS")
    assert jw.severity == "high"


def test_rule_legacy():
    fs = audit_pairing({"smp": {"method": "passkey", "mitm": True,
                                "secure_connections": False, "max_enc_key_size": 16}},
                       "fitness_tracker")
    assert "SMP-LEGACY" in _ids(fs)


def test_rule_weakkey_high_when_le7():
    fs = audit_pairing({"smp": {"method": "passkey", "mitm": True,
                                "secure_connections": True, "max_enc_key_size": 7}},
                       "fitness_tracker")
    wk = next(f for f in fs if f.id == "SMP-WEAKKEY")
    assert wk.severity == "high"


def test_rule_weakkey_medium_when_8to15():
    fs = audit_pairing({"smp": {"method": "passkey", "mitm": True,
                                "secure_connections": True, "max_enc_key_size": 12}},
                       "fitness_tracker")
    wk = next(f for f in fs if f.id == "SMP-WEAKKEY")
    assert wk.severity == "medium"


def test_rule_weakkey_absent_when_16():
    fs = audit_pairing({"smp": {"method": "passkey", "mitm": True,
                                "secure_connections": True, "max_enc_key_size": 16}},
                       "fitness_tracker")
    assert "SMP-WEAKKEY" not in _ids(fs)


def test_rule_iocap():
    fs = audit_pairing({"smp": {"method": "passkey", "mitm": True,
                                "secure_connections": True, "max_enc_key_size": 16,
                                "io_capability": "NoInputNoOutput"}}, "fitness_tracker")
    assert "SMP-IOCAP" in _ids(fs)


def test_rule_debugkey():
    fs = audit_pairing({"smp": {"method": "passkey", "mitm": True,
                                "secure_connections": True, "max_enc_key_size": 16,
                                "debug_keys": True}}, "fitness_tracker")
    dk = next(f for f in fs if f.id == "SMP-DEBUGKEY")
    assert dk.severity == "critical"


def test_rule_debugkey_via_public_key_field():
    fs = audit_pairing({"smp": {"method": "passkey", "mitm": True,
                                "secure_connections": True, "max_enc_key_size": 16,
                                "public_key": "debug"}}, "fitness_tracker")
    assert "SMP-DEBUGKEY" in _ids(fs)


def test_rule_smp_none():
    fs = audit_pairing({}, "environmental_sensor")
    assert "SMP-NONE" in _ids(fs)


def test_rule_weakbond():
    fs = audit_pairing({"smp": {"method": "just_works", "secure_connections": True,
                                "max_enc_key_size": 16, "bonding": True,
                                "mitm": False}}, "fitness_tracker")
    assert "SMP-WEAKBOND" in _ids(fs)


def test_rule_priv_static_addr():
    cap = {"device": {"name": "Tracker", "address": "00:11:22:33:44:55",
                      "address_type": "public"},
           "smp": {"method": "passkey", "mitm": True, "secure_connections": True,
                   "max_enc_key_size": 16}}
    fs = audit_pairing(cap, "fitness_tracker")
    assert "PRIV-STATIC-ADDR" in _ids(fs)


def test_rule_priv_absent_for_random_private():
    cap = {"device": {"name": "Tracker", "address": "80:11:22:33:44:55",
                      "address_type": "random"},
           "smp": {"method": "passkey", "mitm": True, "secure_connections": True,
                   "max_enc_key_size": 16}}
    fs = audit_pairing(cap, "fitness_tracker")
    assert "PRIV-STATIC-ADDR" not in _ids(fs)


def test_rule_att_plaintext_ctrl_lock_critical():
    cap = {"smp": {"method": "passkey", "mitm": True, "secure_connections": True,
                   "max_enc_key_size": 16},
           "att_ops": [{"op": "write", "characteristic": "2a56", "encrypted": False}]}
    fs = audit_pairing(cap, "smart_lock")
    att = next(f for f in fs if f.id == "ATT-PLAINTEXT-CTRL")
    assert att.severity == "critical"


def test_rule_att_plaintext_skipped_when_encrypted():
    cap = {"smp": {"method": "passkey", "mitm": True, "secure_connections": True,
                   "max_enc_key_size": 16},
           "att_ops": [{"op": "write", "characteristic": "2a56", "encrypted": True}]}
    fs = audit_pairing(cap, "smart_lock")
    assert "ATT-PLAINTEXT-CTRL" not in _ids(fs)


def test_rule_att_plaintext_skipped_for_nonsensitive_char():
    cap = {"smp": {"method": "passkey", "mitm": True, "secure_connections": True,
                   "max_enc_key_size": 16},
           "att_ops": [{"op": "write", "characteristic": "2a19", "encrypted": False}]}
    fs = audit_pairing(cap, "smart_lock")
    assert "ATT-PLAINTEXT-CTRL" not in _ids(fs)


def test_rule_gatt_unauth_write():
    cap = {"smp": {"method": "passkey", "mitm": True, "secure_connections": True,
                   "max_enc_key_size": 16},
           "gatt": [{"service": "1815", "characteristic": "2a56",
                     "properties": ["read", "write"]}]}
    fs = audit_pairing(cap, "smart_lock")
    assert "GATT-UNAUTH-WRITE" in _ids(fs)


def test_rule_gatt_unauth_write_skipped_when_signed():
    cap = {"smp": {"method": "passkey", "mitm": True, "secure_connections": True,
                   "max_enc_key_size": 16},
           "gatt": [{"service": "1815", "characteristic": "2a56",
                     "properties": ["write", "signed_write"]}]}
    fs = audit_pairing(cap, "smart_lock")
    assert "GATT-UNAUTH-WRITE" not in _ids(fs)


def test_findings_sorted_worst_first():
    cap = {"smp": {"method": "just_works", "secure_connections": False,
                   "max_enc_key_size": 7, "io_capability": "NoInputNoOutput"},
           "gatt": [{"service": "1815", "characteristic": "2a56",
                     "properties": ["write"]}],
           "att_ops": [{"op": "write", "characteristic": "2a56", "encrypted": False}]}
    fs = audit_pairing(cap, "smart_lock")
    idx = [SEVERITY_ORDER.index(f.severity) for f in fs]
    assert idx == sorted(idx)


# --------------------------------------------------------------------------- #
# AnalysisResult helpers
# --------------------------------------------------------------------------- #
def test_worst_severity_and_insecure():
    r = analyze_capture({"smp": {"method": "just_works", "secure_connections": False,
                                 "max_enc_key_size": 7}})
    assert r.worst_severity in SEVERITY_ORDER
    assert r.insecure() is True


def test_insecure_false_for_info_only():
    r = AnalysisResult(device={}, profile="x", profile_confidence=0.0,
                       services=[], characteristics=[],
                       findings=[Finding("I", "info", "t", "d")])
    assert r.insecure() is False
    assert r.worst_severity == "info"


def test_no_findings_worst_none():
    r = AnalysisResult(device={}, profile="x", profile_confidence=0.0,
                       services=[], characteristics=[], findings=[])
    assert r.worst_severity is None
    assert r.insecure() is False


def test_analyze_dedupes_services_and_chars():
    cap = {"gatt": [
        {"service": "1815", "characteristic": "2a56", "properties": ["write"]},
        {"service": "1815", "characteristic": "2a56", "properties": ["read"]},
    ]}
    r = analyze_capture(cap)
    assert len(r.services) == 1
    assert len(r.characteristics) == 1


def test_to_dict_round_shape():
    r = analyze_capture({"smp": {}})
    d = r.to_dict()
    for key in ("device", "profile", "profile_confidence", "services",
                "characteristics", "findings", "worst_severity", "insecure"):
        assert key in d


# --------------------------------------------------------------------------- #
# SARIF mapping edge cases
# --------------------------------------------------------------------------- #
def test_sarif_dedupes_rules_for_repeated_ids():
    cap = {"att_ops": [
        {"op": "write", "characteristic": "2a56", "encrypted": False},
        {"op": "write", "characteristic": "2a57", "encrypted": False},
    ], "smp": {"method": "passkey", "mitm": True, "secure_connections": True,
               "max_enc_key_size": 16}}
    r = analyze_capture(cap)
    sarif = r.to_sarif("blescope", "9.9.9")
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    results = sarif["runs"][0]["results"]
    # two ATT-PLAINTEXT-CTRL results, one rule
    assert len([x for x in results if x["ruleId"] == "ATT-PLAINTEXT-CTRL"]) == 2
    assert len([x for x in rules if x["id"] == "ATT-PLAINTEXT-CTRL"]) == 1


def test_sarif_custom_source_path():
    r = analyze_capture({"smp": {}})
    sarif = r.to_sarif("blescope", "1.0.0", source_path="my/cap.json")
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "my/cap.json"
