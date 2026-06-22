"""Core BLE GATT capture analysis engine (standard library only).

Capture format
--------------
A capture is a JSON object (or a simple ``key: value`` / line text form) describing
one BLE connection session::

    {
      "device": {"name": "FrontDoorLock", "address": "AA:BB:CC:DD:EE:FF",
                  "appearance": 0, "tx_power": -4},
      "advertisements": [
        {"type": "flags", "value": "0x06"},
        {"type": "complete_local_name", "value": "FrontDoorLock"},
        {"type": "service_uuids", "value": ["1815", "180a"]}
      ],
      "gatt": [
        {"service": "1815", "characteristic": "2a56",
         "properties": ["read", "write", "notify"], "handle": "0x0010"}
      ],
      "smp": {
        "method": "just_works",
        "io_capability": "NoInputNoOutput",
        "mitm": false,
        "secure_connections": false,
        "bonding": true,
        "max_enc_key_size": 7,
        "oob": false
      },
      "att_ops": [
        {"op": "write", "characteristic": "2a56", "value": "01", "encrypted": false}
      ]
    }

Every field is optional; the engine degrades gracefully on partial captures.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

TOOL_NAME = "blescope"


def _read_version() -> str:
    """Tool version from the repo-root VERSION file, with a safe fallback."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(os.path.dirname(here), "VERSION")
    try:
        with open(candidate, "r", encoding="utf-8") as fh:
            v = fh.read().strip()
            if v:
                return v
    except OSError:
        pass
    return "0.6.0"


TOOL_VERSION = _read_version()

# Severity ordering, worst first. Used to rank findings and pick exit codes.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# BLE severity -> SARIF level (error/warning/note) for code-scanning dashboards.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# BLE severity -> GitHub code-scanning numeric security-severity (CVSS-like).
_SARIF_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}

# ---------------------------------------------------------------------------
# Well-known GATT UUID tables (16-bit assigned numbers, Bluetooth SIG).
# Stored lowercased without the Bluetooth base UUID suffix.
# ---------------------------------------------------------------------------
_SERVICE_NAMES = {
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    "1802": "Immediate Alert",
    "1803": "Link Loss",
    "1804": "Tx Power",
    "1805": "Current Time",
    "180a": "Device Information",
    "180d": "Heart Rate",
    "180f": "Battery Service",
    "1810": "Blood Pressure",
    "1812": "Human Interface Device",
    "1815": "Automation IO",
    "1816": "Cycling Speed and Cadence",
    "181a": "Environmental Sensing",
    "181c": "User Data",
    "feaa": "Eddystone (Google)",
    "fd5a": "Smart Lock (vendor)",
}

_CHARACTERISTIC_NAMES = {
    "2a00": "Device Name",
    "2a01": "Appearance",
    "2a19": "Battery Level",
    "2a24": "Model Number String",
    "2a25": "Serial Number String",
    "2a26": "Firmware Revision String",
    "2a27": "Hardware Revision String",
    "2a29": "Manufacturer Name String",
    "2a37": "Heart Rate Measurement",
    "2a56": "Digital",  # Automation IO digital I/O — used by many DIY locks/relays
    "2a57": "Analog",
    "2a58": "Aggregate",
}

# Characteristics that, when written without encryption, are security-sensitive
# (actuation / control surfaces commonly used to drive smart locks & relays).
_SENSITIVE_CHARACTERISTICS = {"2a56", "2a57", "2a58", "fd5b"}

# Profile fingerprints: a profile matches if ANY of its service UUIDs appear.
_PROFILE_RULES = [
    ("smart_lock", {"1815", "fd5a", "fd5b"}, {"lock", "door", "bolt", "latch"}),
    ("fitness_tracker", {"180d", "1816"}, {"band", "fit", "watch", "hr"}),
    ("beacon", {"feaa"}, {"beacon", "eddystone", "ibeacon"}),
    ("hid_peripheral", {"1812"}, {"keyboard", "mouse", "remote"}),
    ("environmental_sensor", {"181a"}, {"sensor", "temp", "humidity"}),
]


def decode_uuid(uuid: str, kind: str = "service") -> str:
    """Return a human-readable name for a GATT UUID, or 'Unknown ...'.

    Accepts 16-bit short UUIDs (``"1815"``, ``"0x1815"``) and full 128-bit
    UUIDs that use the Bluetooth base; the latter are reduced to their 16-bit
    short form when possible.
    """
    norm = _normalize_uuid(uuid)
    table = _SERVICE_NAMES if kind == "service" else _CHARACTERISTIC_NAMES
    if norm in table:
        return table[norm]
    return f"Unknown {kind} (0x{norm})"


def _normalize_uuid(uuid: str) -> str:
    """Lowercase, strip 0x, and reduce a Bluetooth-base 128-bit UUID to 16 bits."""
    s = str(uuid).strip().lower().replace("0x", "")
    s = s.replace("-", "")
    # Bluetooth base UUID: 0000XXXX-0000-1000-8000-00805f9b34fb
    if len(s) == 32 and s.endswith("00001000800000805f9b34fb"):
        s = s[4:8]
    # Drop leading zeros down to the canonical 4-hex short form when applicable.
    if len(s) > 4 and s.startswith("0000"):
        s = s[4:8]
    return s


@dataclass
class Finding:
    """A single security/correctness observation about the capture."""

    id: str
    severity: str
    title: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    """Complete result of analyzing one capture."""

    device: dict[str, Any]
    profile: str
    profile_confidence: float
    services: list[dict[str, Any]]
    characteristics: list[dict[str, Any]]
    findings: list[Finding]

    @property
    def worst_severity(self) -> Optional[str]:
        for sev in SEVERITY_ORDER:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None

    def insecure(self) -> bool:
        """True when any actionable (non-info) finding exists — drives CI exit."""
        return any(f.severity != "info" for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device": self.device,
            "profile": self.profile,
            "profile_confidence": round(self.profile_confidence, 3),
            "services": self.services,
            "characteristics": self.characteristics,
            "findings": [f.to_dict() for f in self.findings],
            "worst_severity": self.worst_severity,
            "insecure": self.insecure(),
        }

    def to_sarif(self, tool_name: str, tool_version: str,
                 source_path: Optional[str] = None) -> dict[str, Any]:
        """Render the result as a SARIF 2.1.0 log (one run, one result per finding).

        SARIF (Static Analysis Results Interchange Format) is the OASIS standard
        consumed by GitHub code-scanning, Azure DevOps, and most SAST dashboards.
        BLE severities map onto SARIF ``level`` as: critical/high -> ``error``,
        medium -> ``warning``, low/info -> ``note``.
        """
        artifact_uri = source_path or f"{self.profile or 'unknown'}-capture.json"

        # Stable rule catalogue derived from the findings actually present.
        rules: list[dict[str, Any]] = []
        seen_rules: set[str] = set()
        results: list[dict[str, Any]] = []
        for f in self.findings:
            if f.id not in seen_rules:
                seen_rules.add(f.id)
                rules.append({
                    "id": f.id,
                    "name": f.id.replace("-", ""),
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.detail},
                    "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "note")},
                    "properties": {"security-severity": _SARIF_SECURITY_SEVERITY.get(f.severity, "0.0"),
                                   "ble-severity": f.severity},
                })
            results.append({
                "ruleId": f.id,
                "level": _SARIF_LEVEL.get(f.severity, "note"),
                "message": {"text": f"{f.title} — {f.detail}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_uri},
                    },
                    "logicalLocations": [{
                        "name": self.profile or "unknown",
                        "kind": "namespace",
                    }],
                }],
                "properties": {"evidence": f.evidence, "ble-severity": f.severity},
            })

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/cognis-digital/blescope",
                    "rules": rules,
                }},
                "results": results,
            }],
        }


def load_capture(text: str) -> dict[str, Any]:
    """Parse a capture from JSON, falling back to a tolerant line/KV text form.

    The text fallback supports lines like::

        device.name: FrontDoorLock
        service: 1815
        char: 1815 2a56 read,write,notify
        smp.method: just_works
        smp.mitm: false
    """
    text = text.strip()
    if not text:
        return {}
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
        raise ValueError("capture JSON must be an object")
    except json.JSONDecodeError:
        return _parse_text_capture(text)


def _parse_text_capture(text: str) -> dict[str, Any]:
    cap: dict[str, Any] = {"device": {}, "gatt": [], "smp": {}, "att_ops": []}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key.startswith("device."):
            cap["device"][key.split(".", 1)[1]] = _coerce(val)
        elif key == "service":
            cap["gatt"].append({"service": val, "characteristic": None, "properties": []})
        elif key in ("char", "characteristic"):
            parts = val.split()
            entry = {"service": None, "characteristic": None, "properties": []}
            if len(parts) >= 1:
                entry["service"] = parts[0]
            if len(parts) >= 2:
                entry["characteristic"] = parts[1]
            if len(parts) >= 3:
                entry["properties"] = [p.strip() for p in parts[2].split(",") if p.strip()]
            cap["gatt"].append(entry)
        elif key.startswith("smp."):
            cap["smp"][key.split(".", 1)[1]] = _coerce(val)
        elif key in ("write", "att.write"):
            parts = val.split()
            cap["att_ops"].append({
                "op": "write",
                "characteristic": parts[0] if parts else None,
                "value": parts[1] if len(parts) > 1 else "",
                "encrypted": False,
            })
    return cap


def _is_random_private(addr: str) -> bool:
    """True if a BLE address looks like a resolvable/non-resolvable private addr.

    Private random addresses have the two most-significant bits of the most
    significant byte set to 0b01 (non-resolvable) or 0b10 (resolvable). Public
    and static-random addresses do not vary, so they are trackable.
    """
    try:
        msb = int(addr.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    top = msb >> 6
    return top in (0b01, 0b10)


def _coerce(val: str) -> Any:
    low = val.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if re.fullmatch(r"-?\d+", val):
        return int(val)
    return val


def fingerprint_profile(capture: dict[str, Any]) -> tuple[str, float]:
    """Guess the device profile and a confidence in [0, 1].

    Combines advertised + discovered service UUIDs with name keyword hints.
    """
    uuids = _collect_service_uuids(capture)
    name = str(capture.get("device", {}).get("name", "")).lower()

    best_profile, best_score = "unknown", 0.0
    for profile, svc_set, keywords in _PROFILE_RULES:
        score = 0.0
        matched_svcs = uuids & svc_set
        if matched_svcs:
            score += 0.6 + 0.1 * (len(matched_svcs) - 1)
        if any(kw in name for kw in keywords):
            score += 0.4
        if score > best_score:
            best_profile, best_score = profile, score
    return best_profile, min(best_score, 1.0)


def _collect_service_uuids(capture: dict[str, Any]) -> set[str]:
    uuids: set[str] = set()
    for entry in capture.get("gatt", []) or []:
        svc = entry.get("service")
        if svc:
            uuids.add(_normalize_uuid(svc))
    for adv in capture.get("advertisements", []) or []:
        if adv.get("type") in ("service_uuids", "incomplete_service_uuids"):
            vals = adv.get("value")
            if isinstance(vals, list):
                uuids.update(_normalize_uuid(v) for v in vals)
            elif vals:
                uuids.add(_normalize_uuid(vals))
    return uuids


def audit_pairing(capture: dict[str, Any], profile: str) -> list[Finding]:
    """Inspect SMP config and ATT operations for insecure pairing/access."""
    findings: list[Finding] = []
    smp = capture.get("smp") or {}
    is_lock = profile == "smart_lock"

    if smp:
        method = str(smp.get("method", "")).lower()
        mitm = bool(smp.get("mitm", False))
        sc = bool(smp.get("secure_connections", False))
        oob = bool(smp.get("oob", False))
        io_cap = str(smp.get("io_capability", ""))
        key_size = smp.get("max_enc_key_size")

        if method in ("just_works", "justworks") or (not mitm and not oob):
            findings.append(Finding(
                id="SMP-JUSTWORKS",
                severity="critical" if is_lock else "high",
                title="Just Works pairing (no MITM protection)",
                detail=("Pairing offers no man-in-the-middle protection; an active "
                        "attacker in range can complete pairing and impersonate "
                        "either peer."),
                evidence={"method": method or "unspecified", "mitm": mitm, "oob": oob,
                          "io_capability": io_cap},
            ))
        if not sc:
            findings.append(Finding(
                id="SMP-LEGACY",
                severity="high" if is_lock else "medium",
                title="LE Legacy Pairing (no Secure Connections)",
                detail=("Secure Connections (LESC / P-256 ECDH) is not used. Legacy "
                        "pairing keys can be recovered by a passive sniffer that "
                        "captures the pairing exchange."),
                evidence={"secure_connections": sc},
            ))
        if isinstance(key_size, int) and key_size < 16:
            findings.append(Finding(
                id="SMP-WEAKKEY",
                severity="high" if key_size <= 7 else "medium",
                title=f"Short encryption key ({key_size} bytes)",
                detail=("Maximum encryption key size is below 128 bits, reducing "
                        "brute-force cost against the link encryption."),
                evidence={"max_enc_key_size": key_size},
            ))
        if io_cap == "NoInputNoOutput":
            findings.append(Finding(
                id="SMP-IOCAP",
                severity="medium",
                title="NoInputNoOutput I/O capability forces Just Works",
                detail=("With no input/output capability the only available "
                        "association model is Just Works, precluding authenticated "
                        "pairing regardless of peer support."),
                evidence={"io_capability": io_cap},
            ))
        if smp.get("debug_keys") or str(smp.get("public_key", "")).lower() == "debug":
            findings.append(Finding(
                id="SMP-DEBUGKEY",
                severity="critical",
                title="Bluetooth debug keys in use",
                detail=("The well-known SMP debug public/private key pair is used, so "
                        "link encryption is trivially decryptable by any observer."),
                evidence={"debug_keys": True},
            ))
        # Bonding without authenticated pairing leaves a reusable, weak LTK.
        if smp.get("bonding") and not mitm and method in (
                "just_works", "justworks", ""):
            findings.append(Finding(
                id="SMP-WEAKBOND",
                severity="medium",
                title="Bonding stores an unauthenticated long-term key",
                detail=("The peers bond (persist an LTK) after Just Works "
                        "pairing, so a key with no MITM protection is reused "
                        "across reconnections."),
                evidence={"bonding": True, "mitm": mitm, "method": method or "unspecified"},
            ))
    else:
        findings.append(Finding(
            id="SMP-NONE",
            severity="medium",
            title="No pairing/security manager exchange observed",
            detail=("The capture contains no SMP exchange; the link may operate "
                    "entirely unencrypted (Security Mode 1 Level 1)."),
            evidence={},
        ))

    # Static (non-resolvable) device address harms privacy and aids tracking.
    addr = str(capture.get("device", {}).get("address", "")).upper().replace("-", ":")
    addr_type = str(capture.get("device", {}).get("address_type", "")).lower()
    if addr and addr_type in ("public", "static", "static_random") and not _is_random_private(addr):
        findings.append(Finding(
            id="PRIV-STATIC-ADDR",
            severity="low",
            title="Static/public device address enables tracking",
            detail=("The device advertises with a fixed (public or static) "
                    "address rather than a resolvable private address, so it "
                    "can be tracked across time and place."),
            evidence={"address": addr, "address_type": addr_type or "public"},
        ))

    # Plaintext writes to sensitive (actuation) characteristics.
    for op in capture.get("att_ops", []) or []:
        if str(op.get("op", "")).lower() not in ("write", "write_command", "write_request"):
            continue
        char = _normalize_uuid(op.get("characteristic", "")) if op.get("characteristic") else ""
        encrypted = bool(op.get("encrypted", False))
        if char in _SENSITIVE_CHARACTERISTICS and not encrypted:
            findings.append(Finding(
                id="ATT-PLAINTEXT-CTRL",
                severity="critical" if is_lock else "high",
                title=f"Plaintext write to control characteristic {char}",
                detail=("A write to a security-sensitive (actuation) characteristic "
                        "is sent without link-layer encryption and can be replayed "
                        "or forged by a sniffer."),
                evidence={"characteristic": char,
                          "name": decode_uuid(char, "characteristic"),
                          "value": op.get("value")},
            ))

    # Writable, unauthenticated sensitive characteristics discovered in GATT.
    for entry in capture.get("gatt", []) or []:
        char = entry.get("characteristic")
        if not char:
            continue
        cn = _normalize_uuid(char)
        props = {str(p).lower() for p in (entry.get("properties") or [])}
        if cn in _SENSITIVE_CHARACTERISTICS and "write" in props and not (
            "authenticated_write" in props or "signed_write" in props
        ):
            findings.append(Finding(
                id="GATT-UNAUTH-WRITE",
                severity="high" if is_lock else "medium",
                title=f"Unauthenticated writable control characteristic {cn}",
                detail=("A control characteristic exposes a plain Write property with "
                        "no authenticated/signed-write requirement."),
                evidence={"characteristic": cn,
                          "name": decode_uuid(cn, "characteristic"),
                          "properties": sorted(props)},
            ))

    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    return findings


def analyze_capture(capture: dict[str, Any]) -> AnalysisResult:
    """Run the full pipeline: decode, fingerprint, audit."""
    profile, confidence = fingerprint_profile(capture)

    services: list[dict[str, Any]] = []
    characteristics: list[dict[str, Any]] = []
    seen_svc: set[str] = set()
    seen_char: set[str] = set()
    for entry in capture.get("gatt", []) or []:
        svc = entry.get("service")
        if svc:
            n = _normalize_uuid(svc)
            if n not in seen_svc:
                seen_svc.add(n)
                services.append({"uuid": n, "name": decode_uuid(n, "service")})
        char = entry.get("characteristic")
        if char:
            n = _normalize_uuid(char)
            if n not in seen_char:
                seen_char.add(n)
                characteristics.append({
                    "uuid": n,
                    "name": decode_uuid(n, "characteristic"),
                    "properties": sorted({str(p).lower() for p in (entry.get("properties") or [])}),
                })

    findings = audit_pairing(capture, profile)
    return AnalysisResult(
        device=capture.get("device", {}) or {},
        profile=profile,
        profile_confidence=confidence,
        services=services,
        characteristics=characteristics,
        findings=findings,
    )
