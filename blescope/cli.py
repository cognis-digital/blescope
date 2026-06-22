"""BLESCOPE command-line interface.

Examples
--------
  # Analyze a capture and print a human-readable report
  blescope scan demos/01-basic/frontdoor_lock.json

  # Machine-readable output for CI / piping
  blescope scan capture.json --format json | jq '.findings'

  # Read a capture from stdin
  cat capture.json | blescope scan -

Exit codes
----------
  0  analysis completed, no actionable (non-info) findings
  1  insecure: at least one actionable finding was reported (CI gate)
  2  usage / input error
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import analyze_capture, load_capture, AnalysisResult, SEVERITY_ORDER
from .active import (
    ActiveConfig,
    ActiveResult,
    MockScanner,
    NullScanner,
    ScopeError,
    load_allowlist,
    run_active,
)

_SEV_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def _read_source(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _render_table(result: AnalysisResult) -> str:
    dev = result.device
    lines = []
    lines.append("=" * 60)
    lines.append(f"BLESCOPE report  ({TOOL_NAME} {TOOL_VERSION})")
    lines.append("=" * 60)
    name = dev.get("name", "<unknown>")
    addr = dev.get("address", "<unknown>")
    lines.append(f"Device       : {name}  [{addr}]")
    lines.append(f"Profile      : {result.profile}  (confidence {result.profile_confidence:.0%})")
    lines.append("")

    lines.append(f"Services ({len(result.services)}):")
    if result.services:
        for s in result.services:
            lines.append(f"  0x{s['uuid']:<6} {s['name']}")
    else:
        lines.append("  (none discovered)")
    lines.append("")

    lines.append(f"Characteristics ({len(result.characteristics)}):")
    if result.characteristics:
        for c in result.characteristics:
            props = ",".join(c["properties"]) if c["properties"] else "-"
            lines.append(f"  0x{c['uuid']:<6} {c['name']:<28} [{props}]")
    else:
        lines.append("  (none discovered)")
    lines.append("")

    lines.append(f"Findings ({len(result.findings)}):")
    if result.findings:
        for f in result.findings:
            lines.append(f"  [{_SEV_LABEL.get(f.severity, f.severity.upper())}] {f.id}: {f.title}")
            lines.append(f"          {f.detail}")
    else:
        lines.append("  none — no insecure pairing or access patterns detected")
    lines.append("")

    verdict = "INSECURE" if result.insecure() else "OK"
    worst = result.worst_severity or "none"
    lines.append("-" * 60)
    lines.append(f"VERDICT: {verdict}   (worst severity: {worst})")
    lines.append("-" * 60)
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=("Decode a BLE GATT capture, fingerprint the device profile, "
                     "and assert on insecure pairing."),
        epilog=("examples:\n"
                "  blescope scan capture.json\n"
                "  blescope scan capture.json --format json | jq .findings\n"
                "  cat capture.json | blescope scan -\n"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="analyze a BLE GATT capture file (use '-' for stdin)",
        description="Analyze a BLE GATT capture and report device profile + security findings.",
    )
    scan.add_argument("capture", help="path to capture (JSON or text); '-' reads stdin")
    scan.add_argument(
        "--format", choices=["table", "json", "sarif"], default="table",
        help=("output format (default: table). 'sarif' emits a SARIF 2.1.0 log "
              "for GitHub code-scanning and SAST dashboards."),
    )
    scan.add_argument(
        "--min-severity", choices=SEVERITY_ORDER, default="low",
        help=("minimum severity that counts as a failure for the exit code "
              "(default: low). 'info' never fails."),
    )

    live = sub.add_parser(
        "scan-live",
        help="ACTIVE: pull live GATT from authorized in-scope BLE devices",
        description=(
            "AUTHORIZED USE ONLY. Active scanning is OFF by default and only "
            "probes devices you own or are explicitly permitted to test. "
            "Requires --authorized AND a non-empty --target-allowlist; every "
            "probe is rate-limited and out-of-scope devices are skipped."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    live.add_argument(
        "--authorized", action="store_true",
        help="confirm you own / are permitted to test the target devices (REQUIRED)",
    )
    live.add_argument(
        "--target-allowlist", default=None,
        help=("comma-separated BLE addresses OR a path to a file of addresses "
              "(one per line) that are in scope (REQUIRED, non-empty)"),
    )
    live.add_argument(
        "--rate", type=float, default=1.0,
        help="maximum active probes per second (default: 1.0)",
    )
    live.add_argument(
        "--demo", action="store_true",
        help=("use the bundled MockScanner fixtures instead of a real radio "
              "(safe offline demonstration of the active pipeline)"),
    )
    live.add_argument(
        "--format", choices=["table", "json"], default="table",
        help="output format (default: table)",
    )
    return parser


_DEMO_DEVICES = [
    {"address": "AA:BB:CC:DD:EE:01", "name": "DemoLock"},
    {"address": "AA:BB:CC:DD:EE:02", "name": "RoguePhone"},
]
_DEMO_CAPTURES = {
    "AA:BB:CC:DD:EE:01": {
        "device": {"name": "DemoLock", "address": "AA:BB:CC:DD:EE:01"},
        "gatt": [{"service": "1815", "characteristic": "2a56",
                  "properties": ["read", "write", "notify"]}],
        "smp": {"method": "just_works", "io_capability": "NoInputNoOutput",
                "mitm": False, "secure_connections": False, "max_enc_key_size": 7},
        "att_ops": [{"op": "write", "characteristic": "2a56",
                     "value": "01", "encrypted": False}],
    },
}


def _render_active_table(result: ActiveResult) -> str:
    lines = ["=" * 60,
             f"BLESCOPE active report  ({TOOL_NAME} {TOOL_VERSION})",
             "=" * 60,
             f"Scanned (in scope) : {len(result.scanned)}",
             f"Skipped (out of scope): {len(result.skipped_out_of_scope)}"]
    for addr in result.skipped_out_of_scope:
        lines.append(f"  - skipped {addr} (not in allowlist)")
    lines.append("")
    for addr, r in result.results.items():
        lines.append(f"[{addr}] profile={r.profile} verdict="
                     f"{'INSECURE' if r.insecure() else 'OK'} "
                     f"worst={r.worst_severity or 'none'}")
        for f in r.findings:
            lines.append(f"    [{_SEV_LABEL.get(f.severity, f.severity.upper())}] "
                         f"{f.id}: {f.title}")
    lines.append("-" * 60)
    verdict = "INSECURE" if result.to_dict()["insecure"] else "OK"
    lines.append(f"VERDICT: {verdict}")
    lines.append("-" * 60)
    return "\n".join(lines)


def _run_scan_live(args) -> int:
    try:
        allowlist = load_allowlist(args.target_allowlist)
        config = ActiveConfig(
            authorized=args.authorized,
            allowlist=allowlist,
            rate=args.rate,
        )
        config.ensure_gated()
    except ScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.demo:
        scanner = MockScanner(_DEMO_DEVICES, _DEMO_CAPTURES)
    else:
        scanner = NullScanner()

    try:
        result = run_active(config, scanner)
    except ScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(_render_active_table(result))

    return 1 if result.to_dict()["insecure"] else 0


def _exit_code(result: AnalysisResult, min_severity: str) -> int:
    threshold = SEVERITY_ORDER.index(min_severity)
    for f in result.findings:
        if f.severity == "info":
            continue
        if SEVERITY_ORDER.index(f.severity) <= threshold:
            return 1
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 2

    if args.command == "scan-live":
        return _run_scan_live(args)

    if args.command == "scan":
        try:
            text = _read_source(args.capture)
        except OSError as exc:
            print(f"error: cannot read capture: {exc}", file=sys.stderr)
            return 2
        try:
            capture = load_capture(text)
        except ValueError as exc:
            print(f"error: invalid capture: {exc}", file=sys.stderr)
            return 2

        result = analyze_capture(capture)

        if args.format == "json":
            print(json.dumps(result.to_dict(), indent=2))
        elif args.format == "sarif":
            source = None if args.capture == "-" else args.capture
            print(json.dumps(
                result.to_sarif(TOOL_NAME, TOOL_VERSION, source), indent=2))
        else:
            print(_render_table(result))

        return _exit_code(result, args.min_severity)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
