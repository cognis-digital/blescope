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
    return parser


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
