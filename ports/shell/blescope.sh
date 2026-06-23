#!/bin/sh
# POSIX shell + awk port of the blescope BLE pairing-audit core.
#
# PASSIVE only: reads a BLE GATT capture (JSON) from a file argument or stdin
# and reports insecure-pairing findings using the same rule IDs as the Python
# reference. It never touches a radio or a network. Depends only on a POSIX
# shell and awk (both ubiquitous); no jq, no Python, no network.
#
#   sh blescope.sh capture.json          # findings, exit 1 if insecure
#   cat capture.json | sh blescope.sh -  # stdin
#
# The awk program tokenizes the JSON into a flat dotted-path key/value stream
# and then applies the same audit rules as the reference engine. Findings are
# printed one per line as: SEVERITY<TAB>RULE-ID<TAB>title
set -eu

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
AWK_PROG="$SELF_DIR/blescope.awk"

src=${1:--}
if [ "$src" = "-" ]; then
    input=$(cat)
else
    if [ ! -r "$src" ]; then
        echo "error: cannot read capture: $src" >&2
        exit 2
    fi
    input=$(cat -- "$src")
fi

# awk emits findings on stdout and writes the insecure flag (0/1) to fd 3 via a
# trailing marker line "##INSECURE n". We capture it and translate to exit code.
out=$(printf '%s' "$input" | awk -f "$AWK_PROG" 2>/dev/null) || {
    echo "error: invalid capture" >&2
    exit 2
}

insecure=$(printf '%s\n' "$out" | sed -n 's/^##INSECURE //p')
findings=$(printf '%s\n' "$out" | grep -v '^##' || true)

if [ -z "$insecure" ]; then
    echo "error: invalid capture" >&2
    exit 2
fi

echo "tool: blescope"
if [ -n "$findings" ]; then
    printf '%s\n' "$findings" | while IFS='	' read -r sev id title; do
        printf '[%s] %s: %s\n' "$sev" "$id" "$title"
    done
else
    echo "findings: none"
fi

if [ "$insecure" = "1" ]; then
    exit 1
fi
exit 0
