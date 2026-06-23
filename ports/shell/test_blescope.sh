#!/bin/sh
# Smoke + behavior tests for the shell/awk port. Run: sh test_blescope.sh
# POSIX sh; no bashisms. Exits 0 on success, 1 on any failed assertion.
set -u
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEMOS="$DIR/../../demos"
FAIL=0
N=0

assert() { # assert <desc> <cond-result(0/1 string)>
    N=$((N + 1))
    if [ "$2" = "1" ]; then
        echo "ok $N - $1"
    else
        echo "not ok $N - $1"
        FAIL=1
    fi
}

run() { sh "$DIR/blescope.sh" "$@"; }

# 1. insecure lock exits 1
out=$(run "$DEMOS/01-basic/frontdoor_lock.json"); code=$?
assert "lock exits 1" "$( [ $code -eq 1 ] && echo 1 || echo 0 )"

# 2. lock reports SMP-JUSTWORKS
assert "lock has SMP-JUSTWORKS" "$( printf '%s' "$out" | grep -q 'SMP-JUSTWORKS' && echo 1 || echo 0 )"

# 3. lock reports ATT-PLAINTEXT-CTRL
assert "lock has ATT-PLAINTEXT-CTRL" "$( printf '%s' "$out" | grep -q 'ATT-PLAINTEXT-CTRL' && echo 1 || echo 0 )"

# 4. worst-first: first finding line is critical
first=$(printf '%s\n' "$out" | grep '^\[' | head -1)
assert "worst-first ordering (critical leads)" "$( printf '%s' "$first" | grep -q '^\[critical\]' && echo 1 || echo 0 )"

# 5. secure capture clean, exit 0
out2=$(run "$DEMOS/09-secure-lock/secure_deadbolt.json"); code2=$?
assert "secure exits 0" "$( [ $code2 -eq 0 ] && echo 1 || echo 0 )"
assert "secure has no findings" "$( printf '%s' "$out2" | grep -q 'findings: none' && echo 1 || echo 0 )"

# 6. no-smp sensor reports SMP-NONE
out3=$(run "$DEMOS/07-no-smp-sensor/warehouse_sensor.json")
assert "no-smp reports SMP-NONE" "$( printf '%s' "$out3" | grep -q 'SMP-NONE' && echo 1 || echo 0 )"

# 7. debug-keys demo reports SMP-DEBUGKEY
out4=$(run "$DEMOS/04-debug-keys/smartbulb_debugkey.json")
assert "debug-keys reports SMP-DEBUGKEY" "$( printf '%s' "$out4" | grep -q 'SMP-DEBUGKEY' && echo 1 || echo 0 )"

# 8. stdin works
out5=$(cat "$DEMOS/01-basic/frontdoor_lock.json" | run -)
assert "stdin pipe works" "$( printf '%s' "$out5" | grep -q 'SMP-JUSTWORKS' && echo 1 || echo 0 )"

# 9. bad json exits 2
printf 'not json' | run - >/dev/null 2>&1; code3=$?
assert "bad json exits 2" "$( [ $code3 -eq 2 ] && echo 1 || echo 0 )"

# 10. missing file exits 2
run "$DIR/does-not-exist.json" >/dev/null 2>&1; code4=$?
assert "missing file exits 2" "$( [ $code4 -eq 2 ] && echo 1 || echo 0 )"

echo "1..$N"
exit $FAIL
