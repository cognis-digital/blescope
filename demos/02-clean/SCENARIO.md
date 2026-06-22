# Demo 02 — Clean baseline (secure heart-rate strap)

## Where this came from

`CardioStrap H7` is a chest-strap heart-rate monitor that pairs the way a
modern BLE device should: Numeric Comparison with MITM protection, LE Secure
Connections, and a full 16-byte key. It exposes only `read`/`notify`
characteristics — there is no writable actuation surface to abuse.

`secure_hrm.json` is the authorized capture used as a **zero-findings
baseline** for regression testing.

## How to run

```sh
python -m blescope scan demos/02-clean/secure_hrm.json
echo "exit code: $?"
```

## Expected result

Fingerprint **`fitness_tracker`**, **zero findings**, verdict **OK**, exit
code **0**.

## How to act

Use this as the "passes CI" fixture. If a future firmware capture of the same
device starts producing findings, the pairing parameters regressed.
