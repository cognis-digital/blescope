# Demo 09 — A smart lock done right (clean baseline)

## Where this came from

`BoltGuard Pro` is the reference for how a connected deadbolt *should* look.
It is the direct counterpart to demo 01's insecure `FrontDoorLock`: same
profile, same actuation surface, but engineered correctly.

`secure_deadbolt.json` shows:

- **Numeric Comparison** association (`DisplayYesNo`) with **MITM**
  protection.
- **LE Secure Connections** with a full **16-byte** key.
- The Automation IO `Digital` characteristic (`0x2a56`) exposed as
  `read,notify,authenticated_write` — actuation requires an authenticated
  write, not a plain one.
- The unlock ATT write is sent **encrypted**.

## How to run

```sh
python -m blescope scan demos/09-secure-lock/secure_deadbolt.json
echo "exit code: $?"
```

## Expected result

Fingerprint **`smart_lock`** (confidence 1.0), **zero findings**.

Verdict **OK**, exit code **0** — a CI gate passes.

## How to act

Nothing to fix — keep this capture as a regression fixture. Diff a new
firmware's capture against it: if `secure_connections`, `mitm`,
`max_enc_key_size`, or the `authenticated_write` property regress, the next
scan turns red. This is the "green" half of a useful CI gate.
