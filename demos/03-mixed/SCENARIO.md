# Demo 03 — Smart plug on Automation IO (well-paired, leaky control)

## Where this came from

`WattWise Plug Mini` pairs *well* — Passkey Entry with MITM protection, LE
Secure Connections, a full 16-byte key — yet still fails the assessment on
the control surface. It exposes the Automation IO `Digital` characteristic
(`0x2a56`) as plain `read,write,notify`, and the app drives it with an
**unencrypted ATT write**. Good pairing does not help if individual writes
go out in the clear and the characteristic carries no authenticated-write
requirement.

A second, deliberate lesson: BLESCOPE fingerprints any device on the
Automation IO service (`0x1815`) as **`smart_lock`**, because that is the
actuation profile to worry about — so these control-surface findings inherit
**lock-grade severity** even though the marketing name says "plug".

`smart_plug.json` is the authorized capture.

## How to run

```sh
python -m blescope scan demos/03-mixed/smart_plug.json
python -m blescope scan demos/03-mixed/smart_plug.json --format sarif
```

## Expected result

Fingerprint **`smart_lock`** (Automation IO) with:

- `ATT-PLAINTEXT-CTRL` (**critical**) — unencrypted write to the control
  characteristic.
- `GATT-UNAUTH-WRITE` (**high**) — `Digital` (`0x2a56`) is writable with no
  authenticated/signed-write requirement.

Verdict **INSECURE**, exit code **1**.

## How to act

Strong pairing is necessary but not sufficient. Require an authenticated
write on the actuation characteristic and ensure the app sends control
writes over the encrypted link. Contrast with demo 09, which gets all of
this right.
