# Demo 04 — Factory debug keys shipped in a smart bulb

## Where this came from

A connected-lighting vendor shipped `GlowBulb-A19` with their development
firmware by mistake. On paper the pairing looks strong — LE Secure
Connections, MITM-protected Passkey Entry, a full 16-byte key — but the SMP
exchange uses the **well-known Bluetooth debug key pair** that engineers
enable during bring-up. Anyone who captures the pairing can derive the link
key and decrypt everything, defeating all the other protections.

`smartbulb_debugkey.json` is the authorized teardown capture: it advertises
the vendor Smart Lock service (`0xfd5a`), Device Information (`0x180a`), and
Battery (`0x180f`), and exposes the Automation IO `Analog` characteristic
(`0x2a57`) as `read,write`.

## How to run

```sh
python -m blescope scan demos/04-debug-keys/smartbulb_debugkey.json
python -m blescope scan demos/04-debug-keys/smartbulb_debugkey.json --format json
```

## Expected result

BLESCOPE fingerprints the device as **`smart_lock`** and reports:

- `SMP-DEBUGKEY` (**critical**) — the SMP debug public/private key pair is in
  use, so link encryption is trivially decryptable by any observer.
- `GATT-UNAUTH-WRITE` (**high**) — the `Analog` control characteristic
  (`0x2a57`) is writable with no authenticated/signed-write requirement.

Verdict **INSECURE**, exit code **1**.

## How to act

Pull the build from distribution and reflash with production keys
(`debug_keys` disabled). Debug keys are a one-line firmware regression that
strong pairing parameters completely mask — make a SARIF gate
(`--format sarif`) part of the release pipeline so it can never ship again.
