# Demo 10 — DIY garage relay (tolerant text-capture format)

## Where this came from

Not every capture starts as clean JSON. `GarageRelay-ESP32` is a homebrew
ESP32 board wired to a garage-door relay; the assessor sniffed it and
hand-transcribed the session into BLESCOPE's **tolerant `key: value` text
form** — the format you reach for when jotting observations during a live
session. `garage_relay.capture.txt` exercises that parser end to end:
`device.*` lines, `service:` / `char:` lines, `smp.*` lines, and a `write:`
ATT operation, with `#` comments ignored.

The device pairs Just Works with a 7-byte key over the Automation IO service
and the mobile app fires a plaintext write to `0x2a56` to toggle the door —
a near-worst-case stack.

## How to run

```sh
python -m blescope scan demos/10-text-relay/garage_relay.capture.txt
cat demos/10-text-relay/garage_relay.capture.txt | python -m blescope scan -
```

## Expected result

Fingerprint **`smart_lock`** with the full insecure-actuator stack:

- `SMP-JUSTWORKS` (**critical**) — Just Works, no MITM.
- `ATT-PLAINTEXT-CTRL` (**critical**) — plaintext write to the control
  characteristic that toggles the door.
- `SMP-LEGACY` (**high**) — no Secure Connections.
- `SMP-WEAKKEY` (**high**) — 7-byte key.
- `GATT-UNAUTH-WRITE` (**high**) — control characteristic writable with no
  authenticated/signed write.
- `SMP-IOCAP` (**medium**) — `NoInputNoOutput` forces Just Works.

Verdict **INSECURE**, exit code **1**.

## How to act

This demo proves the text format produces identical findings to JSON, so you
can pipe a quick hand-typed capture straight into the same CI gate. The fix
list is the same as any insecure actuator: LESC, a 16-byte key, an
authenticated write, and an encrypted control channel.
