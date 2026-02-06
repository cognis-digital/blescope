# Demo 01 — Smart-lock teardown (insecure pairing)

## What this shows

This demo runs BLESCOPE against `frontdoor_lock.json`, a captured BLE GATT
session from a (fictional) cheap Wi-Fi/BLE smart lock, `FrontDoorLock`.

The capture contains:

- **Advertisements** announcing the `Automation IO` (`0x1815`) and
  `Device Information` (`0x180a`) services.
- A **GATT table** exposing the Automation IO `Digital` characteristic
  (`0x2a56`) with `read,write,notify` — the actuation surface used to throw
  the deadbolt.
- An **SMP pairing exchange** configured for `Just Works`,
  `NoInputNoOutput`, **no** Secure Connections, and a **7-byte** max
  encryption key.
- A **plaintext ATT write** (`01`) to the `Digital` characteristic that
  unlocks the door.

## How to run

```sh
python -m blescope scan demos/01-basic/frontdoor_lock.json
# or machine-readable:
python -m blescope scan demos/01-basic/frontdoor_lock.json --format json
```

## Expected result

BLESCOPE fingerprints the device as **`smart_lock`** and reports several
findings, including:

- `SMP-JUSTWORKS` (**critical**) — Just Works pairing, no MITM protection.
- `SMP-LEGACY` (**high**) — LE Legacy Pairing, no Secure Connections.
- `SMP-WEAKKEY` (**high**) — 7-byte encryption key.
- `SMP-IOCAP` (**medium**) — NoInputNoOutput forces Just Works.
- `ATT-PLAINTEXT-CTRL` (**critical**) — plaintext write to the control
  characteristic that opens the lock.
- `GATT-UNAUTH-WRITE` (**high**) — the control characteristic is writable
  with no authenticated/signed-write requirement.

The verdict is **INSECURE** and the process exits with code **1**, so a CI
gate (`blescope scan ... ; echo $?`) fails the build.
