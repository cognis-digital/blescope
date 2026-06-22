# Demo 06 — BLE keyboard that forces Just Works

## Where this came from

`SlimType BT Keyboard` is a Human Interface Device (HID) peripheral. It
advertises the HID service (`0x1812`) and negotiates LE Secure Connections
with a 16-byte key — good — but it presents a `NoInputNoOutput` I/O
capability, which forces the **Just Works** association model. With no MITM
protection, an attacker in range can complete pairing and impersonate the
keyboard, enabling keystroke injection into the host.

`ble_keyboard.json` shows the HID Report characteristic (`0x2a4d`) under the
HID service alongside the usual Device Information and Battery services.

## How to run

```sh
python -m blescope scan demos/06-hid-keyboard/ble_keyboard.json
python -m blescope scan demos/06-hid-keyboard/ble_keyboard.json --format sarif
```

## Expected result

Fingerprint **`hid_peripheral`** (confidence 1.0) with:

- `SMP-JUSTWORKS` (**high**) — Just Works pairing, no MITM protection.
- `SMP-IOCAP` (**medium**) — `NoInputNoOutput` forces Just Works regardless
  of peer support.

Verdict **INSECURE**, exit code **1**.

## How to act

For an input device, MITM protection is not optional — a Just Works keyboard
is the textbook keystroke-injection target. The fix is hardware/firmware:
expose a passkey display or confirm button so an authenticated association
model becomes available.
