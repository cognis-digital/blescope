# Demo 07 — Cold-chain sensor with no pairing at all

## Where this came from

`ColdChain TH-Sensor` is a warehouse temperature/humidity logger on the
Environmental Sensing service (`0x181a`). During the authorized assessment
the device connected and streamed readings **without any SMP exchange** —
the link operates in Security Mode 1 Level 1 (no encryption, no
authentication). Any sniffer in range reads the telemetry, and nothing stops
a rogue client from connecting and reading the same characteristics.

`warehouse_sensor.json` captures the Temperature (`0x2a6e`) and Humidity
(`0x2a6f`) characteristics plus two unencrypted `read` ATT operations.

## How to run

```sh
python -m blescope scan demos/07-no-smp-sensor/warehouse_sensor.json
```

## Expected result

Fingerprint **`environmental_sensor`** (confidence 1.0) with:

- `SMP-NONE` (**medium**) — no pairing/security manager exchange was
  observed; the link may operate entirely unencrypted.

Verdict **INSECURE**, exit code **1**.

## How to act

For sensors carrying only environmental telemetry the confidentiality risk
is modest, but the *integrity* risk is not: spoofed readings can mask a
cold-chain excursion. Require at least an encrypted bonded link before the
sensor is trusted in compliance records.
