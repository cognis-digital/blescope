# Demo 05 — Wearable stuck on LE Legacy Pairing

## Where this came from

`PulseFit Band 3` is a heart-rate wearable that pairs with MITM protection
(Passkey Entry, `DisplayOnly`) and a full 16-byte key — but it never
negotiated **LE Secure Connections (LESC)**. It falls back to LE Legacy
Pairing, whose key-exchange can be recovered by a passive sniffer that
captures the pairing moment, after which the attacker can decrypt the heart
-rate stream off-air.

`fitband_legacy.json` advertises Heart Rate (`0x180d`), Battery (`0x180f`),
and Device Information (`0x180a`), and discovers the standard Heart Rate
Measurement (`0x2a37`) notification.

## How to run

```sh
python -m blescope scan demos/05-fitness-legacy/fitband_legacy.json
```

## Expected result

Fingerprint **`fitness_tracker`** (confidence 1.0) with a single finding:

- `SMP-LEGACY` (**medium**) — Secure Connections is not used; legacy pairing
  keys are recoverable from a captured pairing exchange.

Verdict **INSECURE**, exit code **1**.

## How to act

This is the most common "looks fine, isn't" finding in the wild — strong
key, strong association model, but no LESC. File a firmware ask to require
`secure_connections` and re-bond. Use `--min-severity high` if you want CI
to *warn* on this class without failing the build.
