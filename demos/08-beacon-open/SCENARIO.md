# Demo 08 — Retail beacon that also accepts open connections

## Where this came from

`Aisle-7 Beacon` is an Eddystone (`0xfeaa`) proximity beacon used for indoor
positioning in a store. Broadcasting is expected and harmless — but during
the assessment the beacon was found to be **connectable with no security
manager exchange**, so anyone can connect and there is no pairing protecting
the link. A beacon that should be broadcast-only is exposing an open GATT
surface.

`eddystone_beacon.json` shows the Eddystone service in the advertisement
along with Eddystone-URL service data, and an empty GATT/SMP — exactly the
shape a passive capture of an over-permissive beacon produces.

## How to run

```sh
python -m blescope scan demos/08-beacon-open/eddystone_beacon.json
python -m blescope scan demos/08-beacon-open/eddystone_beacon.json --format json | jq '.profile'
```

## Expected result

Fingerprint **`beacon`** (confidence 1.0) with:

- `SMP-NONE` (**medium**) — no pairing exchange observed; the connectable
  link is unencrypted.

Verdict **INSECURE**, exit code **1**.

## How to act

A proximity beacon should be non-connectable (advertise-only). If the device
must accept connections (for config), gate them behind bonded, encrypted
pairing. This demo is a good contrast to the *broadcast-only* expectation —
the finding is about the surface the beacon left open, not the broadcast.
