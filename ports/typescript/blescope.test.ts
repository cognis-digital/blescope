import { test } from "node:test";
import assert from "node:assert/strict";
import { audit, insecure, normUuid, type Capture } from "./blescope.ts";

const lockCapture: Capture = {
  device: { name: "FrontDoorLock", address: "AA:BB:CC:DD:EE:FF" },
  gatt: [{ service: "1815", characteristic: "2a56", properties: ["read", "write", "notify"] }],
  smp: { method: "just_works", io_capability: "NoInputNoOutput", mitm: false, secure_connections: false, max_enc_key_size: 7 },
  att_ops: [{ op: "write", characteristic: "2a56", encrypted: false }],
};

const secureCapture: Capture = {
  device: { name: "SecureBand" },
  gatt: [{ service: "180d", characteristic: "2a37", properties: ["notify"] }],
  smp: { method: "numeric_comparison", io_capability: "DisplayYesNo", mitm: true, secure_connections: true, max_enc_key_size: 16 },
  att_ops: [],
};

test("normUuid normalizes short and 128-bit forms", () => {
  assert.equal(normUuid("0x1815"), "1815");
  assert.equal(normUuid("0000180a-0000-1000-8000-00805f9b34fb"), "180a");
});

test("insecure lock yields the headline findings, worst-first", () => {
  const fs = audit(lockCapture);
  assert.ok(insecure(fs));
  const ids = new Set(fs.map((f) => f.id));
  for (const want of ["SMP-JUSTWORKS", "SMP-LEGACY", "SMP-WEAKKEY", "ATT-PLAINTEXT-CTRL"]) {
    assert.ok(ids.has(want), `missing ${want}`);
  }
  assert.equal(fs[0].severity, "critical");
});

test("secure capture is clean", () => {
  const fs = audit(secureCapture);
  assert.equal(fs.length, 0);
  assert.ok(!insecure(fs));
});

test("missing smp block reports SMP-NONE", () => {
  const fs = audit({ device: { name: "x" }, gatt: [] });
  assert.ok(fs.some((f) => f.id === "SMP-NONE"));
});

test("non-lock just-works is high not critical", () => {
  const fs = audit({
    device: { name: "Thermostat" },
    gatt: [{ service: "181a", characteristic: "2a6e", properties: ["read"] }],
    smp: { method: "just_works", secure_connections: true, max_enc_key_size: 16 },
  });
  const jw = fs.find((f) => f.id === "SMP-JUSTWORKS");
  assert.equal(jw?.severity, "high");
});
