import { test } from "node:test";
import assert from "node:assert/strict";
import { audit, insecure, normUuid } from "./index.js";

const lockCapture = {
  device: { name: "FrontDoorLock", address: "AA:BB:CC:DD:EE:FF" },
  gatt: [{ service: "1815", characteristic: "2a56", properties: ["read", "write", "notify"] }],
  smp: { method: "just_works", io_capability: "NoInputNoOutput", mitm: false, secure_connections: false, max_enc_key_size: 7 },
  att_ops: [{ op: "write", characteristic: "2a56", encrypted: false }],
};

test("normUuid", () => {
  assert.equal(normUuid("0x1815"), "1815");
  assert.equal(normUuid("0000180a-0000-1000-8000-00805f9b34fb"), "180a");
});

test("insecure lock findings worst-first", () => {
  const fs = audit(lockCapture);
  assert.ok(insecure(fs));
  const ids = new Set(fs.map((f) => f.id));
  for (const want of ["SMP-JUSTWORKS", "SMP-LEGACY", "SMP-WEAKKEY", "ATT-PLAINTEXT-CTRL"])
    assert.ok(ids.has(want), `missing ${want}`);
  assert.equal(fs[0].severity, "critical");
});

test("secure capture clean", () => {
  const fs = audit({
    device: { name: "SecureBand" },
    gatt: [{ service: "180d", characteristic: "2a37", properties: ["notify"] }],
    smp: { method: "numeric_comparison", io_capability: "DisplayYesNo", mitm: true, secure_connections: true, max_enc_key_size: 16 },
    att_ops: [],
  });
  assert.equal(fs.length, 0);
  assert.ok(!insecure(fs));
});

test("no smp -> SMP-NONE", () => {
  assert.ok(audit({ device: {}, gatt: [] }).some((f) => f.id === "SMP-NONE"));
});
