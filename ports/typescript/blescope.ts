// TypeScript port of the blescope BLE pairing-audit core (PASSIVE only).
// Reads a BLE GATT capture (JSON) and reports insecure-pairing findings using
// the same rule IDs as the Python reference. Never touches a radio or network.

export interface Finding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
}

export interface Capture {
  device?: { name?: string; address?: string; [k: string]: unknown };
  gatt?: Array<{ service?: string; characteristic?: string; properties?: unknown[] }>;
  smp?: Record<string, unknown>;
  att_ops?: Array<{ op?: string; characteristic?: string; encrypted?: boolean }>;
}

const SEV_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SENSITIVE = new Set(["2a56", "2a57", "2a58", "fd5b"]);
const LOCK_SERVICES = new Set(["1815", "fd5a", "fd5b"]);

export function normUuid(uuid: string): string {
  let s = String(uuid).trim().toLowerCase().replace(/0x/g, "").replace(/-/g, "");
  if (s.length === 32 && s.endsWith("00001000800000805f9b34fb")) s = s.slice(4, 8);
  else if (s.length > 4 && s.startsWith("0000")) s = s.slice(4, 8);
  return s;
}

function isLock(cap: Capture): boolean {
  for (const g of cap.gatt ?? []) {
    if (g.service && LOCK_SERVICES.has(normUuid(g.service))) return true;
  }
  const name = String(cap.device?.name ?? "").toLowerCase();
  return ["lock", "door", "bolt", "latch"].some((k) => name.includes(k));
}

export function audit(cap: Capture): Finding[] {
  const fs: Finding[] = [];
  const lock = isLock(cap);
  const smp = cap.smp;
  const smpPresent = !!smp && Object.keys(smp).length > 0;

  if (smpPresent && smp) {
    const method = String(smp.method ?? "").toLowerCase();
    const mitm = smp.mitm === true;
    const sc = smp.secure_connections === true;
    const oob = smp.oob === true;
    const ioCap = String(smp.io_capability ?? "");

    if (method === "just_works" || method === "justworks" || (!mitm && !oob)) {
      fs.push({ id: "SMP-JUSTWORKS", severity: lock ? "critical" : "high", title: "Just Works pairing (no MITM protection)" });
    }
    if (!sc) {
      fs.push({ id: "SMP-LEGACY", severity: lock ? "high" : "medium", title: "LE Legacy Pairing (no Secure Connections)" });
    }
    const ks = smp.max_enc_key_size;
    if (typeof ks === "number" && ks < 16) {
      fs.push({ id: "SMP-WEAKKEY", severity: ks <= 7 ? "high" : "medium", title: `Short encryption key (${ks} bytes)` });
    }
    if (ioCap === "NoInputNoOutput") {
      fs.push({ id: "SMP-IOCAP", severity: "medium", title: "NoInputNoOutput I/O capability forces Just Works" });
    }
    if (smp.debug_keys === true || String(smp.public_key ?? "").toLowerCase() === "debug") {
      fs.push({ id: "SMP-DEBUGKEY", severity: "critical", title: "Bluetooth debug keys in use" });
    }
  } else {
    fs.push({ id: "SMP-NONE", severity: "medium", title: "No pairing/security manager exchange observed" });
  }

  for (const op of cap.att_ops ?? []) {
    const o = String(op.op ?? "").toLowerCase();
    if (!["write", "write_command", "write_request"].includes(o)) continue;
    const ch = op.characteristic ? normUuid(op.characteristic) : "";
    if (SENSITIVE.has(ch) && op.encrypted !== true) {
      fs.push({ id: "ATT-PLAINTEXT-CTRL", severity: lock ? "critical" : "high", title: `Plaintext write to control characteristic ${ch}` });
    }
  }

  for (const g of cap.gatt ?? []) {
    if (!g.characteristic) continue;
    const ch = normUuid(g.characteristic);
    const props = new Set((g.properties ?? []).map((p) => String(p).toLowerCase()));
    if (SENSITIVE.has(ch) && props.has("write") && !props.has("authenticated_write") && !props.has("signed_write")) {
      fs.push({ id: "GATT-UNAUTH-WRITE", severity: lock ? "high" : "medium", title: `Unauthenticated writable control characteristic ${ch}` });
    }
  }

  fs.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
  return fs;
}

export function insecure(fs: Finding[]): boolean {
  return fs.some((f) => f.severity !== "info");
}
