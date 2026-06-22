#!/usr/bin/env node
// PASSIVE CLI for the TypeScript port: blescope-ts <capture.json | ->
import { readFileSync } from "node:fs";
import { audit, insecure, type Capture } from "./blescope.ts";

function readInput(arg?: string): string {
  if (arg && arg !== "-") return readFileSync(arg, "utf8");
  return readFileSync(0, "utf8");
}

// CLI entry (this file is only invoked directly, so no main-guard needed).
const arg = process.argv[2];
let cap: Capture;
try {
  cap = JSON.parse(readInput(arg));
} catch (e) {
  process.stderr.write(`error: invalid capture: ${(e as Error).message}\n`);
  process.exit(2);
}
const fs = audit(cap);
const bad = insecure(fs);
process.stdout.write(JSON.stringify({ tool: "blescope", findings: fs, insecure: bad }, null, 2) + "\n");
process.exit(bad ? 1 : 0);
