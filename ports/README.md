# Ports of blescope

The **PASSIVE** BLE pairing-audit core, ported across languages so you can drop
blescope into any stack or ship a single static binary. Every port reads a BLE
GATT capture (JSON) and emits the **same rule IDs** (`SMP-JUSTWORKS`,
`SMP-LEGACY`, `SMP-WEAKKEY`, `SMP-IOCAP`, `SMP-DEBUGKEY`, `SMP-NONE`,
`ATT-PLAINTEXT-CTRL`, `GATT-UNAUTH-WRITE`) with findings sorted worst-first.
None of the ports touch a radio or a network — they are passive only. The
authorization-gated **active** mode lives in the Python package.

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | `../blescope/` | `blescope scan capture.json` | `pytest` |
| JavaScript / Node | `javascript/` | `node ports/javascript/index.js capture.json` | `node --test` |
| TypeScript / Node | `typescript/` | `node --experimental-strip-types ports/typescript/cli.ts capture.json` | `npm test` |
| Go | `go/` | `cd ports/go && go run . ../../demos/01-basic/frontdoor_lock.json` | `go test ./...` |
| Rust | `rust/` | `cd ports/rust && cargo run -- ../../demos/01-basic/frontdoor_lock.json` | `cargo test` |

All ports exit `1` when an actionable finding is present (CI gate) and `0` on a
clean capture, matching the Python reference.

> **Note on Go/Rust:** these are built and tested on GitHub runners by
> `.github/workflows/ports.yml`. The Go/Rust toolchains are not assumed to be
> present locally; the JS/TS/Python ports are verified locally.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
../CONTRIBUTING.md.
