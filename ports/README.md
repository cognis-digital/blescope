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
| Perl | `perl/` | `perl ports/perl/blescope.pl ../../demos/01-basic/frontdoor_lock.json` | `perl blescope.t` |
| Ruby | `ruby/` | `ruby ports/ruby/blescope.rb ../../demos/01-basic/frontdoor_lock.json` | `ruby test_blescope.rb` |
| Shell + awk | `shell/` | `sh ports/shell/blescope.sh ../../demos/01-basic/frontdoor_lock.json` | `sh test_blescope.sh` |

All ports exit `1` when an actionable finding is present (CI gate) and `0` on a
clean capture, matching the Python reference. Their finding-ID sets are verified
identical to the Python engine across every JSON demo capture.

### Dependency footprint per port

| Port | Runtime deps |
|---|---|
| Python | stdlib only |
| JavaScript / TypeScript | Node ≥ 18 (no npm deps; tests use the built-in `node --test`) |
| Go | stdlib `encoding/json` only |
| Rust | a tiny vendored JSON parser in `src/lib.rs` (no crates) |
| **Perl** | core `JSON::PP` (ships with Perl 5) — nothing to install |
| **Ruby** | stdlib `json` + `minitest` (both bundled with Ruby) |
| **Shell + awk** | a POSIX shell and `awk` — no jq, no Python, no network |

> **Note on toolchains:** Go, Rust, and Ruby are built and tested on GitHub
> runners by `.github/workflows/ports.yml`. The Python, JavaScript, TypeScript,
> Perl, and Shell ports are also verified locally. The toolchains for the
> CI-only ports are not assumed to be present on every dev machine.

> **Air-gap note:** the Perl and Shell ports are the most portable — Perl 5 and
> a POSIX `awk` are present on essentially every Unix host out of the box, so you
> can audit a capture on a locked-down, network-isolated box with zero installs.

Contributions of additional ports (C#, Bun, Deno, WASM, Lua) are welcome — see
../CONTRIBUTING.md.
