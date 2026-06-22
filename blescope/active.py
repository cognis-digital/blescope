"""Authorization-gated ACTIVE BLE scanning for blescope.

PASSIVE analysis (``blescope scan``) is the safe default: it only reads a
capture you provide and never touches a radio or a network.

ACTIVE mode (``blescope scan-live``) pulls *live* GATT data from a BLE device
or adapter **you own and are authorized to test**. It is engineered as a hard
opt-in:

* **OFF by default.** Active code never runs from the passive ``scan`` path.
* **Explicit consent flag.** ``--authorized`` is mandatory; without it the
  command refuses and exits 2.
* **Scope allowlist.** ``--target-allowlist`` (a comma list or a file of BLE
  addresses) is mandatory and non-empty. Any device whose address is not in
  scope is skipped — never probed.
* **Rate limit.** ``--rate`` caps probes/second (default 1.0); a token-bucket
  paces every connection attempt.
* **Loud banner.** A standing "AUTHORIZED USE ONLY" notice is printed to stderr
  before any active operation.

The actual radio I/O is delegated to a pluggable :class:`Scanner`. The bundled
default refuses to invent data: if no real BLE backend is wired in it raises,
so nothing is ever fabricated. Tests inject a :class:`MockScanner` that returns
fixtures — no real device, adapter, or external host is ever contacted in CI.
"""
from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol

from .core import analyze_capture, AnalysisResult

AUTHORIZED_BANNER = (
    "================================================================\n"
    " blescope ACTIVE mode — AUTHORIZED USE ONLY\n"
    " Probe only devices you own or have explicit written permission to\n"
    " test. Active BLE scanning of third-party devices may be illegal.\n"
    "================================================================"
)


class ScopeError(Exception):
    """Raised when active mode is invoked without proper authorization/scope."""


def normalize_addr(addr: str) -> str:
    """Canonicalize a BLE address for scope comparison (upper, colon-stripped)."""
    return str(addr).strip().upper().replace("-", ":")


def load_allowlist(spec: Optional[str]) -> set[str]:
    """Build an allowlist set from a comma list or a path to a newline file.

    Empty / missing spec yields an empty set (which the gate then rejects).
    """
    if not spec:
        return set()
    # A real file path takes precedence over treating the value as a literal list.
    if os.path.isfile(spec):
        with open(spec, "r", encoding="utf-8") as fh:
            raw = fh.read()
        parts = raw.replace(",", "\n").splitlines()
    else:
        parts = spec.split(",")
    return {normalize_addr(p) for p in parts if p.strip() and not p.strip().startswith("#")}


@dataclass
class RateLimiter:
    """Simple token-bucket pacing active probes to ``rate`` per second."""

    rate: float
    _allowance: float = field(default=0.0, init=False)
    _last: float = field(default=0.0, init=False)
    _clock: Callable[[], float] = time.monotonic
    _sleep: Callable[[float], None] = time.sleep

    def __post_init__(self) -> None:
        if self.rate <= 0:
            raise ScopeError("rate limit must be > 0 probes/second")
        self._allowance = 1.0
        self._last = self._clock()

    def acquire(self) -> None:
        now = self._clock()
        elapsed = now - self._last
        self._last = now
        self._allowance = min(self.rate, self._allowance + elapsed * self.rate)
        if self._allowance < 1.0:
            wait = (1.0 - self._allowance) / self.rate
            self._sleep(wait)
            self._allowance = 0.0
        else:
            self._allowance -= 1.0


class Scanner(Protocol):
    """Pluggable BLE backend. A real implementation talks to an adapter."""

    def discover(self) -> list[dict[str, Any]]:
        """Return advertised devices as ``[{"address": ..., "name": ...}, ...]``."""
        ...

    def connect_and_enumerate(self, address: str) -> dict[str, Any]:
        """Connect to ``address`` and return a capture dict (core schema)."""
        ...


class NullScanner:
    """Default backend with no radio wired in. Refuses rather than fabricate."""

    def discover(self) -> list[dict[str, Any]]:
        raise ScopeError(
            "no BLE backend available — active scanning requires a real adapter "
            "backend (e.g. a bleak-based Scanner) to be injected. blescope will "
            "not fabricate device data."
        )

    def connect_and_enumerate(self, address: str) -> dict[str, Any]:
        raise ScopeError("no BLE backend available")


@dataclass
class ActiveConfig:
    """Validated configuration for an authorized active run."""

    authorized: bool
    allowlist: set[str]
    rate: float = 1.0

    def ensure_gated(self) -> None:
        """Enforce the authorization boundary. Raises :class:`ScopeError`."""
        if not self.authorized:
            raise ScopeError(
                "active scanning is disabled by default; pass --authorized to "
                "confirm you own / are permitted to test the target devices"
            )
        if not self.allowlist:
            raise ScopeError(
                "active scanning requires a non-empty --target-allowlist "
                "(BLE addresses in scope); refusing to probe an open scope"
            )
        if self.rate <= 0:
            raise ScopeError("--rate must be > 0 probes/second")

    def in_scope(self, address: str) -> bool:
        return normalize_addr(address) in self.allowlist


@dataclass
class ActiveResult:
    """Outcome of an authorized active run over the in-scope devices."""

    scanned: list[str]
    skipped_out_of_scope: list[str]
    results: dict[str, AnalysisResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": "active",
            "scanned": self.scanned,
            "skipped_out_of_scope": self.skipped_out_of_scope,
            "results": {addr: r.to_dict() for addr, r in self.results.items()},
            "insecure": any(r.insecure() for r in self.results.values()),
        }


def run_active(config: ActiveConfig, scanner: Scanner,
               banner_stream=sys.stderr) -> ActiveResult:
    """Discover, scope-filter, rate-limit, connect, and analyze in-scope devices.

    Every device returned by discovery is checked against the allowlist; out-of
    scope devices are recorded and skipped without any connection attempt. A
    rate limiter paces each connection. Analysis itself reuses the passive
    engine, so findings are identical to ``scan`` over the same data.
    """
    config.ensure_gated()
    if banner_stream is not None:
        print(AUTHORIZED_BANNER, file=banner_stream)

    limiter = RateLimiter(rate=config.rate)
    scanned: list[str] = []
    skipped: list[str] = []
    results: dict[str, AnalysisResult] = {}

    for dev in scanner.discover():
        addr = normalize_addr(dev.get("address", ""))
        if not addr:
            continue
        if not config.in_scope(addr):
            skipped.append(addr)
            continue
        limiter.acquire()
        capture = scanner.connect_and_enumerate(addr)
        results[addr] = analyze_capture(capture or {})
        scanned.append(addr)

    return ActiveResult(scanned=scanned, skipped_out_of_scope=skipped, results=results)


class MockScanner:
    """Test/fixture backend. Returns canned devices + captures; no real I/O.

    Used by the test suite and the ``--demo`` path so active mode can be
    exercised end-to-end without touching a radio or any external host.
    """

    def __init__(self, devices: list[dict[str, Any]],
                 captures: dict[str, dict[str, Any]]):
        self._devices = devices
        self._captures = {normalize_addr(k): v for k, v in captures.items()}

    def discover(self) -> list[dict[str, Any]]:
        return list(self._devices)

    def connect_and_enumerate(self, address: str) -> dict[str, Any]:
        return self._captures.get(normalize_addr(address), {})
