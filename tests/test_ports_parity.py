"""Cross-port parity: each polyglot port must agree with the Python reference.

For every JSON capture in ``demos/`` we run the Python engine and, for each port
whose toolchain is available on this machine, the corresponding port, then assert
the set of finding rule-IDs and the insecure/exit verdict match exactly.

Ports whose toolchain is absent are skipped (not failed) so the suite stays green
offline on any machine; CI (.github/workflows/ports.yml) exercises every port on
a runner that has the toolchain installed.

No network, no radio — every port reads a local fixture file only.
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from blescope.core import analyze_capture, load_capture

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEMOS_DIR = os.path.join(REPO_ROOT, "demos")
PORTS_DIR = os.path.join(REPO_ROOT, "ports")


def _demo_json_files():
    out = []
    for root, _dirs, files in os.walk(DEMOS_DIR):
        for fn in files:
            if fn.endswith(".json"):
                out.append(os.path.join(root, fn))
    return sorted(out)


DEMOS = _demo_json_files()


def python_ids_and_verdict(path):
    with open(path, "r", encoding="utf-8") as fh:
        res = analyze_capture(load_capture(fh.read()))
    return {f.id for f in res.findings}, res.insecure()


# --------------------------------------------------------------------------- #
# Perl port
# --------------------------------------------------------------------------- #
PERL = shutil.which("perl")
PERL_SCRIPT = os.path.join(PORTS_DIR, "perl", "blescope.pl")


@pytest.mark.skipif(not PERL, reason="perl not installed")
@pytest.mark.parametrize("path", DEMOS)
def test_perl_parity(path):
    proc = subprocess.run([PERL, PERL_SCRIPT, path],
                          capture_output=True, text=True)
    assert proc.returncode in (0, 1), proc.stderr
    data = json.loads(proc.stdout)
    port_ids = {f["id"] for f in data["findings"]}
    py_ids, py_insecure = python_ids_and_verdict(path)
    assert port_ids == py_ids, f"{os.path.basename(path)}: perl {port_ids} vs py {py_ids}"
    assert data["insecure"] is py_insecure
    assert (proc.returncode == 1) is py_insecure


# --------------------------------------------------------------------------- #
# Ruby port
# --------------------------------------------------------------------------- #
RUBY = shutil.which("ruby")
RUBY_SCRIPT = os.path.join(PORTS_DIR, "ruby", "blescope.rb")


@pytest.mark.skipif(not RUBY, reason="ruby not installed")
@pytest.mark.parametrize("path", DEMOS)
def test_ruby_parity(path):
    proc = subprocess.run([RUBY, RUBY_SCRIPT, path],
                          capture_output=True, text=True)
    assert proc.returncode in (0, 1), proc.stderr
    data = json.loads(proc.stdout)
    port_ids = {f["id"] for f in data["findings"]}
    py_ids, py_insecure = python_ids_and_verdict(path)
    assert port_ids == py_ids, f"{os.path.basename(path)}: ruby {port_ids} vs py {py_ids}"
    assert data["insecure"] is py_insecure


# --------------------------------------------------------------------------- #
# Shell + awk port
# --------------------------------------------------------------------------- #
SH = shutil.which("sh")
AWK = shutil.which("awk")
SH_SCRIPT = os.path.join(PORTS_DIR, "shell", "blescope.sh")


def _shell_ids(path):
    proc = subprocess.run([SH, SH_SCRIPT, path], capture_output=True, text=True)
    out_ids = set()
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("[") and "]" in line and ":" in line:
            rule = line.split("]", 1)[1].split(":", 1)[0].strip()
            out_ids.add(rule)
    return out_ids, proc.returncode


@pytest.mark.skipif(not (SH and AWK), reason="sh/awk not available")
@pytest.mark.parametrize("path", DEMOS)
def test_shell_parity(path):
    port_ids, code = _shell_ids(path)
    py_ids, py_insecure = python_ids_and_verdict(path)
    assert port_ids == py_ids, f"{os.path.basename(path)}: shell {port_ids} vs py {py_ids}"
    assert code in (0, 1)
    assert (code == 1) is py_insecure


# --------------------------------------------------------------------------- #
# Sanity: at least one port is exercised here (so this file isn't a no-op).
# --------------------------------------------------------------------------- #
def test_some_port_available():
    assert PERL or RUBY or (SH and AWK), "no port toolchain available at all"


def test_demo_corpus_nonempty():
    assert len(DEMOS) >= 8
