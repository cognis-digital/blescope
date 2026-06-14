"""Tests for hardened error handling and edge-case paths added in the hardening pass."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from blescope.core import analyze_capture, load_capture
from blescope.cli import main


# ---------------------------------------------------------------------------
# load_capture edge cases
# ---------------------------------------------------------------------------

def test_load_capture_empty_string_returns_empty_dict():
    assert load_capture("") == {}


def test_load_capture_whitespace_only_returns_empty_dict():
    assert load_capture("   \n\t  ") == {}


def test_load_capture_rejects_json_array():
    with pytest.raises(ValueError, match="capture JSON must be an object"):
        load_capture("[1, 2, 3]")


def test_load_capture_rejects_non_string():
    with pytest.raises(TypeError, match="must be a str"):
        load_capture(None)  # type: ignore[arg-type]


def test_load_capture_rejects_bytes():
    with pytest.raises(TypeError, match="must be a str"):
        load_capture(b'{"device": {}}')  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# analyze_capture input validation
# ---------------------------------------------------------------------------

def test_analyze_capture_rejects_none():
    with pytest.raises(TypeError, match="capture must be a dict"):
        analyze_capture(None)  # type: ignore[arg-type]


def test_analyze_capture_rejects_list():
    with pytest.raises(TypeError, match="capture must be a dict"):
        analyze_capture([{"service": "1815"}])  # type: ignore[arg-type]


def test_analyze_capture_empty_dict_is_safe():
    """An empty capture should produce a result without raising."""
    result = analyze_capture({})
    assert result.profile == "unknown"
    assert result.services == []
    assert result.characteristics == []


def test_analyze_capture_handles_non_iterable_properties():
    """A numeric 'properties' field must not crash — treat as no properties."""
    capture = {
        "device": {"name": "BrokenDevice"},
        "gatt": [
            {"service": "1815", "characteristic": "2a56", "properties": 42}
        ],
        "smp": {},
        "att_ops": [],
    }
    result = analyze_capture(capture)
    # characteristics parsed, properties list should be empty
    assert any(c["uuid"] == "2a56" for c in result.characteristics)
    char = next(c for c in result.characteristics if c["uuid"] == "2a56")
    assert char["properties"] == []


def test_analyze_capture_handles_non_dict_att_ops_items():
    """Non-dict entries in att_ops must be skipped gracefully."""
    capture = {
        "device": {},
        "gatt": [],
        "smp": {"method": "numeric_comparison", "mitm": True,
                "secure_connections": True, "max_enc_key_size": 16},
        "att_ops": ["not_a_dict", None, 42],
    }
    result = analyze_capture(capture)
    # Should not raise; no ATT-PLAINTEXT-CTRL finding expected
    ids = {f.id for f in result.findings}
    assert "ATT-PLAINTEXT-CTRL" not in ids


# ---------------------------------------------------------------------------
# CLI error paths
# ---------------------------------------------------------------------------

def test_cli_missing_file_returns_exit_2(capsys):
    rc = main(["scan", "/nonexistent/path/capture.json"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "error:" in err


def test_cli_json_array_file_returns_exit_2(capsys, tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("[1, 2, 3]", encoding="utf-8")
    rc = main(["scan", str(f)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "error:" in err


def test_cli_empty_file_runs_cleanly(capsys, tmp_path):
    """An empty capture file should produce a report without crashing."""
    f = tmp_path / "empty.json"
    f.write_text("", encoding="utf-8")
    rc = main(["scan", str(f)])
    # Exit code 1 (insecure: SMP-NONE finding) or 0; must not be 2
    assert rc in (0, 1)


def test_cli_malformed_json_uses_text_fallback(capsys, tmp_path):
    """Malformed JSON triggers the text-parse fallback; should not exit 2."""
    f = tmp_path / "text.txt"
    f.write_text(
        "device.name: Fallback\n"
        "smp.method: numeric_comparison\n"
        "smp.mitm: true\n"
        "smp.secure_connections: true\n"
        "smp.max_enc_key_size: 16\n",
        encoding="utf-8",
    )
    rc = main(["scan", str(f)])
    assert rc in (0, 1)
    out = capsys.readouterr().out
    assert "Fallback" in out
