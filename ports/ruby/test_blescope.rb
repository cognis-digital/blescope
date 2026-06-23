#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Behavior tests for the Ruby port. Run: ruby test_blescope.rb
require "minitest/autorun"
require_relative "blescope"

LOCK = <<~JSON
  {
    "device": {"name": "FrontDoorLock", "address": "AA:BB:CC:DD:EE:FF"},
    "gatt": [{"service": "1815", "characteristic": "2a56", "properties": ["read","write","notify"]}],
    "smp": {"method": "just_works", "io_capability": "NoInputNoOutput",
            "mitm": false, "secure_connections": false, "max_enc_key_size": 7},
    "att_ops": [{"op": "write", "characteristic": "2a56", "value": "01", "encrypted": false}]
  }
JSON

SECURE = <<~JSON
  {
    "device": {"name": "SecureBand", "address": "11:22:33:44:55:66"},
    "gatt": [{"service": "180d", "characteristic": "2a37", "properties": ["notify"]}],
    "smp": {"method": "numeric_comparison", "io_capability": "DisplayYesNo",
            "mitm": true, "secure_connections": true, "max_enc_key_size": 16},
    "att_ops": []
  }
JSON

class BlescopeTest < Minitest::Test
  def ids(findings)
    findings.map { |f| f["id"] }
  end

  def test_norm_uuid_passthrough
    assert_equal "1815", Blescope.norm_uuid("1815")
  end

  def test_norm_uuid_strips_0x
    assert_equal "1815", Blescope.norm_uuid("0x1815")
  end

  def test_norm_uuid_reduces_base
    assert_equal "180a", Blescope.norm_uuid("0000180a-0000-1000-8000-00805f9b34fb")
  end

  def test_insecure_lock_flagged
    _findings, insecure = Blescope.audit_text(LOCK)
    assert insecure, "lock capture should be insecure"
  end

  def test_lock_finding_ids
    findings, = Blescope.audit_text(LOCK)
    present = ids(findings)
    %w[SMP-JUSTWORKS SMP-LEGACY SMP-WEAKKEY ATT-PLAINTEXT-CTRL].each do |id|
      assert_includes present, id
    end
  end

  def test_worst_first_ordering
    findings, = Blescope.audit_text(LOCK)
    assert_equal "critical", findings.first["severity"]
  end

  def test_secure_capture_clean
    findings, insecure = Blescope.audit_text(SECURE)
    refute insecure
    assert_empty findings
  end

  def test_no_smp
    findings, = Blescope.audit_text('{"device":{"name":"x"},"gatt":[]}')
    assert_includes ids(findings), "SMP-NONE"
  end

  def test_bad_json_raises
    assert_raises(JSON::ParserError) { Blescope.audit_text("not json") }
  end

  def test_array_rejected
    assert_raises(ArgumentError) { Blescope.audit_text("[]") }
  end

  def test_debug_keys
    cap = '{"device":{"name":"bulb"},"smp":{"method":"numeric_comparison","mitm":true,' \
          '"secure_connections":true,"max_enc_key_size":16,"debug_keys":true}}'
    findings, = Blescope.audit_text(cap)
    assert_includes ids(findings), "SMP-DEBUGKEY"
  end
end
