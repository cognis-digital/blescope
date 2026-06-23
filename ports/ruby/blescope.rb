#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Ruby port of the blescope BLE pairing-audit core.
#
# PASSIVE only: reads a BLE GATT capture (JSON) from a file argument or stdin
# and reports insecure-pairing findings using the same rule IDs as the Python
# reference. It never touches a radio or a network. Depends only on the stdlib
# `json` library.
#
#   ruby blescope.rb capture.json          # JSON report, exit 1 if insecure
#   cat capture.json | ruby blescope.rb -  # stdin
require "json"

module Blescope
  VERSION = "0.6.0"

  SEVERITY_ORDER = { "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, "info" => 4 }.freeze
  SENSITIVE = %w[2a56 2a57 2a58 fd5b].freeze
  LOCK_SERVICES = %w[1815 fd5a fd5b].freeze
  LOCK_KEYWORDS = %w[lock door bolt latch].freeze

  module_function

  def norm_uuid(value)
    s = value.to_s.strip.downcase.gsub("0x", "").delete("-")
    s = s[4, 4] if s.length == 32 && s.end_with?("00001000800000805f9b34fb")
    s = s[4, 4] if s.length > 4 && s.start_with?("0000")
    s
  end

  def truthy(hash, key)
    hash.is_a?(Hash) && hash[key] == true
  end

  def str(hash, key)
    return "" unless hash.is_a?(Hash) && hash[key]

    v = hash[key]
    v.is_a?(String) ? v : ""
  end

  def lock?(cap)
    (cap["gatt"] || []).each do |g|
      return true if LOCK_SERVICES.include?(norm_uuid(g["service"]))
    end
    name = str(cap["device"] || {}, "name").downcase
    LOCK_KEYWORDS.any? { |kw| name.include?(kw) }
  end

  def audit(cap)
    findings = []
    is_lock = lock?(cap)
    smp = cap["smp"]

    if smp.is_a?(Hash) && !smp.empty?
      method = str(smp, "method").downcase
      mitm = truthy(smp, "mitm")
      sc = truthy(smp, "secure_connections")
      oob = truthy(smp, "oob")
      iocap = str(smp, "io_capability")

      if %w[just_works justworks].include?(method) || (!mitm && !oob)
        findings << { "id" => "SMP-JUSTWORKS", "severity" => is_lock ? "critical" : "high",
                      "title" => "Just Works pairing (no MITM protection)" }
      end
      unless sc
        findings << { "id" => "SMP-LEGACY", "severity" => is_lock ? "high" : "medium",
                      "title" => "LE Legacy Pairing (no Secure Connections)" }
      end
      ks = smp["max_enc_key_size"]
      if ks.is_a?(Integer) && ks < 16
        findings << { "id" => "SMP-WEAKKEY", "severity" => ks <= 7 ? "high" : "medium",
                      "title" => "Short encryption key (#{ks} bytes)" }
      end
      if iocap == "NoInputNoOutput"
        findings << { "id" => "SMP-IOCAP", "severity" => "medium",
                      "title" => "NoInputNoOutput I/O capability forces Just Works" }
      end
      if truthy(smp, "debug_keys") || str(smp, "public_key").downcase == "debug"
        findings << { "id" => "SMP-DEBUGKEY", "severity" => "critical",
                      "title" => "Bluetooth debug keys in use" }
      end
      if truthy(smp, "bonding") && !mitm && ["just_works", "justworks", ""].include?(method)
        findings << { "id" => "SMP-WEAKBOND", "severity" => "medium",
                      "title" => "Bonding stores an unauthenticated long-term key" }
      end
    else
      findings << { "id" => "SMP-NONE", "severity" => "medium",
                    "title" => "No pairing/security manager exchange observed" }
    end

    (cap["att_ops"] || []).each do |op|
      next unless %w[write write_command write_request].include?(str(op, "op").downcase)

      ch = norm_uuid(op["characteristic"])
      next unless SENSITIVE.include?(ch) && !truthy(op, "encrypted")

      findings << { "id" => "ATT-PLAINTEXT-CTRL", "severity" => is_lock ? "critical" : "high",
                    "title" => "Plaintext write to control characteristic #{ch}" }
    end

    (cap["gatt"] || []).each do |g|
      c = g["characteristic"]
      next if c.nil? || c == ""

      ch = norm_uuid(c)
      props = (g["properties"] || []).map { |p| p.to_s.downcase }
      next unless SENSITIVE.include?(ch) && props.include?("write") &&
                  !props.include?("authenticated_write") && !props.include?("signed_write")

      findings << { "id" => "GATT-UNAUTH-WRITE", "severity" => is_lock ? "high" : "medium",
                    "title" => "Unauthenticated writable control characteristic #{ch}" }
    end

    findings.sort_by { |f| SEVERITY_ORDER[f["severity"]] }
  end

  def audit_text(text)
    cap = JSON.parse(text)
    raise ArgumentError, "capture JSON must be an object" unless cap.is_a?(Hash)

    findings = audit(cap)
    insecure = findings.any? { |f| f["severity"] != "info" }
    [findings, insecure]
  end
end

if __FILE__ == $PROGRAM_NAME
  path = ARGV[0]
  text = (path.nil? || path == "-") ? $stdin.read : File.read(path)
  begin
    findings, insecure = Blescope.audit_text(text)
  rescue JSON::ParserError, ArgumentError => e
    warn "error: invalid capture: #{e.message}"
    exit 2
  end
  puts JSON.pretty_generate("tool" => "blescope", "findings" => findings, "insecure" => insecure)
  exit(insecure ? 1 : 0)
end
