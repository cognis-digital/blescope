package main

import "testing"

const lockCapture = `{
  "device": {"name": "FrontDoorLock", "address": "AA:BB:CC:DD:EE:FF"},
  "gatt": [{"service": "1815", "characteristic": "2a56", "properties": ["read","write","notify"]}],
  "smp": {"method": "just_works", "io_capability": "NoInputNoOutput",
          "mitm": false, "secure_connections": false, "max_enc_key_size": 7},
  "att_ops": [{"op": "write", "characteristic": "2a56", "value": "01", "encrypted": false}]
}`

const secureCapture = `{
  "device": {"name": "SecureBand", "address": "11:22:33:44:55:66"},
  "gatt": [{"service": "180d", "characteristic": "2a37", "properties": ["notify"]}],
  "smp": {"method": "numeric_comparison", "io_capability": "DisplayYesNo",
          "mitm": true, "secure_connections": true, "max_enc_key_size": 16},
  "att_ops": []
}`

func ids(fs []Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.ID] = true
	}
	return m
}

func TestNormUUID(t *testing.T) {
	cases := map[string]string{
		"1815": "1815", "0x1815": "1815",
		"0000180a-0000-1000-8000-00805f9b34fb": "180a",
	}
	for in, want := range cases {
		if got := normUUID(in); got != want {
			t.Errorf("normUUID(%q)=%q want %q", in, got, want)
		}
	}
}

func TestInsecureLock(t *testing.T) {
	fs, insecure, err := auditBytes([]byte(lockCapture))
	if err != nil {
		t.Fatal(err)
	}
	if !insecure {
		t.Fatal("expected insecure lock")
	}
	id := ids(fs)
	for _, want := range []string{"SMP-JUSTWORKS", "SMP-LEGACY", "SMP-WEAKKEY", "ATT-PLAINTEXT-CTRL"} {
		if !id[want] {
			t.Errorf("missing finding %s", want)
		}
	}
	if fs[0].Severity != "critical" {
		t.Errorf("worst-first ordering broken: %s", fs[0].Severity)
	}
}

func TestSecureClean(t *testing.T) {
	fs, insecure, err := auditBytes([]byte(secureCapture))
	if err != nil {
		t.Fatal(err)
	}
	if insecure || len(fs) != 0 {
		t.Errorf("expected clean, got %v", fs)
	}
}

func TestNoSMP(t *testing.T) {
	fs, _, err := auditBytes([]byte(`{"device":{"name":"x"},"gatt":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !ids(fs)["SMP-NONE"] {
		t.Error("expected SMP-NONE when no smp block")
	}
}

func TestBadJSON(t *testing.T) {
	if _, _, err := auditBytes([]byte("not json")); err == nil {
		t.Error("expected error on bad json")
	}
}
