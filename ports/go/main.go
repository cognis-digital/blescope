// Go port of the blescope BLE pairing-audit core — single binary, zero deps.
//
// PASSIVE only: reads a BLE GATT capture (JSON) from a file argument or stdin
// and reports insecure-pairing findings using the same rule IDs as the Python
// reference. It never touches a radio or a network.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
}

var severityOrder = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

var sensitiveChars = map[string]bool{
	"2a56": true, "2a57": true, "2a58": true, "fd5b": true,
}

var lockServices = map[string]bool{"1815": true, "fd5a": true, "fd5b": true}

type capture struct {
	Device map[string]any `json:"device"`
	Gatt   []struct {
		Service        string `json:"service"`
		Characteristic string `json:"characteristic"`
		Properties     []any  `json:"properties"`
	} `json:"gatt"`
	Smp    map[string]any `json:"smp"`
	AttOps []struct {
		Op             string `json:"op"`
		Characteristic string `json:"characteristic"`
		Encrypted      bool   `json:"encrypted"`
	} `json:"att_ops"`
}

func normUUID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "0x", "")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) == 32 && strings.HasSuffix(s, "00001000800000805f9b34fb") {
		s = s[4:8]
	}
	if len(s) > 4 && strings.HasPrefix(s, "0000") {
		s = s[4:8]
	}
	return s
}

func asBool(m map[string]any, k string) bool {
	if v, ok := m[k]; ok {
		b, _ := v.(bool)
		return b
	}
	return false
}

func asStr(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func isLock(c capture) bool {
	for _, g := range c.Gatt {
		if lockServices[normUUID(g.Service)] {
			return true
		}
	}
	name := strings.ToLower(asStr(c.Device, "name"))
	for _, kw := range []string{"lock", "door", "bolt", "latch"} {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

func audit(c capture) []Finding {
	var fs []Finding
	lock := isLock(c)

	if len(c.Smp) > 0 {
		method := strings.ToLower(asStr(c.Smp, "method"))
		mitm := asBool(c.Smp, "mitm")
		sc := asBool(c.Smp, "secure_connections")
		oob := asBool(c.Smp, "oob")
		ioCap := asStr(c.Smp, "io_capability")

		if method == "just_works" || method == "justworks" || (!mitm && !oob) {
			sev := "high"
			if lock {
				sev = "critical"
			}
			fs = append(fs, Finding{"SMP-JUSTWORKS", sev, "Just Works pairing (no MITM protection)"})
		}
		if !sc {
			sev := "medium"
			if lock {
				sev = "high"
			}
			fs = append(fs, Finding{"SMP-LEGACY", sev, "LE Legacy Pairing (no Secure Connections)"})
		}
		if ks, ok := c.Smp["max_enc_key_size"].(float64); ok && int(ks) < 16 {
			sev := "medium"
			if int(ks) <= 7 {
				sev = "high"
			}
			fs = append(fs, Finding{"SMP-WEAKKEY", sev, "Short encryption key"})
		}
		if ioCap == "NoInputNoOutput" {
			fs = append(fs, Finding{"SMP-IOCAP", "medium", "NoInputNoOutput I/O capability forces Just Works"})
		}
		if asBool(c.Smp, "debug_keys") || strings.ToLower(asStr(c.Smp, "public_key")) == "debug" {
			fs = append(fs, Finding{"SMP-DEBUGKEY", "critical", "Bluetooth debug keys in use"})
		}
	} else {
		fs = append(fs, Finding{"SMP-NONE", "medium", "No pairing/security manager exchange observed"})
	}

	for _, op := range c.AttOps {
		o := strings.ToLower(op.Op)
		if o != "write" && o != "write_command" && o != "write_request" {
			continue
		}
		ch := normUUID(op.Characteristic)
		if sensitiveChars[ch] && !op.Encrypted {
			sev := "high"
			if lock {
				sev = "critical"
			}
			fs = append(fs, Finding{"ATT-PLAINTEXT-CTRL", sev, "Plaintext write to control characteristic " + ch})
		}
	}

	for _, g := range c.Gatt {
		if g.Characteristic == "" {
			continue
		}
		ch := normUUID(g.Characteristic)
		props := map[string]bool{}
		for _, p := range g.Properties {
			if s, ok := p.(string); ok {
				props[strings.ToLower(s)] = true
			}
		}
		if sensitiveChars[ch] && props["write"] && !props["authenticated_write"] && !props["signed_write"] {
			sev := "medium"
			if lock {
				sev = "high"
			}
			fs = append(fs, Finding{"GATT-UNAUTH-WRITE", sev, "Unauthenticated writable control characteristic " + ch})
		}
	}

	sort.SliceStable(fs, func(i, j int) bool {
		return severityOrder[fs[i].Severity] < severityOrder[fs[j].Severity]
	})
	return fs
}

func auditBytes(data []byte) ([]Finding, bool, error) {
	var c capture
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, false, err
	}
	fs := audit(c)
	insecure := false
	for _, f := range fs {
		if f.Severity != "info" {
			insecure = true
		}
	}
	return fs, insecure, nil
}

func main() {
	var data []byte
	var err error
	if len(os.Args) > 1 && os.Args[1] != "-" {
		data, err = os.ReadFile(os.Args[1])
	} else {
		data, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	fs, insecure, err := auditBytes(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: invalid capture:", err)
		os.Exit(2)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"tool": "blescope", "findings": fs, "insecure": insecure,
	}, "", "  ")
	fmt.Println(string(out))
	if insecure {
		os.Exit(1)
	}
}
