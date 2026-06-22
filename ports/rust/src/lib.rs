//! Rust port of the blescope BLE pairing-audit core (PASSIVE only).
//!
//! Reads a BLE GATT capture (JSON) and reports insecure-pairing findings using
//! the same rule IDs as the Python reference. Never touches a radio or network.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub id: &'static str,
    pub severity: &'static str,
    pub title: String,
}

fn sev_rank(s: &str) -> usize {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

pub fn norm_uuid(s: &str) -> String {
    let mut t = s.trim().to_lowercase().replace("0x", "").replace('-', "");
    if t.len() == 32 && t.ends_with("00001000800000805f9b34fb") {
        t = t[4..8].to_string();
    } else if t.len() > 4 && t.starts_with("0000") {
        t = t[4..8].to_string();
    }
    t
}

fn is_sensitive(ch: &str) -> bool {
    matches!(ch, "2a56" | "2a57" | "2a58" | "fd5b")
}

fn is_lock(cap: &Value) -> bool {
    if let Some(gatt) = cap.get("gatt").and_then(|g| g.as_array()) {
        for g in gatt {
            if let Some(svc) = g.get("service").and_then(|s| s.as_str()) {
                if matches!(norm_uuid(svc).as_str(), "1815" | "fd5a" | "fd5b") {
                    return true;
                }
            }
        }
    }
    let name = cap
        .get("device")
        .and_then(|d| d.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_lowercase();
    ["lock", "door", "bolt", "latch"].iter().any(|k| name.contains(k))
}

pub fn audit(cap: &Value) -> Vec<Finding> {
    let mut fs: Vec<Finding> = Vec::new();
    let lock = is_lock(cap);

    let smp = cap.get("smp");
    let smp_present = smp
        .and_then(|s| s.as_object())
        .map(|o| !o.is_empty())
        .unwrap_or(false);

    if smp_present {
        let smp = smp.unwrap();
        let method = smp.get("method").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        let mitm = smp.get("mitm").and_then(|v| v.as_bool()).unwrap_or(false);
        let sc = smp.get("secure_connections").and_then(|v| v.as_bool()).unwrap_or(false);
        let oob = smp.get("oob").and_then(|v| v.as_bool()).unwrap_or(false);
        let io_cap = smp.get("io_capability").and_then(|v| v.as_str()).unwrap_or("");

        if method == "just_works" || method == "justworks" || (!mitm && !oob) {
            fs.push(Finding {
                id: "SMP-JUSTWORKS",
                severity: if lock { "critical" } else { "high" },
                title: "Just Works pairing (no MITM protection)".into(),
            });
        }
        if !sc {
            fs.push(Finding {
                id: "SMP-LEGACY",
                severity: if lock { "high" } else { "medium" },
                title: "LE Legacy Pairing (no Secure Connections)".into(),
            });
        }
        if let Some(ks) = smp.get("max_enc_key_size").and_then(|v| v.as_i64()) {
            if ks < 16 {
                fs.push(Finding {
                    id: "SMP-WEAKKEY",
                    severity: if ks <= 7 { "high" } else { "medium" },
                    title: format!("Short encryption key ({} bytes)", ks),
                });
            }
        }
        if io_cap == "NoInputNoOutput" {
            fs.push(Finding {
                id: "SMP-IOCAP",
                severity: "medium",
                title: "NoInputNoOutput I/O capability forces Just Works".into(),
            });
        }
        let debug = smp.get("debug_keys").and_then(|v| v.as_bool()).unwrap_or(false)
            || smp.get("public_key").and_then(|v| v.as_str()).unwrap_or("").to_lowercase() == "debug";
        if debug {
            fs.push(Finding {
                id: "SMP-DEBUGKEY",
                severity: "critical",
                title: "Bluetooth debug keys in use".into(),
            });
        }
    } else {
        fs.push(Finding {
            id: "SMP-NONE",
            severity: "medium",
            title: "No pairing/security manager exchange observed".into(),
        });
    }

    if let Some(ops) = cap.get("att_ops").and_then(|v| v.as_array()) {
        for op in ops {
            let o = op.get("op").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
            if !matches!(o.as_str(), "write" | "write_command" | "write_request") {
                continue;
            }
            let ch = op.get("characteristic").and_then(|v| v.as_str()).map(norm_uuid).unwrap_or_default();
            let enc = op.get("encrypted").and_then(|v| v.as_bool()).unwrap_or(false);
            if is_sensitive(&ch) && !enc {
                fs.push(Finding {
                    id: "ATT-PLAINTEXT-CTRL",
                    severity: if lock { "critical" } else { "high" },
                    title: format!("Plaintext write to control characteristic {}", ch),
                });
            }
        }
    }

    if let Some(gatt) = cap.get("gatt").and_then(|v| v.as_array()) {
        for g in gatt {
            let ch = match g.get("characteristic").and_then(|v| v.as_str()) {
                Some(c) => norm_uuid(c),
                None => continue,
            };
            let props: Vec<String> = g
                .get("properties")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|p| p.as_str()).map(|s| s.to_lowercase()).collect())
                .unwrap_or_default();
            let has = |p: &str| props.iter().any(|x| x == p);
            if is_sensitive(&ch) && has("write") && !has("authenticated_write") && !has("signed_write") {
                fs.push(Finding {
                    id: "GATT-UNAUTH-WRITE",
                    severity: if lock { "high" } else { "medium" },
                    title: format!("Unauthenticated writable control characteristic {}", ch),
                });
            }
        }
    }

    fs.sort_by_key(|f| sev_rank(f.severity));
    fs
}

pub fn insecure(fs: &[Finding]) -> bool {
    fs.iter().any(|f| f.severity != "info")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn lock_cap() -> Value {
        json!({
            "device": {"name": "FrontDoorLock", "address": "AA:BB:CC:DD:EE:FF"},
            "gatt": [{"service": "1815", "characteristic": "2a56", "properties": ["read","write","notify"]}],
            "smp": {"method": "just_works", "io_capability": "NoInputNoOutput",
                    "mitm": false, "secure_connections": false, "max_enc_key_size": 7},
            "att_ops": [{"op": "write", "characteristic": "2a56", "value": "01", "encrypted": false}]
        })
    }

    #[test]
    fn test_norm_uuid() {
        assert_eq!(norm_uuid("0x1815"), "1815");
        assert_eq!(norm_uuid("0000180a-0000-1000-8000-00805f9b34fb"), "180a");
    }

    #[test]
    fn test_insecure_lock() {
        let fs = audit(&lock_cap());
        assert!(insecure(&fs));
        let ids: Vec<&str> = fs.iter().map(|f| f.id).collect();
        for want in ["SMP-JUSTWORKS", "SMP-LEGACY", "SMP-WEAKKEY", "ATT-PLAINTEXT-CTRL"] {
            assert!(ids.contains(&want), "missing {}", want);
        }
        assert_eq!(fs[0].severity, "critical");
    }

    #[test]
    fn test_secure_clean() {
        let cap = json!({
            "device": {"name": "SecureBand"},
            "gatt": [{"service": "180d", "characteristic": "2a37", "properties": ["notify"]}],
            "smp": {"method": "numeric_comparison", "io_capability": "DisplayYesNo",
                    "mitm": true, "secure_connections": true, "max_enc_key_size": 16},
            "att_ops": []
        });
        let fs = audit(&cap);
        assert!(fs.is_empty());
        assert!(!insecure(&fs));
    }

    #[test]
    fn test_no_smp() {
        let fs = audit(&json!({"device": {"name": "x"}, "gatt": []}));
        assert!(fs.iter().any(|f| f.id == "SMP-NONE"));
    }
}
