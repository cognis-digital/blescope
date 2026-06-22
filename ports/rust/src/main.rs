// Rust port of blescope (PASSIVE only) — CLI wrapper around the audit library.
use blescope::{audit, insecure};
use std::io::Read;

fn main() {
    let arg = std::env::args().nth(1);
    let data = match arg.as_deref() {
        Some(p) if p != "-" => std::fs::read_to_string(p),
        _ => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).map(|_| s)
        }
    };
    let data = match data {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(2);
        }
    };
    let cap: serde_json::Value = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: invalid capture: {}", e);
            std::process::exit(2);
        }
    };
    let fs = audit(&cap);
    let bad = insecure(&fs);
    let arr: Vec<serde_json::Value> = fs
        .iter()
        .map(|f| serde_json::json!({"id": f.id, "severity": f.severity, "title": f.title}))
        .collect();
    let out = serde_json::json!({"tool": "blescope", "findings": arr, "insecure": bad});
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
    std::process::exit(if bad { 1 } else { 0 });
}
