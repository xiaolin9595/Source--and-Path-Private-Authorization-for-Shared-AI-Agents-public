//! Short, proof-free deserialization gate for the shared matched-service wire.

use plan_a_dac_fixed_wrapper::{semantic_schema::sha256_hex, service_wire::ResidentCommand};
use serde_json::{json, Value};
use std::{env, fs};

fn field(value: &Value, name: &str) -> Value {
    value
        .get(name)
        .unwrap_or_else(|| panic!("contract fixture missing {name}"))
        .clone()
}

fn main() {
    let path = env::args()
        .nth(1)
        .expect("usage: dac_jsonl_contract_check FIXTURE.json");
    let bytes = fs::read(path).expect("read DAC JSONL contract fixture");
    let fixture: Value = serde_json::from_slice(&bytes).expect("parse DAC JSONL contract fixture");
    assert_eq!(fixture["wire_version"], "plan-a-matched-jsonl-v1");
    assert_eq!(fixture["backend"], "dac-bw6-761");
    let manifest = field(&fixture, "canonical_manifest");
    let expected = field(&fixture, "expected");
    let envelope = field(&fixture, "proof_envelope");
    let header_envelope = field(&fixture, "header_envelope");
    let backend_profile = field(&fixture, "backend_profile");
    let templates = fixture["commands"]
        .as_array()
        .expect("commands must be an array");
    assert_eq!(templates.len(), 3);

    let mut names = Vec::new();
    for template in templates {
        let name = template["command"].as_str().expect("command name");
        let command = match name {
            "materialize-and-verify-header" => json!({
                "command": name,
                "canonical_manifest": manifest,
                "semantic_input_sha256": template["semantic_input_sha256"],
                "update_index": template["update_index"],
                "header_envelope": header_envelope,
                "backend_profile": backend_profile,
            }),
            "verify-at-read" => json!({
                "command": name,
                "canonical_manifest": manifest,
                "expected": expected,
                "envelope": envelope,
            }),
            "commit" => json!({
                "command": name,
                "ticket": template["ticket"],
                "canonical_manifest": manifest,
                "expected": expected,
                "envelope": envelope,
            }),
            _ => panic!("unknown command template {name}"),
        };
        let encoded = serde_json::to_vec(&command).expect("serialize complete command");
        assert!(!encoded.windows(2).any(|window| window == b"vk"));
        assert!(!command["envelope"].get("actual").is_some());
        let decoded: ResidentCommand =
            serde_json::from_slice(&encoded).expect("deserialize exact resident command");
        assert_eq!(decoded.name(), name);
        names.push(name);
    }

    println!(
        "{}",
        serde_json::to_string(&json!({
            "valid": true,
            "wire_version": fixture["wire_version"],
            "backend": fixture["backend"],
            "commands": names,
            "fixture_sha256": sha256_hex(&bytes),
            "proof_or_setup_executed": false,
        }))
        .unwrap()
    );
}
