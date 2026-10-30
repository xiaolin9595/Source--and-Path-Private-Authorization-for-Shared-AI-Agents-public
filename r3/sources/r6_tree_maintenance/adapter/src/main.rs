use ark_bls12_381::Fr;
use ark_ed_on_bls12_381::Fr as Scalar;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use base64::{engine::general_purpose::STANDARD, Engine};
use plan_a_joint_circuit::{
    blind_update::{state_leaf, StateOpening},
    merkle::{build_tree, node_hash, path_for, root_from_path},
    poseidon::{canonical_le_bytes, Domain},
    signature::{public_key, SecretKey},
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
    time::Instant,
};

fn field_hex(value: Fr) -> String {
    let mut bytes = canonical_le_bytes(value);
    bytes.reverse();
    hex::encode(bytes)
}

fn parse_field(value: &str) -> Result<Fr, String> {
    let bytes = hex::decode(value).map_err(|_| "bad-field-hex")?;
    if bytes.len() != 32 {
        return Err("bad-field-length".into());
    }
    let value = Fr::from_be_bytes_mod_order(&bytes);
    if field_hex(value) != hex::encode(bytes) {
        return Err("noncanonical-field".into());
    }
    Ok(value)
}

fn synthetic_opening(seed: u64, index: usize, replacement: bool) -> StateOpening {
    let base = seed
        .wrapping_mul(4_000_003)
        .wrapping_add(index as u64 * 3 + replacement as u64);
    StateOpening {
        grant_root: Fr::from(base.wrapping_add(101)),
        expiry: 4_000_000_000,
        active: true,
        salt: Fr::from(base.wrapping_add(303)),
    }
}

fn owner(seed: u64, index: usize) -> Fr {
    Fr::from(seed.wrapping_mul(2_000_003).wrapping_add(index as u64 + 17))
}

fn generated_leaf(seed: u64, index: usize, replacement: bool) -> Fr {
    let opening = synthetic_opening(seed, index, replacement);
    state_leaf(
        owner(seed, index),
        replacement as u64,
        50 + replacement as u64,
        index as u32,
        &opening,
    )
}

// Exact extraction of plan_a_service_core::sparse_state_root for equivalence tests.
#[allow(dead_code)] // exercised by equivalence tests; production uses the original service core
fn sparse_state_root(depth: usize, records: &BTreeMap<u32, Fr>) -> Result<Fr, String> {
    if depth == 0 || depth > 32 {
        return Err("bad-state-depth".into());
    }
    let mut defaults = vec![Fr::from(0u64)];
    for i in 0..depth {
        defaults.push(node_hash(Domain::TreeNode, defaults[i], defaults[i]));
    }
    let mut level = records.clone();
    for d in 0..depth {
        let mut next = BTreeMap::new();
        for index in level
            .keys()
            .map(|x| x >> 1)
            .collect::<BTreeSet<_>>()
        {
            let left = *level.get(&(index * 2)).unwrap_or(&defaults[d]);
            let right = *level.get(&(index * 2 + 1)).unwrap_or(&defaults[d]);
            next.insert(index, node_hash(Domain::TreeNode, left, right));
        }
        level = next;
    }
    Ok(*level.get(&0).unwrap_or(&defaults[depth]))
}

fn generate(depth: usize, seed: u64, output: &Path) -> Result<(), String> {
    if !(1..=20).contains(&depth) {
        return Err("depth-out-of-adapter-range".into());
    }
    let population = 1usize << depth;
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let target = rng.gen_range(0..population);
    let unchanged = if target == 0 { 1 } else { 0 };
    let mut writer = BufWriter::new(File::create(output).map_err(|e| e.to_string())?);
    writeln!(writer, "{}", json!({
        "schema":"r6-population-v1", "depth":depth, "population":population,
        "seed":seed, "target":target, "unchanged":unchanged,
        "replacement_leaf":field_hex(generated_leaf(seed,target,true)),
        "owner":field_hex(owner(seed,target)), "old_version":0, "new_version":1,
        "old_epoch":50, "new_epoch":51, "expiry_cap":4_000_000_000u64,
        "admission_version":0, "unrelated_ra_population":0,
        "unrelated_revocation_population":0
    })).map_err(|e| e.to_string())?;
    for index in 0..population {
        writeln!(writer, "{}", json!({
            "position":index, "owner":field_hex(owner(seed,index)),
            "leaf":field_hex(generated_leaf(seed,index,false)),
            "state_version":0, "state_epoch":50
        })).map_err(|e| e.to_string())?;
    }
    writer.flush().map_err(|e| e.to_string())
}

fn dense_refresh(public_path: &Path, depth: usize, target: usize, unchanged: usize) -> Result<Value, String> {
    let started = Instant::now();
    let bytes = fs::read(public_path).map_err(|e| e.to_string())?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "bad-public-json")?;
    let rows = value.get("state").and_then(|v| v.get("leaves")).and_then(Value::as_array)
        .ok_or("bad-public-state")?;
    let capacity = 1usize.checked_shl(depth as u32).ok_or("bad-depth")?;
    let mut leaves = vec![Fr::from(0u64); capacity];
    let mut seen = vec![false; capacity];
    for row in rows {
        let position = row.get("position").and_then(Value::as_u64).ok_or("bad-position")? as usize;
        if position >= capacity || seen[position] { return Err("duplicate-or-out-of-range-position".into()); }
        seen[position] = true;
        leaves[position] = parse_field(row.get("leaf").and_then(Value::as_str).ok_or("bad-leaf")?)?;
    }
    if !seen.iter().all(|x| *x) { return Err("population-not-full".into()); }
    if target >= capacity || unchanged >= capacity || target == unchanged { return Err("bad-holder-index".into()); }
    let target_leaf = leaves[target];
    let unchanged_leaf = leaves[unchanged];
    let (root, levels) = build_tree(leaves, depth, Domain::TreeNode).map_err(str::to_string)?;
    let target_path = path_for(&levels, target).map_err(str::to_string)?;
    let unchanged_path = path_for(&levels, unchanged).map_err(str::to_string)?;
    if root_from_path(target_leaf, &target_path, Domain::TreeNode) != Some(root)
        || root_from_path(unchanged_leaf, &unchanged_path, Domain::TreeNode) != Some(root) {
        return Err("refreshed-path-invalid".into());
    }
    let expected = value.get("snapshot").and_then(|v| v.get("state_root")).and_then(Value::as_str)
        .ok_or("missing-state-root")?;
    if field_hex(root) != expected { return Err("dense-root-mismatch".into()); }
    let target_value = json!({"siblings":target_path.siblings.iter().copied().map(field_hex).collect::<Vec<_>>(),
        "directions":target_path.directions});
    let unchanged_value = json!({"siblings":unchanged_path.siblings.iter().copied().map(field_hex).collect::<Vec<_>>(),
        "directions":unchanged_path.directions});
    let paths = json!({"target":target_value,"unchanged":unchanged_value});
    Ok(json!({"valid":true,"state_root":field_hex(root),"public_file_bytes":bytes.len(),
        "path_encoding_bytes":{
            "target_json":serde_json::to_vec(&paths["target"]).map_err(|e|e.to_string())?.len(),
            "unchanged_json":serde_json::to_vec(&paths["unchanged"]).map_err(|e|e.to_string())?.len(),
            "two_path_object_json":serde_json::to_vec(&paths).map_err(|e|e.to_string())?.len()
        },
        "path_raw":{
            "target_sibling_bytes":target_path.siblings.len()*32,
            "unchanged_sibling_bytes":unchanged_path.siblings.len()*32,
            "two_path_sibling_bytes":(target_path.siblings.len()+unchanged_path.siblings.len())*32,
            "target_direction_count":target_path.directions.len(),
            "unchanged_direction_count":unchanged_path.directions.len(),
            "two_path_direction_count":target_path.directions.len()+unchanged_path.directions.len(),
            "target_directions_json_bytes":serde_json::to_vec(&target_path.directions).map_err(|e|e.to_string())?.len(),
            "unchanged_directions_json_bytes":serde_json::to_vec(&unchanged_path.directions).map_err(|e|e.to_string())?.len()
        },
        "holder_refresh_ns":started.elapsed().as_nanos()}))
}

fn registry_pk() -> Result<Value, String> {
    let pk = public_key(&SecretKey(Scalar::from(900u64))).map_err(|_| "registry-key")?;
    let mut bytes = Vec::new();
    pk.0.serialize_compressed(&mut bytes).map_err(|_| "registry-key-encode")?;
    Ok(json!({"registry_pk_b64":STANDARD.encode(bytes)}))
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let result = match args.get(1).map(String::as_str) {
        Some("generate") if args.len() == 5 => {
            let depth = args[2].parse::<usize>().map_err(|_| "bad-depth".to_string());
            let seed = args[3].parse::<u64>().map_err(|_| "bad-seed".to_string());
            depth.and_then(|d| seed.and_then(|s| generate(d, s, Path::new(&args[4])).map(|_| json!({"valid":true}))))
        }
        Some("dense-refresh") if args.len() == 6 => {
            let depth = args[3].parse::<usize>().map_err(|_| "bad-depth".to_string());
            let target = args[4].parse::<usize>().map_err(|_| "bad-target".to_string());
            let unchanged = args[5].parse::<usize>().map_err(|_| "bad-unchanged".to_string());
            depth.and_then(|d| target.and_then(|t| unchanged.and_then(|u| dense_refresh(Path::new(&args[2]), d, t, u))))
        }
        Some("registry-pk") if args.len() == 2 => registry_pk(),
        _ => Err("usage: r6-tree-adapter generate DEPTH SEED OUTPUT | dense-refresh PUBLIC DEPTH TARGET UNCHANGED | registry-pk".into()),
    };
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => { eprintln!("{error}"); std::process::exit(2); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracted_sparse_matches_dense_for_full_and_sparse_small_trees() {
        for depth in 2..=6 {
            let capacity = 1usize << depth;
            for full in [false, true] {
                let leaves = (0..capacity)
                    .map(|i| if full || i % 3 == 0 { Fr::from((i + 1) as u64) } else { Fr::from(0u64) })
                    .collect::<Vec<_>>();
                let records = leaves.iter().enumerate().filter(|(_,v)| **v != Fr::from(0u64))
                    .map(|(i,v)|(i as u32,*v)).collect::<BTreeMap<_,_>>();
                let dense = build_tree(leaves, depth, Domain::TreeNode).unwrap().0;
                assert_eq!(sparse_state_root(depth, &records).unwrap(), dense);
            }
        }
    }

    #[test]
    fn replacement_changes_root_and_both_paths_verify() {
        let depth = 4;
        let seed = 77;
        let mut leaves = (0..1usize<<depth).map(|i| generated_leaf(seed,i,false)).collect::<Vec<_>>();
        let old_root = build_tree(leaves.clone(),depth,Domain::TreeNode).unwrap().0;
        leaves[7] = generated_leaf(seed,7,true);
        let (new_root,levels) = build_tree(leaves.clone(),depth,Domain::TreeNode).unwrap();
        assert_ne!(old_root,new_root);
        for i in [7usize,2usize] {
            let path=path_for(&levels,i).unwrap();
            assert_eq!(root_from_path(leaves[i],&path,Domain::TreeNode),Some(new_root));
        }
    }

    #[test]
    fn serialized_path_accounting_is_unambiguous() {
        let depth = 3;
        let leaves = (0..1usize << depth).map(|i| Fr::from((i + 1) as u64)).collect::<Vec<_>>();
        let (_, levels) = build_tree(leaves, depth, Domain::TreeNode).unwrap();
        let path = path_for(&levels, 2).unwrap();
        assert_eq!(path.siblings.len() * 32, depth * 32);
        assert_eq!(path.directions.len(), depth);
        assert!(serde_json::to_vec(&path.directions).unwrap().len() >= depth + 2);
    }
}
