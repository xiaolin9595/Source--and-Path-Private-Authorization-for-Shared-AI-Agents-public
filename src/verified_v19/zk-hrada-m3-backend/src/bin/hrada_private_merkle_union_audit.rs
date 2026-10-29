//! Synthesis-only comparison of three independent depth-3 Blake2s paths with
//! a fixed-shape 3/2/1-row private union. This binary performs no setup/proof.
use ark_bls12_381::Fr;
use ark_crypto_primitives::prf::blake2s::constraints::evaluate_blake2s;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
};
use blake2::{Blake2s, Digest};
use serde::Serialize;
use serde_json::json;
use std::{env, fs, path::PathBuf, time::Instant};

type Hash = [u8; 32];
const DEPTH: usize = 3;
const QUERIES: usize = 3;
const NODE_DOMAIN: u8 = 7;

fn hash(domain: u8, data: &[u8]) -> Hash {
    let mut input = vec![domain];
    input.extend_from_slice(data);
    let digest = Blake2s::digest(&input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    hash(NODE_DOMAIN, &[left.as_ref(), right.as_ref()].concat())
}

fn node_hash_var(
    left: &[UInt8<Fr>],
    right: &[UInt8<Fr>],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut input = vec![UInt8::constant(NODE_DOMAIN)];
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    let bits = input
        .iter()
        .map(|byte| byte.to_bits_le())
        .collect::<Result<Vec<_>, _>>()?
        .concat();
    Ok(evaluate_blake2s(&bits)?
        .iter()
        .flat_map(|word| word.to_bytes().unwrap())
        .collect())
}

fn limbs(value: Hash) -> [Fr; 2] {
    [
        Fr::from_le_bytes_mod_order(&value[..16]),
        Fr::from_le_bytes_mod_order(&value[16..]),
    ]
}

fn enforce_root(bytes: &[UInt8<Fr>], public: &[FpVar<Fr>]) -> Result<(), SynthesisError> {
    for (part, expected) in bytes.chunks(16).zip(public) {
        let bits = part
            .iter()
            .map(|byte| byte.to_bits_le())
            .collect::<Result<Vec<_>, _>>()?
            .concat();
        Boolean::le_bits_to_fp_var(&bits)?.enforce_equal(expected)?;
    }
    Ok(())
}

#[derive(Clone)]
struct Tree {
    levels: Vec<Vec<Hash>>,
}

impl Tree {
    fn deterministic() -> Self {
        let leaves = (0u8..8)
            .map(|index| hash(0xa5, &[index]))
            .collect::<Vec<_>>();
        let mut levels = vec![leaves];
        for level in 0..DEPTH {
            levels.push(
                levels[level]
                    .chunks(2)
                    .map(|pair| node_hash(&pair[0], &pair[1]))
                    .collect(),
            );
        }
        Self { levels }
    }

    fn root(&self) -> Hash {
        self.levels[DEPTH][0]
    }

    fn path(&self, index: usize) -> [Hash; DEPTH] {
        [
            self.levels[0][index ^ 1],
            self.levels[1][(index >> 1) ^ 1],
            self.levels[2][(index >> 2) ^ 1],
        ]
    }
}

#[derive(Clone)]
struct Query {
    leaf: Hash,
    index: usize,
    enabled: bool,
}

fn alloc_common(
    cs: ConstraintSystemRef<Fr>,
    queries: &[Query; QUERIES],
    root: Hash,
) -> Result<
    (
        Vec<Boolean<Fr>>,
        Vec<Vec<Boolean<Fr>>>,
        Vec<Vec<UInt8<Fr>>>,
        Vec<FpVar<Fr>>,
        Vec<UInt8<Fr>>,
    ),
    SynthesisError,
> {
    let public_root = limbs(root)
        .iter()
        .map(|limb| FpVar::new_input(cs.clone(), || Ok(*limb)))
        .collect::<Result<Vec<_>, _>>()?;
    let root_bytes = UInt8::new_witness_vec(cs.clone(), &root)?;
    enforce_root(&root_bytes, &public_root)?;
    let enabled = queries
        .iter()
        .map(|query| Boolean::new_witness(cs.clone(), || Ok(query.enabled)))
        .collect::<Result<Vec<_>, _>>()?;
    enabled[0].enforce_equal(&Boolean::TRUE)?;
    for slot in 1..QUERIES {
        enabled[slot]
            .and(&enabled[slot - 1].not())?
            .enforce_equal(&Boolean::FALSE)?;
    }
    let mut indexes = Vec::new();
    let mut leaves = Vec::new();
    for (slot, query) in queries.iter().enumerate() {
        let index_value = FpVar::new_witness(cs.clone(), || Ok(Fr::from(query.index as u64)))?;
        let bits = (0..DEPTH)
            .map(|bit| Boolean::new_witness(cs.clone(), || Ok(((query.index >> bit) & 1) == 1)))
            .collect::<Result<Vec<_>, _>>()?;
        index_value.enforce_equal(&Boolean::le_bits_to_fp_var(&bits)?)?;
        let disabled = enabled[slot].not();
        for bit in &bits {
            bit.conditional_enforce_equal(&Boolean::FALSE, &disabled)?;
        }
        indexes.push(bits);
        // Original Auth does not require a disabled leaf digest to be zero.
        leaves.push(UInt8::new_witness_vec(cs.clone(), &query.leaf)?);
    }
    Ok((enabled, indexes, leaves, public_root, root_bytes))
}

#[derive(Clone)]
struct BaselineCircuit {
    queries: [Query; QUERIES],
    paths: [[Hash; DEPTH]; QUERIES],
    root: Hash,
}

impl ConstraintSynthesizer<Fr> for BaselineCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let (enabled, indexes, leaves, _public_root, root_bytes) =
            alloc_common(cs.clone(), &self.queries, self.root)?;
        for slot in 0..QUERIES {
            let disabled = enabled[slot].not();
            let mut current = leaves[slot].clone();
            for level in 0..DEPTH {
                let sibling = UInt8::new_witness_vec(cs.clone(), &self.paths[slot][level])?;
                for byte in &sibling {
                    byte.conditional_enforce_equal(&UInt8::constant(0), &disabled)?;
                }
                let mut left = Vec::with_capacity(32);
                let mut right = Vec::with_capacity(32);
                for byte in 0..32 {
                    left.push(UInt8::conditionally_select(
                        &indexes[slot][level],
                        &sibling[byte],
                        &current[byte],
                    )?);
                    right.push(UInt8::conditionally_select(
                        &indexes[slot][level],
                        &current[byte],
                        &sibling[byte],
                    )?);
                }
                current = node_hash_var(&left, &right)?;
            }
            let computed = current;
            for byte in 0..32 {
                computed[byte].conditional_enforce_equal(&root_bytes[byte], &enabled[slot])?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
struct RowWitness {
    active: bool,
    address: usize,
    left: Hash,
    right: Hash,
}

#[derive(Clone)]
struct UnionWitness {
    level0: [RowWitness; 3],
    level1: [RowWitness; 2],
    level2: [RowWitness; 1],
    query_routes: [[bool; 3]; 3],
    level0_routes: [[bool; 2]; 3],
    level1_routes: [[bool; 1]; 2],
}

#[derive(Clone)]
struct UnionCircuit {
    queries: [Query; QUERIES],
    root: Hash,
    witness: UnionWitness,
}

struct RowVar {
    active: Boolean<Fr>,
    address: Vec<Boolean<Fr>>,
    left: Vec<UInt8<Fr>>,
    right: Vec<UInt8<Fr>>,
    parent: Vec<UInt8<Fr>>,
}

fn alloc_rows(
    cs: ConstraintSystemRef<Fr>,
    witnesses: &[RowWitness],
    address_bits: usize,
) -> Result<Vec<RowVar>, SynthesisError> {
    let mut rows = Vec::new();
    for witness in witnesses {
        let active = Boolean::new_witness(cs.clone(), || Ok(witness.active))?;
        let address_value =
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(witness.address as u64)))?;
        let address = (0..address_bits)
            .map(|bit| Boolean::new_witness(cs.clone(), || Ok(((witness.address >> bit) & 1) == 1)))
            .collect::<Result<Vec<_>, _>>()?;
        address_value.enforce_equal(&Boolean::le_bits_to_fp_var(&address)?)?;
        let left = UInt8::new_witness_vec(cs.clone(), &witness.left)?;
        let right = UInt8::new_witness_vec(cs.clone(), &witness.right)?;
        let inactive = active.not();
        for bit in &address {
            bit.conditional_enforce_equal(&Boolean::FALSE, &inactive)?;
        }
        for byte in left.iter().chain(right.iter()) {
            byte.conditional_enforce_equal(&UInt8::constant(0), &inactive)?;
        }
        let parent = node_hash_var(&left, &right)?;
        rows.push(RowVar {
            active,
            address,
            left,
            right,
            parent,
        });
    }
    // Active rows have unique addresses. Inactive rows are already canonical.
    for first in 0..rows.len() {
        for second in (first + 1)..rows.len() {
            let both = rows[first].active.and(&rows[second].active)?;
            let mut equal = Boolean::TRUE;
            for bit in 0..address_bits {
                equal = equal.and(
                    &rows[first].address[bit]
                        .xor(&rows[second].address[bit])?
                        .not(),
                )?;
            }
            both.and(&equal)?.enforce_equal(&Boolean::FALSE)?;
        }
    }
    Ok(rows)
}

fn bool_sum_equals(bits: &[Boolean<Fr>], expected: &Boolean<Fr>) -> Result<(), SynthesisError> {
    let mut sum = FpVar::zero();
    for bit in bits {
        sum += Boolean::le_bits_to_fp_var(&[bit.clone()])?;
    }
    sum.enforce_equal(&Boolean::le_bits_to_fp_var(&[expected.clone()])?)
}

fn enforce_query_routes(
    cs: ConstraintSystemRef<Fr>,
    routes: &[[bool; 3]; 3],
    enabled: &[Boolean<Fr>],
    indexes: &[Vec<Boolean<Fr>>],
    leaves: &[Vec<UInt8<Fr>>],
    parents: &[RowVar],
) -> Result<(), SynthesisError> {
    let mut selectors = Vec::new();
    for query in 0..3 {
        let row = routes[query]
            .iter()
            .map(|value| Boolean::new_witness(cs.clone(), || Ok(*value)))
            .collect::<Result<Vec<_>, _>>()?;
        bool_sum_equals(&row, &enabled[query])?;
        for parent in 0..3 {
            parents[parent]
                .active
                .conditional_enforce_equal(&Boolean::TRUE, &row[parent])?;
            for bit in 0..2 {
                parents[parent].address[bit]
                    .conditional_enforce_equal(&indexes[query][bit + 1], &row[parent])?;
            }
            for byte in 0..32 {
                let child = UInt8::conditionally_select(
                    &indexes[query][0],
                    &parents[parent].right[byte],
                    &parents[parent].left[byte],
                )?;
                child.conditional_enforce_equal(&leaves[query][byte], &row[parent])?;
            }
        }
        selectors.push(row);
    }
    for parent in 0..3 {
        let mut covered = Boolean::FALSE;
        for query in 0..3 {
            covered = covered.or(&selectors[query][parent])?;
        }
        parents[parent].active.enforce_equal(&covered)?;
    }
    Ok(())
}

fn enforce_row_routes<const CHILDREN: usize, const PARENTS: usize>(
    cs: ConstraintSystemRef<Fr>,
    route_values: &[[bool; PARENTS]; CHILDREN],
    children: &[RowVar],
    parents: &[RowVar],
) -> Result<(), SynthesisError> {
    let mut selectors = Vec::new();
    for child in 0..CHILDREN {
        let route = route_values[child]
            .iter()
            .map(|value| Boolean::new_witness(cs.clone(), || Ok(*value)))
            .collect::<Result<Vec<_>, _>>()?;
        bool_sum_equals(&route, &children[child].active)?;
        for parent in 0..PARENTS {
            parents[parent]
                .active
                .conditional_enforce_equal(&Boolean::TRUE, &route[parent])?;
            for bit in 1..children[child].address.len() {
                parents[parent].address[bit - 1]
                    .conditional_enforce_equal(&children[child].address[bit], &route[parent])?;
            }
            for byte in 0..32 {
                let selected = UInt8::conditionally_select(
                    &children[child].address[0],
                    &parents[parent].right[byte],
                    &parents[parent].left[byte],
                )?;
                selected
                    .conditional_enforce_equal(&children[child].parent[byte], &route[parent])?;
            }
        }
        selectors.push(route);
    }
    for parent in 0..PARENTS {
        let mut covered = Boolean::FALSE;
        for child in 0..CHILDREN {
            covered = covered.or(&selectors[child][parent])?;
        }
        parents[parent].active.enforce_equal(&covered)?;
    }
    Ok(())
}

impl ConstraintSynthesizer<Fr> for UnionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let (enabled, indexes, leaves, _public_root, root_bytes) =
            alloc_common(cs.clone(), &self.queries, self.root)?;
        let level0 = alloc_rows(cs.clone(), &self.witness.level0, 2)?;
        let level1 = alloc_rows(cs.clone(), &self.witness.level1, 1)?;
        let level2 = alloc_rows(cs.clone(), &self.witness.level2, 0)?;
        enforce_query_routes(
            cs.clone(),
            &self.witness.query_routes,
            &enabled,
            &indexes,
            &leaves,
            &level0,
        )?;
        enforce_row_routes::<3, 2>(cs.clone(), &self.witness.level0_routes, &level0, &level1)?;
        enforce_row_routes::<2, 1>(cs, &self.witness.level1_routes, &level1, &level2)?;
        level2[0].active.enforce_equal(&Boolean::TRUE)?;
        for byte in 0..32 {
            level2[0].parent[byte].enforce_equal(&root_bytes[byte])?;
        }
        Ok(())
    }
}

fn sorted_unique(mut values: Vec<usize>) -> Vec<usize> {
    values.sort_unstable();
    values.dedup();
    values
}

fn row(level: &[Hash], address: usize) -> RowWitness {
    RowWitness {
        active: true,
        address,
        left: level[2 * address],
        right: level[2 * address + 1],
    }
}

fn union_witness(tree: &Tree, queries: &[Query; 3]) -> UnionWitness {
    let level0_addresses = sorted_unique(
        queries
            .iter()
            .filter(|query| query.enabled)
            .map(|query| query.index >> 1)
            .collect(),
    );
    let level1_addresses = sorted_unique(
        level0_addresses
            .iter()
            .map(|address| address >> 1)
            .collect(),
    );
    let mut level0: [RowWitness; 3] = Default::default();
    let mut level1: [RowWitness; 2] = Default::default();
    let mut level2: [RowWitness; 1] = Default::default();
    for (slot, address) in level0_addresses.iter().enumerate() {
        level0[slot] = row(&tree.levels[0], *address);
    }
    for (slot, address) in level1_addresses.iter().enumerate() {
        level1[slot] = row(&tree.levels[1], *address);
    }
    level2[0] = row(&tree.levels[2], 0);
    let mut query_routes = [[false; 3]; 3];
    for (query_index, query) in queries.iter().enumerate() {
        if query.enabled {
            let target = level0_addresses
                .iter()
                .position(|address| *address == query.index >> 1)
                .unwrap();
            query_routes[query_index][target] = true;
        }
    }
    let mut level0_routes = [[false; 2]; 3];
    for child in 0..level0_addresses.len() {
        let target = level1_addresses
            .iter()
            .position(|address| *address == level0_addresses[child] >> 1)
            .unwrap();
        level0_routes[child][target] = true;
    }
    let mut level1_routes = [[false; 1]; 2];
    for child in 0..level1_addresses.len() {
        level1_routes[child][0] = true;
    }
    UnionWitness {
        level0,
        level1,
        level2,
        query_routes,
        level0_routes,
        level1_routes,
    }
}

fn circuits(tree: &Tree, indices: [usize; 3], prefix: usize) -> (BaselineCircuit, UnionCircuit) {
    let queries = [0, 1, 2].map(|slot| Query {
        // Keep a nonzero, ordinary digest even for disabled slots.
        leaf: tree.levels[0][indices[slot]],
        index: if slot < prefix { indices[slot] } else { 0 },
        enabled: slot < prefix,
    });
    let paths = [0, 1, 2].map(|slot| {
        if slot < prefix {
            tree.path(indices[slot])
        } else {
            [[0u8; 32]; DEPTH]
        }
    });
    let baseline = BaselineCircuit {
        queries: queries.clone(),
        paths,
        root: tree.root(),
    };
    let union = UnionCircuit {
        queries: queries.clone(),
        root: tree.root(),
        witness: union_witness(tree, &queries),
    };
    (baseline, union)
}

fn native_verify_union(circuit: &UnionCircuit) -> bool {
    let w = &circuit.witness;
    if !circuit.queries[0].enabled
        || circuit.queries[1].enabled && !circuit.queries[0].enabled
        || circuit.queries[2].enabled && !circuit.queries[1].enabled
    {
        return false;
    }
    for query in &circuit.queries {
        if query.index >= 8 || (!query.enabled && query.index != 0) {
            return false;
        }
    }
    for (rows, address_limit) in [
        (&w.level0[..], 4usize),
        (&w.level1[..], 2usize),
        (&w.level2[..], 1usize),
    ] {
        let mut seen = Vec::new();
        for row in rows {
            if row.active {
                if row.address >= address_limit || seen.contains(&row.address) {
                    return false;
                }
                seen.push(row.address);
            } else if row.address != 0 || row.left != [0u8; 32] || row.right != [0u8; 32] {
                return false;
            }
        }
    }
    for query in 0..3 {
        let selected = w.query_routes[query].iter().filter(|value| **value).count();
        if selected != usize::from(circuit.queries[query].enabled) {
            return false;
        }
        for parent in 0..3 {
            if w.query_routes[query][parent]
                && (!w.level0[parent].active
                    || w.level0[parent].address != circuit.queries[query].index >> 1
                    || if circuit.queries[query].index & 1 == 0 {
                        w.level0[parent].left != circuit.queries[query].leaf
                    } else {
                        w.level0[parent].right != circuit.queries[query].leaf
                    })
            {
                return false;
            }
        }
    }
    for parent in 0..3 {
        if w.level0[parent].active != (0..3).any(|query| w.query_routes[query][parent]) {
            return false;
        }
    }
    for child in 0..3 {
        let selected = w.level0_routes[child]
            .iter()
            .filter(|value| **value)
            .count();
        if selected != usize::from(w.level0[child].active) {
            return false;
        }
        for parent in 0..2 {
            if w.level0_routes[child][parent]
                && (!w.level1[parent].active
                    || w.level1[parent].address != w.level0[child].address >> 1
                    || if w.level0[child].address & 1 == 0 {
                        w.level1[parent].left
                            != node_hash(&w.level0[child].left, &w.level0[child].right)
                    } else {
                        w.level1[parent].right
                            != node_hash(&w.level0[child].left, &w.level0[child].right)
                    })
            {
                return false;
            }
        }
    }
    for parent in 0..2 {
        if w.level1[parent].active != (0..3).any(|child| w.level0_routes[child][parent]) {
            return false;
        }
    }
    for child in 0..2 {
        let selected = usize::from(w.level1_routes[child][0]);
        if selected != usize::from(w.level1[child].active) {
            return false;
        }
        if w.level1_routes[child][0]
            && (!w.level2[0].active
                || if w.level1[child].address & 1 == 0 {
                    w.level2[0].left != node_hash(&w.level1[child].left, &w.level1[child].right)
                } else {
                    w.level2[0].right != node_hash(&w.level1[child].left, &w.level1[child].right)
                })
        {
            return false;
        }
    }
    w.level2[0].active
        && (0..2).any(|child| w.level1_routes[child][0])
        && node_hash(&w.level2[0].left, &w.level2[0].right) == circuit.root
}

#[derive(Clone, Debug, Serialize, PartialEq)]
struct Counts {
    constraints: usize,
    instance_variables: usize,
    witness_variables: usize,
}

#[derive(Clone, Debug, Serialize)]
struct Run {
    relation: String,
    case: String,
    expected_satisfied: bool,
    satisfied_pre_finalize: bool,
    satisfied_post_finalize: bool,
    pre_finalize: Counts,
    post_finalize: Counts,
}

fn counts(cs: &ConstraintSystemRef<Fr>) -> Counts {
    Counts {
        constraints: cs.num_constraints(),
        instance_variables: cs.num_instance_variables(),
        witness_variables: cs.num_witness_variables(),
    }
}

fn synthesize<C: ConstraintSynthesizer<Fr>>(
    relation: &str,
    case: &str,
    circuit: C,
    expected: bool,
) -> Run {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit.generate_constraints(cs.clone()).unwrap();
    let pre_finalize = counts(&cs);
    let satisfied_pre_finalize = cs.is_satisfied().unwrap();
    cs.finalize();
    let post_finalize = counts(&cs);
    let satisfied_post_finalize = cs.is_satisfied().unwrap();
    assert_eq!(
        satisfied_pre_finalize, expected,
        "unexpected pre-finalize result: {}",
        case
    );
    assert_eq!(
        satisfied_post_finalize, expected,
        "unexpected post-finalize result: {}",
        case
    );
    Run {
        relation: relation.to_owned(),
        case: case.to_owned(),
        expected_satisfied: expected,
        satisfied_pre_finalize,
        satisfied_post_finalize,
        pre_finalize,
        post_finalize,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn main() {
    let started = Instant::now();
    let output = PathBuf::from(env::args().nth(1).unwrap_or_else(|| {
        "../paper/pets_2027_english/work/joint_auth_cost_design_2026-10-18/private_merkle_union_audit".to_owned()
    }));
    fs::create_dir_all(&output).unwrap();
    let tree = Tree::deterministic();

    let mut host_cases = 0usize;
    for prefix in 1..=3 {
        for first in 0..8 {
            for second in 0..8 {
                for third in 0..8 {
                    let (_, union) = circuits(&tree, [first, second, third], prefix);
                    assert!(native_verify_union(&union));
                    host_cases += 1;
                }
            }
        }
    }
    assert_eq!(host_cases, 3 * 8 * 8 * 8);

    let valid_specs = [
        ("shared_high", [0, 1, 2], 3usize),
        ("dispersed", [0, 2, 4], 3usize),
        ("short_prefix", [0, 2, 7], 2usize),
        ("single_prefix", [5, 6, 7], 1usize),
        ("duplicate_index", [3, 3, 3], 3usize),
    ];
    let mut runs = Vec::new();
    for (name, indices, prefix) in valid_specs {
        let (baseline, union) = circuits(&tree, indices, prefix);
        assert!(native_verify_union(&union));
        runs.push(synthesize("baseline_3x3", name, baseline, true));
        runs.push(synthesize("union_3_2_1", name, union, true));
    }

    let (baseline, union) = circuits(&tree, [0, 1, 2], 3);
    let mut bad = baseline.clone();
    bad.root[0] ^= 1;
    runs.push(synthesize("baseline_3x3", "wrong_root", bad, false));
    let mut bad = baseline;
    bad.queries[1].index = 3;
    runs.push(synthesize("baseline_3x3", "wrong_index", bad, false));
    let (mut bad, _) = circuits(&tree, [0, 1, 2], 3);
    bad.queries[1].index = 8;
    runs.push(synthesize("baseline_3x3", "index_out_of_range", bad, false));
    let (mut bad, _) = circuits(&tree, [3, 3, 3], 3);
    bad.queries[1].leaf[0] ^= 1;
    runs.push(synthesize(
        "baseline_3x3",
        "duplicate_index_conflicting_leaf",
        bad,
        false,
    ));

    let mut bad = union.clone();
    bad.root[0] ^= 1;
    runs.push(synthesize("union_3_2_1", "wrong_root", bad, false));
    let mut bad = union.clone();
    bad.queries[1].index = 3;
    runs.push(synthesize("union_3_2_1", "wrong_index", bad, false));
    let mut bad = union.clone();
    bad.queries[1].index = 8;
    runs.push(synthesize("union_3_2_1", "index_out_of_range", bad, false));
    let mut bad = union.clone();
    bad.witness.level0[0].address = 4;
    runs.push(synthesize(
        "union_3_2_1",
        "row_address_out_of_range",
        bad,
        false,
    ));
    let (_, mut bad) = circuits(&tree, [3, 3, 3], 3);
    bad.queries[1].leaf[0] ^= 1;
    runs.push(synthesize(
        "union_3_2_1",
        "duplicate_index_conflicting_leaf",
        bad,
        false,
    ));
    let mut bad = union.clone();
    bad.witness.query_routes[1] = [false; 3];
    runs.push(synthesize(
        "union_3_2_1",
        "missing_enabled_leaf_route",
        bad,
        false,
    ));
    let mut bad = union.clone();
    bad.witness.level0_routes[0] = [false; 2];
    runs.push(synthesize(
        "union_3_2_1",
        "missing_intermediate_route",
        bad,
        false,
    ));
    let mut bad = union.clone();
    bad.witness.level0[0].left[0] ^= 1;
    runs.push(synthesize(
        "union_3_2_1",
        "swapped_or_wrong_child",
        bad,
        false,
    ));
    let mut bad = union;
    bad.queries[1].enabled = false;
    bad.queries[2].enabled = true;
    runs.push(synthesize("union_3_2_1", "non_prefix_enabled", bad, false));

    let baseline_counts = runs
        .iter()
        .find(|run| run.relation == "baseline_3x3" && run.expected_satisfied)
        .unwrap()
        .post_finalize
        .clone();
    let union_counts = runs
        .iter()
        .find(|run| run.relation == "union_3_2_1" && run.expected_satisfied)
        .unwrap()
        .post_finalize
        .clone();
    for run in &runs {
        let expected = if run.relation == "baseline_3x3" {
            &baseline_counts
        } else {
            &union_counts
        };
        assert_eq!(
            &run.post_finalize, expected,
            "shape changed for {}",
            run.case
        );
    }

    let source = include_bytes!("hrada_private_merkle_union_audit.rs");
    let source_hash = Blake2s::digest(source);
    let lock_hash = Blake2s::digest(include_bytes!("../../Cargo.lock"));
    let hash_vector = node_hash(&tree.levels[0][0], &tree.levels[0][1]);
    let decision = if union_counts.constraints < baseline_counts.constraints {
        "retain"
    } else {
        "reject"
    };
    let elapsed = started.elapsed().as_secs_f64();
    let document = json!({
        "schema": "hrada-private-merkle-union-audit-v1",
        "scope": "synthesis only; no setup, proof, verification, or full Auth integration",
        "command": "cargo run --release --locked --bin hrada_private_merkle_union_audit -- ../paper/pets_2027_english/work/joint_auth_cost_design_2026-10-18/private_merkle_union_audit",
        "optimization_goal": "Constraints; post-finalize C/I/W is the comparison metric",
        "program_wall_seconds": elapsed,
        "host_exhaustive_cases": host_cases,
        "fixed_hash_calls": {"baseline": 9, "union": 6},
        "encoding": "Blake2s(0x07 || left[32] || right[32]); identical shared native and gadget functions",
        "hash_vector_hex": hex(&hash_vector),
        "root_hex": hex(&tree.root()),
        "source_blake2s": hex(&source_hash),
        "cargo_lock_blake2s": hex(&lock_hash),
        "baseline_post_finalize": baseline_counts,
        "union_post_finalize": union_counts,
        "constraint_delta_union_minus_baseline": union_counts.constraints as i64 - baseline_counts.constraints as i64,
        "decision": decision,
        "runs": runs,
        "notes": [
            "All listed valid and invalid cases have identical C/I/W within each relation; fixed loops and capacities provide the shape argument, not a matrix-digest comparison or exhaustive adversarial enumeration.",
            "Disabled query index and baseline siblings are canonical zero; disabled leaf digest is intentionally not forced to zero, matching the original Auth path boundary.",
            "Duplicate query indices are accepted when their leaf digests agree and rejected when they conflict.",
            "This module delta is not a full-Auth constraint or timing result."
        ]
    });
    fs::write(
        output.join("RESULTS.json"),
        serde_json::to_vec_pretty(&document).unwrap(),
    )
    .unwrap();
    let report = format!(
        "# Fixed-shape private Merkle union audit\n\n\
Scope: synthesis only; no setup, proof, verification, or full Auth integration.\n\n\
- Command: `cargo run --release --locked --bin hrada_private_merkle_union_audit -- ../paper/pets_2027_english/work/joint_auth_cost_design_2026-10-18/private_merkle_union_audit`\n\
- Program wall time: {:.6} s (excludes Cargo compilation)\n\
- Source Blake2s: `{}`\n\
- Cargo.lock Blake2s: `{}`\n\
- Encoding: `Blake2s(0x07 || left[32] || right[32])` in both relations\n\
- Host exhaustive checks: {} (= 8^3 tuples x 3 prefix lengths)\n\
- Baseline post-finalize C/I/W: {}/{}/{}\n\
- Union post-finalize C/I/W: {}/{}/{}\n\
- Union minus baseline constraints: {}\n\
- Decision: **{}**\n\n\
All listed valid and adversarial cases had identical C/I/W within each relation; fixed loops and capacities provide the shape argument (this is not a matrix-digest comparison or exhaustive adversarial enumeration). Disabled indexes and baseline siblings are zero; disabled leaf digests remain ordinary unconstrained inputs, as in the original Auth path boundary. Duplicate indexes with the same leaf are accepted, while a conflicting leaf at the same index is rejected. The union enforces exact-one parent routing for every active child, source coverage for every active parent, address/side consistency, unique active addresses per layer, canonical inactive rows, and public-root binding.\n\n\
This isolated module result must not be reported as a full-Auth constraint delta or timing result. See `RESULTS.json` for pre/post-finalize counts and every case.\n",
        elapsed,
        hex(&source_hash),
        hex(&lock_hash),
        host_cases,
        document["baseline_post_finalize"]["constraints"],
        document["baseline_post_finalize"]["instance_variables"],
        document["baseline_post_finalize"]["witness_variables"],
        document["union_post_finalize"]["constraints"],
        document["union_post_finalize"]["instance_variables"],
        document["union_post_finalize"]["witness_variables"],
        document["constraint_delta_union_minus_baseline"],
        decision,
    );
    fs::write(output.join("REPORT.md"), report).unwrap();
    println!("{}", serde_json::to_string_pretty(&document).unwrap());
}
