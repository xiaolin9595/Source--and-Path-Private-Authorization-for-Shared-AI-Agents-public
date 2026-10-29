use crate::poseidon::{hash, hash_var, Domain};
use ark_bls12_381::Fr;
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub siblings: Vec<Fr>,
    pub directions: Vec<bool>,
}

pub fn leaf_hash(domain: Domain, fields: &[Fr]) -> Fr {
    hash(domain, fields)
}
pub fn node_hash(domain: Domain, left: Fr, right: Fr) -> Fr {
    hash(domain, &[left, right])
}

pub fn root_from_path(leaf: Fr, path: &MerklePath, node_domain: Domain) -> Option<Fr> {
    if path.siblings.len() != path.directions.len() {
        return None;
    }
    Some(
        path.siblings
            .iter()
            .zip(&path.directions)
            .fold(leaf, |cur, (sib, right)| {
                if *right {
                    node_hash(node_domain, *sib, cur)
                } else {
                    node_hash(node_domain, cur, *sib)
                }
            }),
    )
}

pub fn enforce_path(
    cs: ConstraintSystemRef<Fr>,
    leaf: FpVar<Fr>,
    path: &MerklePath,
    expected_root: &FpVar<Fr>,
    node_domain: Domain,
) -> Result<(), SynthesisError> {
    if path.siblings.len() != path.directions.len() {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut cur = leaf;
    for (sibling, direction) in path.siblings.iter().zip(&path.directions) {
        let sib = FpVar::new_witness(cs.clone(), || Ok(*sibling))?;
        let dir = Boolean::new_witness(cs.clone(), || Ok(*direction))?;
        let left = FpVar::conditionally_select(&dir, &sib, &cur)?;
        let right = FpVar::conditionally_select(&dir, &cur, &sib)?;
        cur = hash_var(node_domain, &[left, right])?;
    }
    cur.enforce_equal(expected_root)
}

pub fn path_root_var(
    cs: ConstraintSystemRef<Fr>,
    leaf: FpVar<Fr>,
    path: &MerklePath,
    node_domain: Domain,
) -> Result<FpVar<Fr>, SynthesisError> {
    if path.siblings.len() != path.directions.len() {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut cur = leaf;
    for (sibling, direction) in path.siblings.iter().zip(&path.directions) {
        let sib = FpVar::new_witness(cs.clone(), || Ok(*sibling))?;
        let dir = Boolean::new_witness(cs.clone(), || Ok(*direction))?;
        let left = FpVar::conditionally_select(&dir, &sib, &cur)?;
        let right = FpVar::conditionally_select(&dir, &cur, &sib)?;
        cur = hash_var(node_domain, &[left, right])?;
    }
    Ok(cur)
}

pub fn build_tree(
    mut leaves: Vec<Fr>,
    depth: usize,
    node_domain: Domain,
) -> Result<(Fr, Vec<Vec<Fr>>), &'static str> {
    if depth >= usize::BITS as usize || leaves.len() > (1usize << depth) {
        return Err("invalid depth/capacity");
    }
    leaves.resize(1usize << depth, Fr::from(0u64));
    let mut levels = vec![leaves];
    for _ in 0..depth {
        let next = levels
            .last()
            .unwrap()
            .chunks_exact(2)
            .map(|x| node_hash(node_domain, x[0], x[1]))
            .collect();
        levels.push(next);
    }
    Ok((levels[depth][0], levels))
}

pub fn path_for(levels: &[Vec<Fr>], mut index: usize) -> Result<MerklePath, &'static str> {
    if levels.is_empty() || index >= levels[0].len() {
        return Err("invalid tree/index");
    }
    let mut siblings = Vec::new();
    let mut directions = Vec::new();
    for level in &levels[..levels.len() - 1] {
        directions.push(index & 1 == 1);
        siblings.push(level[index ^ 1]);
        index >>= 1;
    }
    Ok(MerklePath {
        siblings,
        directions,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    #[test]
    fn native_and_circuit_path_match() {
        let leaves = (0..8)
            .map(|i| leaf_hash(Domain::RaLeaf, &[Fr::from(i)]))
            .collect();
        let (root, levels) = build_tree(leaves, 3, Domain::TreeNode).unwrap();
        let p = path_for(&levels, 5).unwrap();
        let leaf = levels[0][5];
        assert_eq!(root_from_path(leaf, &p, Domain::TreeNode), Some(root));
        let cs = ConstraintSystem::new_ref();
        let lv = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
        let rv = FpVar::new_input(cs.clone(), || Ok(root)).unwrap();
        enforce_path(cs.clone(), lv, &p, &rv, Domain::TreeNode).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
