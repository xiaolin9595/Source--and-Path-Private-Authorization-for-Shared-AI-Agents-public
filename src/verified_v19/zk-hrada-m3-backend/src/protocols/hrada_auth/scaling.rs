//! Experiment-only full authorization relation with configurable chain slots
//! and private Merkle-tree depth. The deployed [`super::AuthCircuit`] remains
//! the canonical fixed-three-slot, depth-three relation.

use super::*;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystem, OptimizationGoal};

pub const SCALING_SLOTS: [usize; 3] = [1, 3, 5];
pub const SCALING_TREE_DEPTHS: [usize; 2] = [3, 5];

/// Full-active experimental Auth relation. Only the fixed-capacity shape is
/// generalized; field order, hash domains, signature checks and request hash
/// are copied from the canonical relation in the same synthesis order.
#[derive(Clone)]
pub struct ScalingAuthCircuit {
    pub base: AuthCircuit,
    pub enabled: Vec<bool>,
    pub slot_capacity: usize,
    pub tree_depth: usize,
}

impl ScalingAuthCircuit {
    pub fn from_canonical(base: AuthCircuit) -> Self {
        Self {
            enabled: base.enabled.to_vec(),
            base,
            slot_capacity: 3,
            tree_depth: TREE_DEPTH,
        }
    }

    pub fn public_fields(&self) -> Vec<Fr> {
        self.base.public_fields()
    }
}

impl ConstraintSynthesizer<Fr> for ScalingAuthCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if self.slot_capacity == 0
            || self.slot_capacity > 15
            || self.tree_depth == 0
            || self.tree_depth > 63
            || self.enabled.len() != self.slot_capacity
            || self.base.grants.len() != self.slot_capacity
            || self.base.paths.len() != self.slot_capacity
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        for pk in [self.base.params.generator, self.base.ra_pk, self.base.sr_pk].iter() {
            if pk.is_zero() || !pk.is_on_curve() || !pk.is_in_correct_subgroup_assuming_on_curve() {
                return Err(SynthesisError::Unsatisfiable);
            }
        }
        let p = FpVar::new_input(cs.clone(), || Ok(self.base.prime))?;
        let pb = range(&p, 252)?;
        pb[251].enforce_equal(&Boolean::TRUE)?;
        let q = self
            .base
            .request
            .fields
            .iter()
            .map(|v| FpVar::new_input(cs.clone(), || Ok(*v)))
            .collect::<Result<Vec<_>, _>>()?;
        for i in [0, 1, 12, 13].iter() {
            range(&q[*i], 128)?;
        }
        for i in [2, 3, 4, 5, 6, 7, 9, 10, 11].iter() {
            range(&q[*i], 64)?;
        }
        let reqbits = range(&q[8], 16)?;
        let mut sum = FpVar::zero();
        for b in &reqbits {
            sum += Boolean::le_bits_to_fp_var(&[b.clone()])?;
        }
        sum.enforce_equal(&FpVar::one())?;
        le(&q[9], &q[11], 64)?;
        let up = point(cs.clone(), self.base.user_pk)?;
        let rho = alloc(cs.clone(), self.base.rho)?;
        let cu = hlimbs(&fvhash(1, &[up.x.clone(), up.y.clone(), rho], &[])?)?;
        let serial = alloc(cs.clone(), f(self.base.reg_serial))?;
        range(&serial, 64)?;
        nonzero_if(&serial, &Boolean::TRUE)?;
        let re = alloc(cs.clone(), f(self.base.reg_expiry))?;
        le(&q[11], &re, 64)?;
        let reg = fvhash(
            2,
            &[q[3].clone(), cu[0].clone(), cu[1].clone(), serial, re],
            &[],
        )?;
        let ra = EdwardsVar::new_constant(cs.clone(), self.base.ra_pk)?;
        verify_sig(cs.clone(), &self.base.params, &ra, &reg, &self.base.ra_sig)?;
        let root = UInt8::new_witness_vec(cs.clone(), &self.base.auth_root)?;
        let rt = hlimbs(&root)?;
        let ver = alloc(cs.clone(), f(self.base.state_version))?;
        range(&ver, 32)?;
        let status = alloc(cs.clone(), f(self.base.state_status))?;
        status.enforce_equal(&FpVar::one())?;
        let expiry = alloc(cs.clone(), f(self.base.state_expiry))?;
        le(&q[11], &expiry, 64)?;
        let tr = hlimbs(&UInt8::new_witness_vec(cs.clone(), &self.base.transition)?)?;
        let sh = fvhash(
            6,
            &[
                p.clone(),
                q[3].clone(),
                cu[0].clone(),
                cu[1].clone(),
                rt[0].clone(),
                rt[1].clone(),
                ver,
                status,
                expiry,
                tr[0].clone(),
                tr[1].clone(),
                q[4].clone(),
            ],
            &[],
        )?;
        let sr = EdwardsVar::new_constant(cs.clone(), self.base.sr_pk)?;
        verify_sig(cs.clone(), &self.base.params, &sr, &sh, &self.base.sr_sig)?;
        let enabled = self
            .enabled
            .iter()
            .map(|x| Boolean::new_witness(cs.clone(), || Ok(*x)))
            .collect::<Result<Vec<_>, _>>()?;
        enabled[0].enforce_equal(&Boolean::TRUE)?;
        for i in 1..self.slot_capacity {
            enabled[i]
                .and(&enabled[i - 1].not())?
                .enforce_equal(&Boolean::FALSE)?;
        }
        let mut selected_pk = up.clone();
        let mut prevpk = up;
        let mut parent = reg;
        let mut prev: Option<Vec<FpVar<Fr>>> = None;
        let mut chain = None;
        for i in 0..self.slot_capacity {
            let g = &self.base.grants[i];
            let xs = g
                .fields
                .iter()
                .map(|v| alloc(cs.clone(), *v))
                .collect::<Result<Vec<_>, _>>()?;
            xs[0].enforce_equal(&FpVar::constant(f(if i == 0 { 0 } else { 1 })))?;
            xs[1].enforce_equal(&cu[0])?;
            xs[2].enforce_equal(&cu[1])?;
            xs[3].enforce_equal(&prevpk.x)?;
            xs[4].enforce_equal(&prevpk.y)?;
            let pk = point(cs.clone(), EdwardsAffine::new(g.fields[5], g.fields[6]))?;
            pk.x.enforce_equal(&xs[5])?;
            pk.y.enforce_equal(&xs[6])?;
            for j in [7, 9, 10, 13, 16].iter() {
                range(&xs[*j], 64)?;
            }
            range(&xs[12], 4)?;
            range(&xs[14], self.tree_depth)?;
            let db = range(&xs[11], 1)?;
            let _ = db;
            nonzero_if(&xs[13], &enabled[i])?;
            let disabled = enabled[i].not();
            for j in [7, 8, 9, 10, 11, 12, 13, 14].iter() {
                xs[*j].conditional_enforce_equal(&FpVar::zero(), &disabled)?;
            }
            xs[16].conditional_enforce_equal(&FpVar::one(), &disabled)?;
            pk.conditional_enforce_equal(&prevpk, &disabled)?;
            if let Some(ch) = &chain {
                xs[15].enforce_equal(ch)?;
            } else {
                chain = Some(xs[15].clone());
            }
            let ph = UInt8::new_witness_vec(cs.clone(), &g.parent)?;
            ph.conditional_enforce_equal(&parent, &enabled[i])?;
            ph.conditional_enforce_equal(&UInt8::constant_vec(&[0; 32]), &disabled)?;
            let core = fvhash(3, &xs, &ph)?;
            let sigencoding =
                verify_sig(cs.clone(), &self.base.params, &prevpk, &core, &g.signature)?;
            let mut idbytes = core.clone();
            idbytes.extend(sigencoding);
            parent = hv(4, &idbytes)?;
            let active = Boolean::new_witness(cs.clone(), || Ok(g.active))?;
            active.enforce_equal(&enabled[i])?;
            let mut leafbytes = xs[14].to_bytes()?;
            leafbytes.extend(core);
            leafbytes.push(UInt8::from_bits_le(&[
                active,
                Boolean::FALSE,
                Boolean::FALSE,
                Boolean::FALSE,
                Boolean::FALSE,
                Boolean::FALSE,
                Boolean::FALSE,
                Boolean::FALSE,
            ]));
            let mut node = hv(5, &leafbytes)?;
            let index = range(&xs[14], self.tree_depth)?;
            if self.base.paths[i].len() != self.tree_depth {
                return Err(SynthesisError::Unsatisfiable);
            }
            for level in 0..self.tree_depth {
                let sibling = UInt8::new_witness_vec(cs.clone(), &self.base.paths[i][level])?;
                sibling.conditional_enforce_equal(&UInt8::constant_vec(&[0; 32]), &disabled)?;
                let mut data = vec![];
                for j in 0..32 {
                    data.push(UInt8::conditionally_select(
                        &index[level],
                        &sibling[j],
                        &node[j],
                    )?);
                }
                for j in 0..32 {
                    data.push(UInt8::conditionally_select(
                        &index[level],
                        &node[j],
                        &sibling[j],
                    )?);
                }
                node = hv(7, &data)?;
            }
            node.conditional_enforce_equal(&root, &enabled[i])?;
            let mask = range(&xs[8], 16)?;
            xs[7].conditional_enforce_equal(&q[7], &enabled[i])?;
            le_if(&xs[9], &q[9], 64, &enabled[i])?;
            le_if(&q[11], &xs[10], 64, &enabled[i])?;
            for k in 0..16 {
                reqbits[k]
                    .and(&mask[k].not())?
                    .conditional_enforce_equal(&Boolean::FALSE, &enabled[i])?;
            }
            if let Some(old) = prev {
                old[11].conditional_enforce_equal(&FpVar::one(), &enabled[i])?;
                (&xs[12] + Fr::one()).conditional_enforce_equal(&old[12], &enabled[i])?;
                le_if(&old[9], &xs[9], 64, &enabled[i])?;
                le_if(&xs[10], &old[10], 64, &enabled[i])?;
                let bm = range(&old[8], 16)?;
                for k in 0..16 {
                    mask[k]
                        .and(&bm[k].not())?
                        .conditional_enforce_equal(&Boolean::FALSE, &enabled[i])?;
                }
            } else {
                le(
                    &xs[12],
                    &FpVar::constant(f((self.slot_capacity - 1) as u64)),
                    4,
                )?;
            }
            selected_pk = EdwardsVar::conditionally_select(&enabled[i], &pk, &selected_pk)?;
            prev = Some(xs);
            prevpk = pk;
        }
        selected_pk.x.enforce_equal(&q[14])?;
        selected_pk.y.enforce_equal(&q[15])?;
        let sk = scalar(cs.clone(), self.base.holder)?;
        let generator = EdwardsVar::new_constant(cs.clone(), self.base.params.generator)?;
        generator
            .scalar_mul_le(sk.iter())?
            .enforce_equal(&selected_pk)?;
        // The canonical domain-8 full request hash is deliberately retained.
        let _request_hash = fvhash(8, &q, &[])?;
        Ok(())
    }
}

fn scaling_tree(grants: &[Grant], tree_depth: usize) -> Vec<Vec<Hash>> {
    let mut leaves = vec![[0; 32]; 1 << tree_depth];
    for grant in grants {
        let index = grant.fields[14].into_repr().as_ref()[0] as usize;
        leaves[index] = grant.leaf();
    }
    let mut tree = vec![leaves];
    for level in 0..tree_depth {
        let next = tree[level]
            .chunks(2)
            .map(|pair| hash(7, &[pair[0].to_vec(), pair[1].to_vec()].concat()))
            .collect();
        tree.push(next);
    }
    tree
}

/// Build a synthetic full-active chain for one frozen matrix cell. Slots are
/// signed by consecutive fixture principals and use distinct leaves 0..slots.
pub fn full_active_circuit(
    seed: u64,
    slot_capacity: usize,
    tree_depth: usize,
) -> ScalingAuthCircuit {
    prefix_circuit(seed, slot_capacity, slot_capacity, tree_depth)
}

/// Build a synthetic private prefix and canonical terminal-self-signed padding.
/// The public relation shape depends on capacity, not on `active_slots`.
pub fn prefix_circuit(
    seed: u64,
    slot_capacity: usize,
    active_slots: usize,
    tree_depth: usize,
) -> ScalingAuthCircuit {
    assert!(SCALING_SLOTS.contains(&slot_capacity));
    assert!(SCALING_TREE_DEPTHS.contains(&tree_depth));
    assert!(active_slots > 0 && active_slots <= slot_capacity);
    let mut fixture = AuthFixture::new_with_expiry(seed, 86_400);
    let cu = limbs(fixture.base.user_commitment());
    let mut grants: Vec<Grant> = Vec::with_capacity(slot_capacity);
    for i in 0..active_slots {
        let parent = if i == 0 {
            fixture.base.reg_hash()
        } else {
            grants[i - 1].id()
        };
        let issuer = fixture.keys[i].0;
        let subject = fixture.keys[i + 1].0;
        let fields = [
            f(if i == 0 { 0 } else { 1 }),
            cu[0],
            cu[1],
            issuer.x,
            issuer.y,
            subject.x,
            subject.y,
            f(42),
            f(3),
            f(100),
            f(86_400),
            f(1),
            f((active_slots - 1 - i) as u64),
            f((i + 1) as u64),
            f(i as u64),
            f(777),
            f(1),
        ];
        let mut grant = Grant {
            fields,
            parent,
            signature: Sig::default(),
            active: true,
        };
        grant.signature = sign(
            &fixture.base.params,
            &fixture.keys[i].1,
            grant.core(),
            &mut fixture.rng,
        );
        grants.push(grant);
    }
    let tree = scaling_tree(&grants, tree_depth);
    let mut paths = grants
        .iter()
        .map(|grant| {
            let mut position = grant.fields[14].into_repr().as_ref()[0] as usize;
            let mut path = Vec::with_capacity(tree_depth);
            for level in 0..tree_depth {
                path.push(tree[level][position ^ 1]);
                position /= 2;
            }
            path
        })
        .collect::<Vec<_>>();
    fixture.base.auth_root = tree[tree_depth][0];
    fixture.base.holder = fixture.keys[active_slots].1 .0;
    fixture.base.request.fields[14] = fixture.keys[active_slots].0.x;
    fixture.base.request.fields[15] = fixture.keys[active_slots].0.y;
    let terminal_pk = fixture.keys[active_slots].0;
    while grants.len() < slot_capacity {
        let mut padding = Grant {
            fields: [
                f(1),
                cu[0],
                cu[1],
                terminal_pk.x,
                terminal_pk.y,
                terminal_pk.x,
                terminal_pk.y,
                f(0),
                f(0),
                f(0),
                f(0),
                f(0),
                f(0),
                f(0),
                f(0),
                f(777),
                f(1),
            ],
            parent: [0; 32],
            signature: Sig::default(),
            active: false,
        };
        padding.signature = sign(
            &fixture.base.params,
            &fixture.keys[active_slots].1,
            padding.core(),
            &mut fixture.rng,
        );
        grants.push(padding);
        paths.push(vec![[0; 32]; tree_depth]);
    }
    fixture.base.grants = grants;
    fixture.base.paths = paths;
    fixture.base.sr_sig = sign(
        &fixture.base.params,
        &fixture.sr_sk,
        fixture.base.state_hash(),
        &mut fixture.rng,
    );
    ScalingAuthCircuit {
        base: fixture.base,
        enabled: (0..slot_capacity).map(|i| i < active_slots).collect(),
        slot_capacity,
        tree_depth,
    }
}

#[derive(Debug)]
pub struct RelationSnapshot {
    pub matrices: ConstraintMatrices<Fr>,
    pub instance_assignment: Vec<Fr>,
    pub witness_assignment: Vec<Fr>,
    pub satisfied: bool,
}

pub fn relation_snapshot<C: ConstraintSynthesizer<Fr>>(
    circuit: C,
) -> Result<RelationSnapshot, SynthesisError> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit.generate_constraints(cs.clone())?;
    cs.finalize();
    let satisfied = cs.is_satisfied()?;
    let borrowed = cs.borrow().ok_or(SynthesisError::AssignmentMissing)?;
    let matrices = borrowed
        .to_matrices()
        .ok_or(SynthesisError::AssignmentMissing)?;
    Ok(RelationSnapshot {
        matrices,
        instance_assignment: borrowed.instance_assignment.clone(),
        witness_assignment: borrowed.witness_assignment.clone(),
        satisfied,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_three_by_three_is_exactly_equal() {
        let canonical = AuthFixture::new(20261022).circuit_for("P");
        let generalized = ScalingAuthCircuit::from_canonical(canonical.clone());
        let left = relation_snapshot(canonical).unwrap();
        let right = relation_snapshot(generalized).unwrap();
        assert!(left.satisfied && right.satisfied);
        assert_eq!(left.matrices, right.matrices);
        assert_eq!(left.instance_assignment, right.instance_assignment);
        assert_eq!(left.witness_assignment, right.witness_assignment);
    }

    #[test]
    fn frozen_cells_are_satisfied() {
        for slots in SCALING_SLOTS {
            for depth in SCALING_TREE_DEPTHS {
                let snapshot = relation_snapshot(full_active_circuit(
                    20261022 + slots as u64 * 10 + depth as u64,
                    slots,
                    depth,
                ))
                .unwrap();
                assert!(snapshot.satisfied, "slots={} depth={}", slots, depth);
            }
        }
    }
}
