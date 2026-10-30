//! Typed, single-allocation joint authorization relation.
use crate::{
    contract::{Entitlement, Grant, Request, Slot, Snapshot, UserState, ACTION_BITS},
    indexed_revocation::enforce_nonmembership_if,
    poseidon::{hash, hash_var, Domain},
    signature::{enforce_valid_allocated_if, verify_allocated_if},
    Fr,
};
use ark_ed_on_bls12_381::constraints::EdwardsVar;
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
fn observe(cs: &ConstraintSystemRef<Fr>, phase: &str) {
    if std::env::var_os("PLAN_A_CONSTRAINT_PROFILE").is_some() {
        eprintln!(
            "constraint_profile phase={phase} constraints={} instances={} witnesses={}",
            cs.num_constraints(),
            cs.num_instance_variables(),
            cs.num_witness_variables()
        )
    }
}

#[derive(Clone)]
pub struct JointCircuit<const L: usize> {
    pub snapshot: Snapshot,
    pub request: Request,
    pub entitlement: Entitlement,
    pub state: UserState,
    pub registration_salt: Fr,
    pub grants: [Slot; L],
}
fn fw(cs: &ConstraintSystemRef<Fr>, x: Fr) -> Result<FpVar<Fr>, SynthesisError> {
    FpVar::new_witness(cs.clone(), || Ok(x))
}
fn u64v(
    cs: &ConstraintSystemRef<Fr>,
    x: u64,
) -> Result<(FpVar<Fr>, Vec<Boolean<Fr>>), SynthesisError> {
    let v = fw(cs, Fr::from(x))?;
    let b = v.to_bits_le()?;
    for x in &b[64..] {
        x.enforce_equal(&Boolean::FALSE)?
    }
    Ok((v, b[..64].to_vec()))
}
fn u16v(
    cs: &ConstraintSystemRef<Fr>,
    x: u16,
) -> Result<(FpVar<Fr>, Vec<Boolean<Fr>>), SynthesisError> {
    let v = fw(cs, Fr::from(x as u64))?;
    let b = v.to_bits_le()?;
    for x in &b[16..] {
        x.enforce_equal(&Boolean::FALSE)?
    }
    Ok((v, b[..16].to_vec()))
}
fn le(a: &[Boolean<Fr>], b: &[Boolean<Fr>]) -> Result<Boolean<Fr>, SynthesisError> {
    let (mut l, mut e) = (Boolean::FALSE, Boolean::TRUE);
    for i in (0..a.len()).rev() {
        l = l.or(&e.and(&a[i].not().and(&b[i])?)?)?;
        e = e.and(&a[i].xor(&b[i])?.not())?
    }
    l.or(&e)
}
fn gate(e: &Boolean<Fr>, c: Boolean<Fr>) -> Result<(), SynthesisError> {
    e.and(&c.not())?.enforce_equal(&Boolean::FALSE)
}
fn mpath(
    cs: &ConstraintSystemRef<Fr>,
    mut cur: FpVar<Fr>,
    sib: &[Fr],
    dir: &[bool],
    dom: Domain,
    pos: Option<&[Boolean<Fr>]>,
    disabled: Option<&Boolean<Fr>>,
) -> Result<FpVar<Fr>, SynthesisError> {
    if sib.len() != dir.len() {
        return Err(SynthesisError::Unsatisfiable);
    }
    for (i, (s, d)) in sib.iter().zip(dir).enumerate() {
        let sv = fw(cs, *s)?;
        let dv = Boolean::new_witness(cs.clone(), || Ok(*d))?;
        if let Some(p) = pos {
            dv.enforce_equal(p.get(i).ok_or(SynthesisError::Unsatisfiable)?)?
        }
        if let Some(en) = disabled {
            en.not()
                .and(&sv.is_zero()?.not())?
                .enforce_equal(&Boolean::FALSE)?;
            en.not().and(&dv)?.enforce_equal(&Boolean::FALSE)?
        }
        let l = FpVar::conditionally_select(&dv, &sv, &cur)?;
        let r = FpVar::conditionally_select(&dv, &cur, &sv)?;
        cur = hash_var(dom, &[l, r])?
    }
    Ok(cur)
}

pub fn grant_digest(g: &Grant) -> Fr {
    hash(
        Domain::Grant,
        &[
            g.issuer.0.x,
            g.issuer.0.y,
            g.subject.0.x,
            g.subject.0.y,
            g.resource,
            Fr::from(g.action_mask as u64),
            Fr::from(g.interval_lo),
            Fr::from(g.interval_hi),
            Fr::from(g.not_before),
            Fr::from(g.expiry),
            Fr::from(g.depth_remaining as u64),
            g.serial,
            g.parent_digest,
        ],
    )
}
pub fn snapshot_digest(s: &Snapshot) -> Fr {
    hash(
        Domain::Snapshot,
        &[
            Fr::from(s.tuple_version),
            s.root_ra,
            s.root_state,
            s.root_rev,
            Fr::from(s.state_epoch),
            Fr::from(s.revocation_epoch),
            Fr::from(s.issued_at),
        ],
    )
}
pub fn request_digest(r: &Request, sd: Fr) -> Fr {
    hash(
        Domain::Request,
        &[
            r.canonical_request_lo,
            r.canonical_request_hi,
            r.circuit_id,
            r.verifier_id,
            r.pep_id,
            r.resource,
            Fr::from(r.action_onehot as u64),
            Fr::from(r.interval_lo),
            Fr::from(r.interval_hi),
            Fr::from(r.time),
            r.nonce,
            r.context,
            r.terminal.0.x,
            r.terminal.0.y,
            sd,
        ],
    )
}

impl<const L: usize> ConstraintSynthesizer<Fr> for JointCircuit<L> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if !(1..=5).contains(&L) {
            return Err(SynthesisError::Unsatisfiable);
        }
        let tv = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.snapshot.tuple_version)))?;
        let rr = FpVar::new_input(cs.clone(), || Ok(self.snapshot.root_ra))?;
        let rs = FpVar::new_input(cs.clone(), || Ok(self.snapshot.root_state))?;
        let rv = FpVar::new_input(cs.clone(), || Ok(self.snapshot.root_rev))?;
        let se = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.snapshot.state_epoch)))?;
        let seb = se.to_bits_le()?;
        for b in &seb[64..] {
            b.enforce_equal(&Boolean::FALSE)?
        }
        let re = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.snapshot.revocation_epoch)))?;
        let ia = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.snapshot.issued_at)))?;
        let sd = FpVar::new_input(cs.clone(), || Ok(snapshot_digest(&self.snapshot)))?;
        sd.enforce_equal(&hash_var(
            Domain::Snapshot,
            &[tv, rr.clone(), rs.clone(), rv.clone(), se, re, ia],
        )?)?;
        observe(&cs, "snapshot");
        let q0 = FpVar::new_input(cs.clone(), || Ok(self.request.canonical_request_lo))?;
        let q0b = q0.to_bits_le()?;
        for b in &q0b[128..] {
            b.enforce_equal(&Boolean::FALSE)?
        }
        let q1 = FpVar::new_input(cs.clone(), || Ok(self.request.canonical_request_hi))?;
        let q1b = q1.to_bits_le()?;
        for b in &q1b[128..] {
            b.enforce_equal(&Boolean::FALSE)?
        }
        let cid = FpVar::new_input(cs.clone(), || Ok(self.request.circuit_id))?;
        let vid = FpVar::new_input(cs.clone(), || Ok(self.request.verifier_id))?;
        let pep = FpVar::new_input(cs.clone(), || Ok(self.request.pep_id))?;
        let qres = FpVar::new_input(cs.clone(), || Ok(self.request.resource))?;
        let qa = FpVar::new_input(cs.clone(), || {
            Ok(Fr::from(self.request.action_onehot as u64))
        })?;
        let qab = qa.to_bits_le()?;
        for b in &qab[ACTION_BITS..] {
            b.enforce_equal(&Boolean::FALSE)?
        }
        let mut action_sum = FpVar::zero();
        for b in &qab[..ACTION_BITS] {
            action_sum += Boolean::le_bits_to_fp_var(&[b.clone()])?
        }
        action_sum.enforce_equal(&FpVar::one())?;
        let ql = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.request.interval_lo)))?;
        let qlb = ql.to_bits_le()?;
        for b in &qlb[64..] {
            b.enforce_equal(&Boolean::FALSE)?
        }
        let qh = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.request.interval_hi)))?;
        let qhb = qh.to_bits_le()?;
        for b in &qhb[64..] {
            b.enforce_equal(&Boolean::FALSE)?
        }
        let qt = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.request.time)))?;
        let qtb = qt.to_bits_le()?;
        for b in &qtb[64..] {
            b.enforce_equal(&Boolean::FALSE)?
        }
        let n = FpVar::new_input(cs.clone(), || Ok(self.request.nonce))?;
        let ctx = FpVar::new_input(cs.clone(), || Ok(self.request.context))?;
        let tx = FpVar::new_input(cs.clone(), || Ok(self.request.terminal.0.x))?;
        let ty = FpVar::new_input(cs.clone(), || Ok(self.request.terminal.0.y))?;
        let qd = FpVar::new_input(cs.clone(), || {
            Ok(request_digest(
                &self.request,
                snapshot_digest(&self.snapshot),
            ))
        })?;
        qd.enforce_equal(&hash_var(
            Domain::Request,
            &[
                q0,
                q1,
                cid,
                vid,
                pep,
                qres.clone(),
                qa,
                ql.clone(),
                qh.clone(),
                qt.clone(),
                n,
                ctx,
                tx.clone(),
                ty.clone(),
                sd,
            ],
        )?)?;
        le(&qlb[..64], &qtb[..64])?.enforce_equal(&Boolean::TRUE)?;
        le(&qtb[..64], &qhb[..64])?.enforce_equal(&Boolean::TRUE)?;
        observe(&cs, "request");
        let eo = fw(&cs, self.entitlement.owner_commitment)?;
        let er = fw(&cs, self.entitlement.resource)?;
        let (ea, eab) = u16v(&cs, self.entitlement.action_mask)?;
        let (el, elb) = u64v(&cs, self.entitlement.interval_lo)?;
        let (eh, ehb) = u64v(&cs, self.entitlement.interval_hi)?;
        let (ep, epb) = u64v(&cs, self.entitlement.permit_expiry)?;
        let eid = fw(&cs, self.entitlement.admission_id)?;
        let eleaf = hash_var(
            Domain::RaLeaf,
            &[eo.clone(), er.clone(), ea, el, eh, ep, eid],
        )?;
        mpath(
            &cs,
            eleaf,
            &self.entitlement.path.siblings,
            &self.entitlement.path.directions,
            Domain::TreeNode,
            None,
            None,
        )?
        .enforce_equal(&rr)?;
        er.enforce_equal(&qres)?;
        le(&elb, &qlb[..64])?.enforce_equal(&Boolean::TRUE)?;
        le(&qhb[..64], &ehb)?.enforce_equal(&Boolean::TRUE)?;
        le(&qhb[..64], &epb)?.enforce_equal(&Boolean::TRUE)?;
        for i in 0..16 {
            qab[i].and(&eab[i].not())?.enforce_equal(&Boolean::FALSE)?
        }
        observe(&cs, "registration");
        let so = fw(&cs, self.state.owner_commitment)?;
        let sgr = fw(&cs, self.state.grant_root)?;
        let (sver, _) = u64v(&cs, self.state.state_version)?;
        let (sepoch, sepochb) = u64v(&cs, self.state.state_epoch)?;
        let (sexp, sexpb) = u64v(&cs, self.state.state_expiry)?;
        let active = Boolean::new_witness(cs.clone(), || Ok(self.state.active))?;
        let ssalt = fw(&cs, self.state.salt)?;
        let pos = fw(&cs, Fr::from(self.state.position))?;
        let pb = pos.to_bits_le()?;
        for b in &pb[self.state.path.siblings.len()..] {
            b.enforce_equal(&Boolean::FALSE)?
        }
        let sleaf = hash_var(
            Domain::StateLeaf,
            &[
                so.clone(),
                sgr.clone(),
                sver,
                sepoch,
                sexp,
                Boolean::le_bits_to_fp_var(&[active.clone()])?,
                ssalt,
                pos,
            ],
        )?;
        mpath(
            &cs,
            sleaf,
            &self.state.path.siblings,
            &self.state.path.directions,
            Domain::TreeNode,
            Some(&pb),
            None,
        )?
        .enforce_equal(&rs)?;
        so.enforce_equal(&eo)?;
        active.enforce_equal(&Boolean::TRUE)?;
        le(&sepochb, &seb[..64])?.enforce_equal(&Boolean::TRUE)?;
        le(&qhb[..64], &sexpb)?.enforce_equal(&Boolean::TRUE)?;
        observe(&cs, "state");
        let regsalt = fw(&cs, self.registration_salt)?;
        let mut pe = Boolean::TRUE;
        let (mut ps, mut pd): (Option<EdwardsVar>, Option<FpVar<Fr>>) = (None, None);
        let (mut pa, mut plo, mut phi, mut pexp, mut pnb) = (eab, elb.clone(), ehb, epb, elb);
        let mut pdepth: Option<FpVar<Fr>> = None;
        let (mut lx, mut ly) = (FpVar::zero(), FpVar::one());
        for (i, s) in self.grants.iter().enumerate() {
            let en = Boolean::new_witness(cs.clone(), || Ok(s.enabled))?;
            if i == 0 {
                en.enforce_equal(&Boolean::TRUE)?
            }
            en.and(&pe.not())?.enforce_equal(&Boolean::FALSE)?;
            pe = en.clone();
            let ix = fw(&cs, s.grant.issuer.0.x)?;
            let iy = fw(&cs, s.grant.issuer.0.y)?;
            let sx = fw(&cs, s.grant.subject.0.x)?;
            let sy = fw(&cs, s.grant.subject.0.y)?;
            let issuer = EdwardsVar::new(ix.clone(), iy.clone());
            let subject = EdwardsVar::new(sx.clone(), sy.clone());
            let res = fw(&cs, s.grant.resource)?;
            let (am, ab) = u16v(&cs, s.grant.action_mask)?;
            let (lov, lb) = u64v(&cs, s.grant.interval_lo)?;
            let (hiv, hb) = u64v(&cs, s.grant.interval_hi)?;
            let (nbv, nb) = u64v(&cs, s.grant.not_before)?;
            let (exv, xb) = u64v(&cs, s.grant.expiry)?;
            let depth = fw(&cs, Fr::from(s.grant.depth_remaining as u64))?;
            let db = depth.to_bits_le()?;
            for b in &db[8..] {
                b.enforce_equal(&Boolean::FALSE)?
            }
            let serial = fw(&cs, s.grant.serial)?;
            let parent = fw(&cs, s.grant.parent_digest)?;
            let dig = hash_var(
                Domain::Grant,
                &[
                    ix.clone(),
                    iy.clone(),
                    sx.clone(),
                    sy.clone(),
                    res.clone(),
                    am.clone(),
                    lov.clone(),
                    hiv.clone(),
                    nbv.clone(),
                    exv.clone(),
                    depth.clone(),
                    serial.clone(),
                    parent.clone(),
                ],
            )?;
            let rx = fw(&cs, s.grant.signature.r.x)?;
            let ry = fw(&cs, s.grant.signature.r.y)?;
            verify_allocated_if(
                cs.clone(),
                &Boolean::TRUE,
                &issuer,
                dig.clone(),
                &EdwardsVar::new(rx.clone(), ry.clone()),
                s.grant.signature.s,
            )?;
            enforce_valid_allocated_if(&Boolean::TRUE, &subject)?;
            observe(&cs, &format!("slot_{i}_signature"));
            observe(&cs, &format!("slot_{i}_crypto_valid"));
            if i == 0 {
                hash_var(Domain::Owner, &[ix.clone(), iy.clone(), regsalt.clone()])?
                    .enforce_equal(&eo)?;
                res.enforce_equal(&er)?;
                parent.enforce_equal(&FpVar::zero())?;
                let leaf = hash_var(Domain::GrantLeaf, &[dig.clone()])?;
                mpath(
                    &cs,
                    leaf,
                    &s.grant_path.siblings,
                    &s.grant_path.directions,
                    Domain::TreeNode,
                    None,
                    None,
                )?
                .enforce_equal(&sgr)?
            } else {
                if let (Some(p), Some(d)) = (&ps, &pd) {
                    gate(&en, ix.is_eq(&p.x)?)?;
                    gate(&en, iy.is_eq(&p.y)?)?;
                    gate(&en, parent.is_eq(d)?)?
                }
                for (x, d) in s.grant_path.siblings.iter().zip(&s.grant_path.directions) {
                    fw(&cs, *x)?.enforce_equal(&FpVar::zero())?;
                    Boolean::new_witness(cs.clone(), || Ok(*d))?.enforce_equal(&Boolean::FALSE)?
                }
            }
            observe(&cs, &format!("slot_{i}_membership"));
            gate(&en, res.is_eq(&qres)?)?;
            for j in 0..16 {
                gate(&en, qab[j].and(&ab[j].not())?.not())?;
                gate(&en, ab[j].and(&pa[j].not())?.not())?
            }
            gate(&en, le(&plo, &lb)?)?;
            gate(&en, le(&hb, &phi)?)?;
            gate(&en, le(&lb, &qlb[..64])?)?;
            gate(&en, le(&qhb[..64], &hb)?)?;
            gate(&en, le(&pnb, &nb)?)?;
            gate(&en, le(&nb, &qlb[..64])?)?;
            gate(&en, le(&qhb[..64], &xb)?)?;
            gate(&en, le(&xb, &pexp)?)?;
            if let Some(d) = &pdepth {
                gate(&en, (depth.clone() + Fr::from(1u64)).is_eq(d)?)?
            }
            observe(&cs, &format!("slot_{i}_policy"));
            enforce_nonmembership_if(cs.clone(), &Boolean::TRUE, &serial, &rv, &s.revocation)?;
            observe(&cs, &format!("slot_{i}_revocation"));
            lx = FpVar::conditionally_select(&en, &sx, &lx)?;
            ly = FpVar::conditionally_select(&en, &sy, &ly)?;
            ps = Some(subject);
            pd = Some(dig);
            pa = ab;
            plo = lb;
            phi = hb;
            pexp = xb;
            pnb = nb;
            pdepth = Some(depth)
        }
        observe(&cs, "slots_complete");
        lx.enforce_equal(&tx)?;
        ly.enforce_equal(&ty)?;
        observe(&cs, "terminal");
        Ok(())
    }
}
