use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::EdwardsAffine;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::{BTreeMap, BTreeSet},
    rand::RngCore,
};
use bbs_plus::prelude::{KeypairG2, Signature23G1, SignatureParams23G1};
use blake2::{Blake2b512, Blake2s256, Digest};
use legogroth16::{ProvingKey, VerifyingKey};
use proof_system::{
    prelude::{
        EqualWitnesses, MetaStatements, Proof, ProofSpec, Witness, Witnesses,
    },
    statement::{
        bbs_23::{
            PoKBBSSignature23G1Prover as BbsProverStatement,
            PoKBBSSignature23G1Verifier as BbsVerifierStatement,
        },
        bound_check_legogroth16::{
            BoundCheckLegoGroth16Prover as BoundProverStatement,
            BoundCheckLegoGroth16Verifier as BoundVerifierStatement,
        },
        Statements,
    },
    sub_protocols::bound_check_legogroth16::generate_snark_srs_bound_check,
    witness::PoKBBSSignature23G1 as BbsWitness,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CREDENTIAL_DOMAIN: &[u8] = b"HRADA-SR-F-ATOMIC-V1";
pub const SHOW_DOMAIN: &[u8] = b"HRADA-SR-F-SHOW-V1";
pub const PROOF_VARIANT: &[u8] = b"DOCK-BBS23-CDL-COMPOSITE-V1";
pub const MESSAGE_COUNT: usize = 8;
pub const LOWER_SLOT: usize = 6;
pub const UPPER_COMPLEMENT_SLOT: usize = 7;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicCredentialFields {
    pub system: u64,
    pub circuit_version: u64,
    pub global_epoch: u64,
    pub resource: u64,
    pub action_one_hot: u16,
    pub terminal_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestContext {
    pub current_header_digest: [u8; 32],
    pub params_digest: [u8; 32],
    pub complete_q: Vec<u8>,
    pub verifier_nonce: Vec<u8>,
    pub tq: u64,
    pub te: u64,
}

#[derive(Clone)]
pub struct Issuer {
    pub params: SignatureParams23G1<Bls12_381>,
    pub keypair: KeypairG2<Bls12_381>,
    pub bound_proving_key: ProvingKey<Bls12_381>,
}

#[derive(Clone)]
pub struct VerifierParams {
    pub signature_params: SignatureParams23G1<Bls12_381>,
    pub issuer_public_key: bbs_plus::setup::PublicKeyG2<Bls12_381>,
    pub bound_verifying_key: VerifyingKey<Bls12_381>,
}

#[derive(Clone)]
pub struct ProverParams {
    pub signature_params: SignatureParams23G1<Bls12_381>,
    pub bound_proving_key: ProvingKey<Bls12_381>,
    pub params_digest: [u8; 32],
}

#[derive(Clone)]
pub struct AtomicCredential {
    pub public: PublicCredentialFields,
    pub lower: u64,
    pub upper: u64,
    pub signature: Signature23G1<Bls12_381>,
}

pub struct Showing {
    pub proof: Proof<Bls12_381>,
    pub disclosed: BTreeMap<usize, Fr>,
    pub context: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum FullFError {
    #[error("action must be exactly one non-zero bit")]
    InvalidAction,
    #[error("invalid closed interval")]
    InvalidInterval,
    #[error("invalid request interval")]
    InvalidRequest,
    #[error("public credential fields do not match")]
    PublicFieldsMismatch,
    #[error("request parameter digest does not match verifier parameters")]
    ParamsDigestMismatch,
    #[error("invalid canonical Q16: {0}")]
    InvalidQ16(&'static str),
    #[error("issuance batch does not match request")]
    IssuanceMismatch,
    #[error("proof system error: {0}")]
    Proof(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicPermissionInput { pub resource: u64, pub action: u16 }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilationKeyInput {
    pub system: u64,
    pub circuit_version: u64,
    pub epoch: u64,
    pub terminal: Vec<u8>,
    pub permission: AtomicPermissionInput,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicCredentialInput {
    pub format: String,
    pub key: CompilationKeyInput,
    pub not_before: u64,
    pub not_after_complement: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialIssuanceBatch {
    pub format: String,
    pub epoch: u64,
    pub credentials: Vec<AtomicCredentialInput>,
}

fn fr_u64(value: &Fr) -> Result<u64, FullFError> {
    let bytes = value.into_bigint().to_bytes_le();
    if bytes.iter().skip(8).any(|b| *b != 0) { return Err(FullFError::InvalidQ16("field_not_u64")); }
    let mut low = [0u8; 8];
    low[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
    let n = u64::from_le_bytes(low);
    if Fr::from(n) != *value { return Err(FullFError::InvalidQ16("field_not_u64")); }
    Ok(n)
}

pub fn decode_complete_q(encoded: &[u8]) -> Result<[Fr; 16], FullFError> {
    const PREFIX: &[u8] = b"HRADA-Q16-V1";
    if !encoded.starts_with(PREFIX) { return Err(FullFError::InvalidQ16("prefix")); }
    let mut cursor = PREFIX.len();
    let mut fields = Vec::with_capacity(16);
    for _ in 0..16 {
        let len_bytes: [u8; 4] = encoded.get(cursor..cursor + 4).ok_or(FullFError::InvalidQ16("truncated_length"))?.try_into().unwrap();
        cursor += 4;
        let len = u32::from_le_bytes(len_bytes) as usize;
        let bytes = encoded.get(cursor..cursor + len).ok_or(FullFError::InvalidQ16("truncated_field"))?;
        cursor += len;
        let value = Fr::deserialize_compressed(bytes).map_err(|_| FullFError::InvalidQ16("noncanonical_field"))?;
        let mut canonical = Vec::new(); value.serialize_compressed(&mut canonical).map_err(|_| FullFError::InvalidQ16("field_encoding"))?;
        if canonical != bytes { return Err(FullFError::InvalidQ16("noncanonical_field")); }
        fields.push(value);
    }
    if cursor != encoded.len() { return Err(FullFError::InvalidQ16("trailing_bytes")); }
    fields.try_into().map_err(|_| FullFError::InvalidQ16("arity"))
}

pub fn encode_complete_q(fields: &[Fr; 16]) -> Result<Vec<u8>, FullFError> {
    let mut out = b"HRADA-Q16-V1".to_vec();
    for field in fields {
        let mut bytes = Vec::new(); field.serialize_compressed(&mut bytes).map_err(|e| FullFError::Proof(e.to_string()))?;
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes()); out.extend_from_slice(&bytes);
    }
    Ok(out)
}

pub fn q16_with_nonce(encoded: &[u8], nonce: u64) -> Result<Vec<u8>, FullFError> {
    let mut fields = decode_complete_q(encoded)?; fields[10] = Fr::from(nonce); encode_complete_q(&fields)
}

impl RequestContext {
    pub fn from_q16(
        complete_q: Vec<u8>, current_header_digest: [u8; 32], params_digest: [u8; 32],
        terminal_key: &[u8], verifier_nonce: u64,
    ) -> Result<(Self, PublicCredentialFields), FullFError> {
        let q = decode_complete_q(&complete_q)?;
        if q[0] != Fr::from_le_bytes_mod_order(&current_header_digest[..16]) || q[1] != Fr::from_le_bytes_mod_order(&current_header_digest[16..]) {
            return Err(FullFError::InvalidQ16("header_mismatch"));
        }
        let terminal = EdwardsAffine::new_unchecked(q[14], q[15]);
        if !terminal.is_on_curve() || !terminal.is_in_correct_subgroup_assuming_on_curve() { return Err(FullFError::InvalidQ16("terminal_point")); }
        // Decode through the pinned arkworks codec, then compare the complete
        // point. Reimplementing an assumed sign-bit layout here is brittle and
        // previously rejected the exact canonical bytes emitted by the Joint
        // compiler even though both crates use the same curve dependency.
        let encoded_terminal = EdwardsAffine::deserialize_compressed(terminal_key)
            .map_err(|_| FullFError::InvalidQ16("terminal_encoding"))?;
        if encoded_terminal != terminal { return Err(FullFError::InvalidQ16("terminal_mismatch")); }
        if fr_u64(&q[10])? != verifier_nonce { return Err(FullFError::InvalidQ16("nonce_mismatch")); }
        let action = fr_u64(&q[8])?;
        if action > u16::MAX as u64 { return Err(FullFError::InvalidQ16("action_not_u16")); }
        let public = PublicCredentialFields {
            system: fr_u64(&q[3])?, circuit_version: fr_u64(&q[4])?, global_epoch: fr_u64(&q[2])?,
            resource: fr_u64(&q[7])?, action_one_hot: action as u16, terminal_key: terminal_key.to_vec(),
        };
        let request = Self { current_header_digest, params_digest, complete_q, verifier_nonce: verifier_nonce.to_le_bytes().to_vec(), tq: fr_u64(&q[9])?, te: fr_u64(&q[11])? };
        if request.tq > request.te { return Err(FullFError::InvalidRequest); }
        Ok((request, public))
    }
}

impl AtomicCredentialInput {
    pub fn public_fields(&self) -> Result<PublicCredentialFields, FullFError> {
        if self.format != "HRADA-SR-F-ATOMIC-V1" { return Err(FullFError::IssuanceMismatch); }
        Ok(PublicCredentialFields { system: self.key.system, circuit_version: self.key.circuit_version, global_epoch: self.key.epoch, resource: self.key.permission.resource, action_one_hot: self.key.permission.action, terminal_key: self.key.terminal.clone() })
    }
    pub fn upper(&self) -> u64 { u64::MAX - self.not_after_complement }
}

impl CredentialIssuanceBatch {
    pub fn validate(&self) -> Result<(), FullFError> {
        if self.format != "HRADA-SR-F-ISSUANCE-BATCH-V1" { return Err(FullFError::IssuanceMismatch); }
        for c in &self.credentials {
            if c.key.epoch != self.epoch || c.not_before > c.upper() { return Err(FullFError::IssuanceMismatch); }
            public_messages(&c.public_fields()?)?;
        }
        Ok(())
    }
}

fn parameter_digest(
    params: &SignatureParams23G1<Bls12_381>,
    public_key: &bbs_plus::setup::PublicKeyG2<Bls12_381>,
    range_vk: &VerifyingKey<Bls12_381>,
) -> Result<[u8; 32], FullFError> {
    let mut encoded = Vec::new();
    push_lp(&mut encoded, CREDENTIAL_DOMAIN);
    push_lp(&mut encoded, PROOF_VARIANT);
    encoded.extend_from_slice(&(MESSAGE_COUNT as u64).to_be_bytes());
    for value in [
        {
            let mut b = Vec::new(); params.serialize_compressed(&mut b).map_err(|e| FullFError::Proof(e.to_string()))?; b
        },
        {
            let mut b = Vec::new(); public_key.serialize_compressed(&mut b).map_err(|e| FullFError::Proof(e.to_string()))?; b
        },
        {
            let mut b = Vec::new(); range_vk.serialize_compressed(&mut b).map_err(|e| FullFError::Proof(e.to_string()))?; b
        },
    ] { push_lp(&mut encoded, &value); }
    let digest = Blake2s256::digest(encoded);
    let mut out = [0u8; 32]; out.copy_from_slice(&digest); Ok(out)
}

fn scalar_hash(domain: &[u8], bytes: &[u8]) -> Fr {
    let mut h = Blake2b512::new();
    h.update((domain.len() as u64).to_be_bytes());
    h.update(domain);
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    Fr::from_le_bytes_mod_order(&h.finalize())
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn take_lp<'a>(input: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], FullFError> {
    let len_bytes: [u8; 8] = input.get(*cursor..*cursor + 8).ok_or(FullFError::Proof("truncated length prefix".into()))?.try_into().unwrap();
    *cursor += 8; let len = u64::from_be_bytes(len_bytes) as usize;
    let bytes = input.get(*cursor..*cursor + len).ok_or(FullFError::Proof("truncated value".into()))?; *cursor += len; Ok(bytes)
}

pub fn encode_context(request: &RequestContext) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, SHOW_DOMAIN);
    push_lp(&mut out, PROOF_VARIANT);
    push_lp(&mut out, &request.params_digest);
    push_lp(&mut out, &request.current_header_digest);
    push_lp(&mut out, &request.complete_q);
    out.push(u8::from(request.tq != u64::MAX));
    out.push(u8::from(request.te != 0));
    out
}

fn public_messages(public: &PublicCredentialFields) -> Result<[Fr; 6], FullFError> {
    if public.action_one_hot == 0 || public.action_one_hot.count_ones() != 1 {
        return Err(FullFError::InvalidAction);
    }
    let mut atom = Vec::with_capacity(18);
    atom.extend_from_slice(b"ATOM-V1");
    atom.extend_from_slice(&public.resource.to_be_bytes());
    atom.extend_from_slice(&public.action_one_hot.to_be_bytes());
    Ok([
        scalar_hash(b"CREDENTIAL-DOMAIN", CREDENTIAL_DOMAIN),
        Fr::from(public.system),
        Fr::from(public.circuit_version),
        Fr::from(public.global_epoch),
        scalar_hash(b"TYPED-ATOM", &atom),
        scalar_hash(b"JUBJUB-TERMINAL", &public.terminal_key),
    ])
}

fn messages(public: &PublicCredentialFields, lower: u64, upper: u64) -> Result<Vec<Fr>, FullFError> {
    if lower > upper {
        return Err(FullFError::InvalidInterval);
    }
    let mut result = public_messages(public)?.to_vec();
    result.push(Fr::from(lower));
    result.push(Fr::from(u64::MAX - upper));
    Ok(result)
}

impl Issuer {
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        let params = SignatureParams23G1::<Bls12_381>::generate_using_rng(rng, MESSAGE_COUNT as u32);
        let keypair = KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(rng, &params);
        let bound_proving_key = generate_snark_srs_bound_check::<Bls12_381, _>(rng).unwrap();
        Self { params, keypair, bound_proving_key }
    }

    pub fn issue<R: RngCore>(
        &self,
        rng: &mut R,
        public: PublicCredentialFields,
        lower: u64,
        upper: u64,
    ) -> Result<AtomicCredential, FullFError> {
        let signed = messages(&public, lower, upper)?;
        let signature = Signature23G1::new(rng, &signed, &self.keypair.secret_key, &self.params)
            .map_err(|e| FullFError::Proof(format!("{e:?}")))?;
        Ok(AtomicCredential { public, lower, upper, signature })
    }

    pub fn verifier_params(&self) -> VerifierParams {
        VerifierParams {
            signature_params: self.params.clone(),
            issuer_public_key: self.keypair.public_key.clone(),
            bound_verifying_key: self.bound_proving_key.vk.clone(),
        }
    }

    pub fn prover_params(&self) -> ProverParams {
        ProverParams { signature_params: self.params.clone(), bound_proving_key: self.bound_proving_key.clone(), params_digest: self.params_digest().expect("serializable public parameters") }
    }

    pub fn params_digest(&self) -> Result<[u8; 32], FullFError> {
        parameter_digest(&self.params, &self.keypair.public_key, &self.bound_proving_key.vk)
    }
}

impl VerifierParams {
    pub fn params_digest(&self) -> Result<[u8; 32], FullFError> {
        parameter_digest(&self.signature_params, &self.issuer_public_key, &self.bound_verifying_key)
    }
    pub fn verify_credential(&self, credential: &AtomicCredential) -> Result<(), FullFError> {
        let signed = messages(&credential.public, credential.lower, credential.upper)?;
        credential.signature
            .verify(&signed, self.issuer_public_key.clone(), self.signature_params.clone())
            .map_err(|e| FullFError::Proof(format!("{e:?}")))
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FullFError> {
        let mut out = Vec::new();
        for value in [
            { let mut b=Vec::new(); self.signature_params.serialize_compressed(&mut b).map_err(|e| FullFError::Proof(e.to_string()))?; b },
            { let mut b=Vec::new(); self.issuer_public_key.serialize_compressed(&mut b).map_err(|e| FullFError::Proof(e.to_string()))?; b },
            { let mut b=Vec::new(); self.bound_verifying_key.serialize_compressed(&mut b).map_err(|e| FullFError::Proof(e.to_string()))?; b },
        ] { push_lp(&mut out, &value); }
        Ok(out)
    }
    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, FullFError> {
        let mut cursor=0;
        let signature_params=SignatureParams23G1::deserialize_compressed(take_lp(input,&mut cursor)?).map_err(|e| FullFError::Proof(e.to_string()))?;
        let issuer_public_key=bbs_plus::setup::PublicKeyG2::deserialize_compressed(take_lp(input,&mut cursor)?).map_err(|e| FullFError::Proof(e.to_string()))?;
        let bound_verifying_key=VerifyingKey::deserialize_compressed(take_lp(input,&mut cursor)?).map_err(|e| FullFError::Proof(e.to_string()))?;
        if cursor != input.len() { return Err(FullFError::Proof("trailing verifier material".into())); }
        Ok(Self { signature_params, issuer_public_key, bound_verifying_key })
    }
}

impl ProverParams {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FullFError> {
        let mut out=Vec::new();
        let mut sig=Vec::new(); self.signature_params.serialize_compressed(&mut sig).map_err(|e| FullFError::Proof(e.to_string()))?; push_lp(&mut out,&sig);
        let mut pk=Vec::new(); self.bound_proving_key.serialize_compressed(&mut pk).map_err(|e| FullFError::Proof(e.to_string()))?; push_lp(&mut out,&pk);
        out.extend_from_slice(&self.params_digest); Ok(out)
    }
}

impl AtomicCredential {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FullFError> {
        let mut out = Vec::new();
        push_lp(&mut out, CREDENTIAL_DOMAIN);
        push_lp(&mut out, &serde_json::to_vec(&self.public).map_err(|e| FullFError::Proof(e.to_string()))?);
        out.extend_from_slice(&self.lower.to_be_bytes()); out.extend_from_slice(&self.upper.to_be_bytes());
        let mut signature = Vec::new(); self.signature.serialize_compressed(&mut signature).map_err(|e| FullFError::Proof(e.to_string()))?;
        push_lp(&mut out, &signature); Ok(out)
    }
}

impl Showing {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FullFError> {
        let mut out = Vec::new(); push_lp(&mut out, SHOW_DOMAIN); push_lp(&mut out, PROOF_VARIANT);
        let mut proof = Vec::new(); self.proof.serialize_compressed(&mut proof).map_err(|e| FullFError::Proof(e.to_string()))?;
        push_lp(&mut out, &proof); push_lp(&mut out, &self.context); push_lp(&mut out, &self.nonce);
        for (index, value) in &self.disclosed {
            out.extend_from_slice(&(*index as u64).to_be_bytes());
            let mut bytes = Vec::new(); value.serialize_compressed(&mut bytes).map_err(|e| FullFError::Proof(e.to_string()))?; push_lp(&mut out, &bytes);
        }
        Ok(out)
    }
    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, FullFError> {
        let mut cursor=0;
        if take_lp(input,&mut cursor)? != SHOW_DOMAIN || take_lp(input,&mut cursor)? != PROOF_VARIANT { return Err(FullFError::Proof("showing domain or variant".into())); }
        let proof=Proof::deserialize_compressed(take_lp(input,&mut cursor)?).map_err(|e| FullFError::Proof(e.to_string()))?;
        let context=take_lp(input,&mut cursor)?.to_vec(); let nonce=take_lp(input,&mut cursor)?.to_vec();
        let mut disclosed=BTreeMap::new();
        for _ in 0..6 {
            let index_bytes: [u8;8]=input.get(cursor..cursor+8).ok_or(FullFError::Proof("truncated disclosed index".into()))?.try_into().unwrap(); cursor+=8;
            let index=u64::from_be_bytes(index_bytes) as usize;
            let value=Fr::deserialize_compressed(take_lp(input,&mut cursor)?).map_err(|e| FullFError::Proof(e.to_string()))?;
            if disclosed.insert(index,value).is_some() { return Err(FullFError::Proof("duplicate disclosed index".into())); }
        }
        if cursor != input.len() { return Err(FullFError::Proof("trailing showing bytes".into())); }
        Ok(Self { proof, disclosed, context, nonce })
    }
}

fn add_bound_meta(
    meta: &mut MetaStatements,
    request: &RequestContext,
    statements: &mut Statements<Bls12_381>,
    proving_key: Option<&ProvingKey<Bls12_381>>,
    verifying_key: Option<&VerifyingKey<Bls12_381>>,
) -> Result<(), FullFError> {
    let mut index = 1usize;
    let mut add = |slot: usize, max: u64| -> Result<(), FullFError> {
        if let Some(pk) = proving_key {
            statements.add(BoundProverStatement::new_statement_from_params(0, max, pk.clone()).map_err(|e| FullFError::Proof(format!("{e:?}")))?);
        } else if let Some(vk) = verifying_key {
            statements.add(BoundVerifierStatement::new_statement_from_params(0, max, vk.clone()).map_err(|e| FullFError::Proof(format!("{e:?}")))?);
        }
        meta.add_witness_equality(EqualWitnesses(BTreeSet::from([(0, slot), (index, 0)])));
        index += 1;
        Ok(())
    };
    if request.tq != u64::MAX { add(LOWER_SLOT, request.tq + 1)?; }
    if request.te != 0 { add(UPPER_COMPLEMENT_SLOT, (u64::MAX - request.te) + 1)?; }
    Ok(())
}

fn build_prover_spec(
    prover: &ProverParams,
    disclosed: &BTreeMap<usize, Fr>,
    request: &RequestContext,
) -> Result<ProofSpec<Bls12_381>, FullFError> {
    if request.params_digest != prover.params_digest { return Err(FullFError::ParamsDigestMismatch); }
    if request.tq > request.te {
        return Err(FullFError::InvalidRequest);
    }
    let snark_pk = &prover.bound_proving_key;
    let mut statements = Statements::new();
    statements.add(BbsProverStatement::new_statement_from_params(
        prover.signature_params.clone(), disclosed.clone(),
    ));
    let mut meta = MetaStatements::new();
    add_bound_meta(&mut meta, request, &mut statements, Some(snark_pk), None)?;
    let context = Some(encode_context(request));
    Ok(ProofSpec::new(statements, meta, vec![], context))
}

fn build_verifier_spec(
    verifier: &VerifierParams,
    disclosed: &BTreeMap<usize, Fr>,
    request: &RequestContext,
) -> Result<ProofSpec<Bls12_381>, FullFError> {
    if request.params_digest != verifier.params_digest()? { return Err(FullFError::ParamsDigestMismatch); }
    if request.tq > request.te { return Err(FullFError::InvalidRequest); }
    let mut statements = Statements::new();
    statements.add(BbsVerifierStatement::new_statement_from_params(
        verifier.signature_params.clone(), verifier.issuer_public_key.clone(), disclosed.clone(),
    ));
    let mut meta = MetaStatements::new();
    add_bound_meta(&mut meta, request, &mut statements, None, Some(&verifier.bound_verifying_key))?;
    Ok(ProofSpec::new(statements, meta, vec![], Some(encode_context(request))))
}

pub fn present<R: RngCore>(
    rng: &mut R,
    prover: &ProverParams,
    credential: &AtomicCredential,
    request: &RequestContext,
) -> Result<Showing, FullFError> {
    let all = messages(&credential.public, credential.lower, credential.upper)?;
    let disclosed: BTreeMap<usize, Fr> = all.iter().take(6).copied().enumerate().collect();
    let prover_spec = build_prover_spec(prover, &disclosed, request)?;
    let mut witnesses = Witnesses::new();
    witnesses.add(BbsWitness::new_as_witness(
        credential.signature.clone(),
        all.iter().copied().enumerate().skip(LOWER_SLOT).collect(),
    ));
    if request.tq != u64::MAX { witnesses.add(Witness::BoundCheckLegoGroth16(Fr::from(credential.lower))); }
    if request.te != 0 { witnesses.add(Witness::BoundCheckLegoGroth16(Fr::from(u64::MAX - credential.upper))); }
    let proof = Proof::new::<R, Blake2b512>(rng, prover_spec, witnesses, Some(request.verifier_nonce.clone()), Default::default())
        .map_err(|e| FullFError::Proof(format!("{e:?}")))?.0;
    Ok(Showing { proof, disclosed, context: encode_context(request), nonce: request.verifier_nonce.clone() })
}

pub fn verify<R: RngCore>(
    rng: &mut R,
    verifier: &VerifierParams,
    expected_public: &PublicCredentialFields,
    request: &RequestContext,
    showing: &Showing,
) -> Result<Vec<u8>, FullFError> {
    let expected: BTreeMap<usize, Fr> = public_messages(expected_public)?.into_iter().enumerate().collect();
    if expected != showing.disclosed { return Err(FullFError::PublicFieldsMismatch); }
    if showing.context != encode_context(request) || showing.nonce != request.verifier_nonce { return Err(FullFError::PublicFieldsMismatch); }
    let verifier_spec = build_verifier_spec(verifier, &expected, request)?;
    showing.proof.clone().verify::<R, Blake2b512>(rng, verifier_spec, Some(request.verifier_nonce.clone()), Default::default())
        .map_err(|e| FullFError::Proof(format!("{e:?}")))?;
    let mut bytes = Vec::new();
    showing.proof.serialize_compressed(&mut bytes).map_err(|e| FullFError::Proof(e.to_string()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    fn public() -> PublicCredentialFields {
        PublicCredentialFields { system: 7, circuit_version: 1, global_epoch: 9, resource: 42, action_one_hot: 4, terminal_key: vec![3; 32] }
    }
    fn request(issuer: &Issuer, tq: u64, te: u64) -> RequestContext {
        RequestContext { current_header_digest: [1; 32], params_digest: issuer.params_digest().unwrap(), complete_q: b"canonical-Q16".to_vec(), verifier_nonce: b"nonce-1".to_vec(), tq, te }
    }

    #[test]
    fn positive_and_binding_negatives() {
        let mut rng = StdRng::seed_from_u64(11);
        let issuer = Issuer::generate(&mut rng);
        let prover = issuer.prover_params();
        let verifier = issuer.verifier_params();
        let credential = issuer.issue(&mut rng, public(), 100, 200).unwrap();
        let q = request(&issuer, 100, 200);
        let showing = present(&mut rng, &prover, &credential, &q).unwrap();
        assert!(!verify(&mut rng, &verifier, &public(), &q, &showing).unwrap().is_empty());
        let mut changed = q.clone(); changed.complete_q.push(0);
        assert!(verify(&mut rng, &verifier, &public(), &changed, &showing).is_err());
        let mut wrong_public = public(); wrong_public.global_epoch += 1;
        assert!(verify(&mut rng, &verifier, &wrong_public, &q, &showing).is_err());
    }

    #[test]
    fn rejects_interval_not_covered_by_one_credential() {
        let mut rng = StdRng::seed_from_u64(12);
        let issuer = Issuer::generate(&mut rng);
        let prover = issuer.prover_params();
        let verifier = issuer.verifier_params();
        for (lower, upper) in [(1, 5), (4, 10)] {
            let credential = issuer.issue(&mut rng, public(), lower, upper).unwrap();
            let q = request(&issuer, 2, 9);
            if let Ok(showing) = present(&mut rng, &prover, &credential, &q) {
                assert!(verify(&mut rng, &verifier, &public(), &q, &showing).is_err());
            }
        }
    }

    #[test]
    fn exact_u64_extremes() {
        let mut rng = StdRng::seed_from_u64(13);
        let issuer = Issuer::generate(&mut rng);
        let prover = issuer.prover_params();
        let verifier = issuer.verifier_params();
        let credential = issuer.issue(&mut rng, public(), 0, u64::MAX).unwrap();
        for (tq, te) in [(0, 0), (1u64 << 53, 1u64 << 53), (u64::MAX - 1, u64::MAX), (u64::MAX, u64::MAX)] {
            let q = request(&issuer, tq, te);
            let showing = present(&mut rng, &prover, &credential, &q).unwrap();
            verify(&mut rng, &verifier, &public(), &q, &showing).unwrap();
        }
    }
}
