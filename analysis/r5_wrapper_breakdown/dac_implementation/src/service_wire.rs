//! Canonical public service envelope for the fixed-policy wrapper.
//!
//! This module exports the exact statement, Groth16 proof, verifying key,
//! signed header and terminal signature needed by a runtime-owned service
//! adapter. It contains no witness, issuer secret, accumulator-manager secret,
//! proving key or CRS trapdoor. All curve and field values use arkworks 0.4
//! canonical compressed encoding represented as lowercase hexadecimal.

use crate::{
    fixed_policy::FixedPolicyStatement,
    semantic_schema::{
        bound_metadata, canonical_http_digest_limbs, manifest_sha256, metadata_digest_limbs,
        CanonicalHttpRequest, Profile, SemanticManifest,
    },
    service_adapter::{AdapterError, DeltaZeroAdapter, SchnorrSignature},
};
use ark_bls12_377::{Fq, G1Affine};
use ark_bw6_761::BW6_761;
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use thiserror::Error;

pub const SERVICE_ENVELOPE_SCHEMA: &str = "plan-a-dac-fixed-policy-service-envelope-v1";
pub const TRUSTED_CONFIG_SCHEMA: &str = "plan-a-dac-resident-trusted-config-v1";
pub const HEADER_ENVELOPE_SCHEMA: &str = "plan-a-dac-header-envelope-v1";
pub const RESIDENT_PROOF_SCHEMA: &str = "plan-a-dac-resident-proof-envelope-v1";

#[derive(Debug, Error)]
pub enum ServiceWireError {
    #[error("invalid hex for {0}")]
    InvalidHex(&'static str),
    #[error("noncanonical or trailing bytes for {0}")]
    InvalidCanonicalEncoding(&'static str),
    #[error("service envelope schema mismatch")]
    SchemaMismatch,
    #[error("proof digest mismatch")]
    ProofDigestMismatch,
    #[error("semantic input hash is not canonical lowercase SHA-256")]
    InvalidSemanticInputHash,
    #[error("semantic update index is out of range")]
    UpdateIndex,
    #[error("canonical HTTP request is invalid")]
    InvalidCanonicalHttp,
    #[error("statement does not equal the independently derived expected service request")]
    StatementBindingMismatch,
    #[error("trusted deployment configuration mismatch")]
    TrustedConfigurationMismatch,
    #[error("adapter rejected the envelope: {0:?}")]
    Adapter(AdapterError),
}

impl From<AdapterError> for ServiceWireError {
    fn from(value: AdapterError) -> Self {
        Self::Adapter(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FixedPolicyStatementWire {
    pub deployment_id: String,
    pub tuple_version: u64,
    pub ra_root: String,
    pub state_root: String,
    pub state_epoch: u64,
    pub revocation_epoch: u64,
    pub issued_at: u64,
    pub mapping_version: u64,
    pub header_digest: String,
    pub canonical_request_lo: [u64; 2],
    pub canonical_request_hi: [u64; 2],
    pub circuit_id: String,
    pub verifier_id: String,
    pub pep_id: String,
    pub nonce: String,
    pub context: String,
    pub request_digest: String,
    pub terminal: u64,
    pub terminal_key: String,
    pub resource: u64,
    pub one_hot_action: u64,
    pub request_lo: u64,
    pub request_hi: u64,
    pub now: u64,
    pub policy_version: u64,
    pub schema_version: u64,
    pub accumulator_value: String,
}

/// Public request values that the service must derive from its trusted route,
/// body, installed policy and clock before accepting an envelope. Callers must
/// not build this value by copying the untrusted envelope.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedServiceRequest {
    pub semantic_input_sha256: String,
    pub backend: String,
    pub deployment_id: u64,
    pub logical_id_mapping_version: u64,
    pub policy_version: u64,
    pub schema_version: u64,
    pub profile: Profile,
    pub update_index: usize,
    pub installed_header: DacInstalledHeader,
    pub terminal: u64,
    pub terminal_key: String,
    pub resource: u64,
    pub one_hot_action_u16: u64,
    pub interval_lo: u64,
    pub interval_hi: u64,
    pub nonce_u64: u64,
    pub trusted_now: u64,
    pub http: CanonicalHttpRequest,
    pub backend_profile: serde_json::Value,
}

/// The exact installed DAC header returned by `materialize-and-verify-header`.
/// It contains only authenticated public snapshot fields and the canonical
/// semantic-input identifier expected by the shared Python service.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DacInstalledHeader {
    pub semantic_input_sha256: String,
    pub deployment_id: String,
    pub tuple_version: u64,
    pub ra_root: String,
    pub state_root: String,
    pub state_epoch: u64,
    pub revocation_epoch: u64,
    pub issued_at: u64,
    pub mapping_version: u64,
    pub header_digest: String,
    pub accumulator_value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchnorrSignatureWire {
    pub r: String,
    pub s: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceEnvelope {
    pub schema: String,
    pub semantic_input_sha256: String,
    pub relation_version: u64,
    pub statement: FixedPolicyStatementWire,
    pub generator: String,
    pub registry_public_key: String,
    pub verifying_key: String,
    pub proof: String,
    pub proof_blake2s: String,
    pub header_signature: SchnorrSignatureWire,
    pub terminal_signature: SchnorrSignatureWire,
}

/// Written by the trusted fixture producer and loaded once when the resident
/// verifier starts. It is never accepted inside an untrusted request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustedDacConfigWire {
    pub schema: String,
    pub semantic_input_sha256: String,
    pub relation_version: u64,
    pub deployment_id: String,
    pub generator: String,
    pub registry_public_key: String,
    pub verifying_key: String,
    pub verifying_key_sha256: String,
    pub trusted_statements: Vec<FixedPolicyStatementWire>,
    pub backend_profile: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeaderEnvelope {
    pub header: DacInstalledHeader,
    pub registry_signature: String,
}

/// Caller supplied proof material. Verification parameters are deliberately
/// absent and come only from `TrustedDacConfigWire`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResidentProofEnvelope {
    pub schema: String,
    pub semantic_input_sha256: String,
    pub update_index: usize,
    pub relation_version: u64,
    pub statement: FixedPolicyStatementWire,
    pub proof: String,
    pub proof_blake2s: String,
    pub terminal_signature: String,
}

/// Exact JSON-lines command schema shared with `matched_service.py`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ResidentCommand {
    MaterializeAndVerifyHeader {
        canonical_manifest: SemanticManifest,
        semantic_input_sha256: String,
        update_index: u64,
        header_envelope: HeaderEnvelope,
        backend_profile: serde_json::Value,
    },
    VerifyAtRead {
        canonical_manifest: SemanticManifest,
        expected: ExpectedServiceRequest,
        envelope: ResidentProofEnvelope,
    },
    Commit {
        canonical_manifest: SemanticManifest,
        expected: ExpectedServiceRequest,
        envelope: ResidentProofEnvelope,
        ticket: String,
    },
}

impl ResidentCommand {
    pub fn name(&self) -> &'static str {
        match self {
            Self::MaterializeAndVerifyHeader { .. } => "materialize-and-verify-header",
            Self::VerifyAtRead { .. } => "verify-at-read",
            Self::Commit { .. } => "commit",
        }
    }
}

pub struct TrustedDacConfig {
    pub semantic_input_sha256: String,
    pub relation_version: u64,
    pub deployment_id: Fq,
    pub generator: G1Affine,
    pub registry_public_key: G1Affine,
    pub verifying_key: VerifyingKey<BW6_761>,
    pub trusted_statements: Vec<FixedPolicyStatement>,
    pub backend_profile: serde_json::Value,
}

pub struct DecodedHeaderEnvelope {
    pub semantic_input_sha256: String,
    pub statement: FixedPolicyStatement,
    pub registry_signature: SchnorrSignature,
}

pub struct DecodedResidentProofEnvelope {
    pub semantic_input_sha256: String,
    pub relation_version: u64,
    pub statement: FixedPolicyStatement,
    pub proof: Proof<BW6_761>,
    pub proof_bytes: Vec<u8>,
    pub terminal_signature: SchnorrSignature,
}

pub struct DecodedServiceEnvelope {
    pub semantic_input_sha256: String,
    pub relation_version: u64,
    pub statement: FixedPolicyStatement,
    pub generator: G1Affine,
    pub registry_public_key: G1Affine,
    pub verifying_key: VerifyingKey<BW6_761>,
    pub proof: Proof<BW6_761>,
    pub proof_bytes: Vec<u8>,
    pub header_signature: SchnorrSignature,
    pub terminal_signature: SchnorrSignature,
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(label: &'static str, encoded: &str) -> Result<Vec<u8>, ServiceWireError> {
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }

    let bytes = encoded.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(ServiceWireError::InvalidHex(label));
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let high = nibble(pair[0]).ok_or(ServiceWireError::InvalidHex(label))?;
            let low = nibble(pair[1]).ok_or(ServiceWireError::InvalidHex(label))?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn canonical_hex<T: CanonicalSerialize>(value: &T) -> String {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .expect("serialization into Vec cannot fail");
    encode_hex(&bytes)
}

fn decode_canonical<T: CanonicalDeserialize>(
    label: &'static str,
    encoded: &str,
) -> Result<T, ServiceWireError> {
    let bytes = decode_hex(label, encoded)?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let value = T::deserialize_compressed(&mut cursor)
        .map_err(|_| ServiceWireError::InvalidCanonicalEncoding(label))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(ServiceWireError::InvalidCanonicalEncoding(label));
    }
    Ok(value)
}

fn proof_digest(bytes: &[u8]) -> String {
    let digest = Blake2s256::digest(bytes);
    encode_hex(digest.as_slice())
}

fn signature_hex(signature: &SchnorrSignature) -> String {
    let mut bytes = Vec::new();
    signature
        .r
        .serialize_compressed(&mut bytes)
        .expect("serialization into Vec cannot fail");
    signature
        .s
        .serialize_compressed(&mut bytes)
        .expect("serialization into Vec cannot fail");
    encode_hex(&bytes)
}

fn decode_signature_hex(
    label: &'static str,
    encoded: &str,
) -> Result<SchnorrSignature, ServiceWireError> {
    let bytes = decode_hex(label, encoded)?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let r = G1Affine::deserialize_compressed(&mut cursor)
        .map_err(|_| ServiceWireError::InvalidCanonicalEncoding(label))?;
    let s = ark_bls12_377::Fr::deserialize_compressed(&mut cursor)
        .map_err(|_| ServiceWireError::InvalidCanonicalEncoding(label))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(ServiceWireError::InvalidCanonicalEncoding(label));
    }
    Ok(SchnorrSignature { r, s })
}

impl FixedPolicyStatementWire {
    pub fn from_statement(statement: &FixedPolicyStatement) -> Self {
        Self {
            deployment_id: canonical_hex(&statement.deployment_id),
            tuple_version: statement.tuple_version,
            ra_root: canonical_hex(&statement.ra_root),
            state_root: canonical_hex(&statement.state_root),
            state_epoch: statement.state_epoch,
            revocation_epoch: statement.revocation_epoch,
            issued_at: statement.issued_at,
            mapping_version: statement.mapping_version,
            header_digest: canonical_hex(&statement.header_digest),
            canonical_request_lo: statement.canonical_request_lo,
            canonical_request_hi: statement.canonical_request_hi,
            circuit_id: canonical_hex(&statement.circuit_id),
            verifier_id: canonical_hex(&statement.verifier_id),
            pep_id: canonical_hex(&statement.pep_id),
            nonce: canonical_hex(&statement.nonce),
            context: canonical_hex(&statement.context),
            request_digest: canonical_hex(&statement.request_digest),
            terminal: statement.terminal,
            terminal_key: canonical_hex(&statement.terminal_key),
            resource: statement.resource,
            one_hot_action: statement.one_hot_action,
            request_lo: statement.request_lo,
            request_hi: statement.request_hi,
            now: statement.now,
            policy_version: statement.policy_version,
            schema_version: statement.schema_version,
            accumulator_value: canonical_hex(&statement.accumulator_value),
        }
    }

    pub fn decode(&self) -> Result<FixedPolicyStatement, ServiceWireError> {
        Ok(FixedPolicyStatement {
            deployment_id: decode_canonical("statement.deployment_id", &self.deployment_id)?,
            tuple_version: self.tuple_version,
            ra_root: decode_canonical("statement.ra_root", &self.ra_root)?,
            state_root: decode_canonical("statement.state_root", &self.state_root)?,
            state_epoch: self.state_epoch,
            revocation_epoch: self.revocation_epoch,
            issued_at: self.issued_at,
            mapping_version: self.mapping_version,
            header_digest: decode_canonical("statement.header_digest", &self.header_digest)?,
            canonical_request_lo: self.canonical_request_lo,
            canonical_request_hi: self.canonical_request_hi,
            circuit_id: decode_canonical("statement.circuit_id", &self.circuit_id)?,
            verifier_id: decode_canonical("statement.verifier_id", &self.verifier_id)?,
            pep_id: decode_canonical("statement.pep_id", &self.pep_id)?,
            nonce: decode_canonical("statement.nonce", &self.nonce)?,
            context: decode_canonical("statement.context", &self.context)?,
            request_digest: decode_canonical("statement.request_digest", &self.request_digest)?,
            terminal: self.terminal,
            terminal_key: decode_canonical("statement.terminal_key", &self.terminal_key)?,
            resource: self.resource,
            one_hot_action: self.one_hot_action,
            request_lo: self.request_lo,
            request_hi: self.request_hi,
            now: self.now,
            policy_version: self.policy_version,
            schema_version: self.schema_version,
            accumulator_value: decode_canonical(
                "statement.accumulator_value",
                &self.accumulator_value,
            )?,
        })
    }
}

impl ExpectedServiceRequest {
    /// Build the service-owned expected request from the canonical parsed raw
    /// object, one trusted installed update, and the authenticated backend
    /// mapping of the logical terminal to its DAC public key.
    pub fn from_semantic_manifest(
        manifest: &SemanticManifest,
        update_index: usize,
        terminal_key: G1Affine,
        canonical_http: CanonicalHttpRequest,
        trusted_now: u64,
        installed_header: DacInstalledHeader,
        backend_profile: serde_json::Value,
    ) -> Result<Self, ServiceWireError> {
        manifest
            .updates
            .get(update_index)
            .ok_or(ServiceWireError::UpdateIndex)?;
        canonical_http_digest_limbs(&canonical_http)
            .map_err(|_| ServiceWireError::InvalidCanonicalHttp)?;
        Ok(Self {
            semantic_input_sha256: manifest_sha256(manifest),
            backend: "dac-bw6-761".to_owned(),
            deployment_id: manifest.deployment_id,
            logical_id_mapping_version: manifest.logical_id_mapping_version,
            policy_version: manifest.policy_version,
            schema_version: manifest.schema_version,
            profile: manifest.profile.clone(),
            update_index,
            installed_header,
            terminal: manifest.request.terminal,
            terminal_key: canonical_hex(&terminal_key),
            resource: manifest.request.resource,
            one_hot_action_u16: manifest.request.one_hot_action_u16,
            interval_lo: manifest.request.interval_lo,
            interval_hi: manifest.request.interval_hi,
            nonce_u64: manifest.request.nonce_u64,
            trusted_now,
            http: canonical_http,
            backend_profile,
        })
    }

    /// Check the exact Python service schema against the canonical manifest,
    /// resident profile, installed header and proof statement.  The service
    /// creates this object from trusted state; no field is copied from the
    /// caller's proof envelope.
    pub fn matches_statement(
        &self,
        manifest: &SemanticManifest,
        backend_profile: &serde_json::Value,
        statement: &FixedPolicyStatement,
    ) -> bool {
        let Some(update) = manifest.updates.get(self.update_index) else {
            return false;
        };
        let Ok(limbs) = canonical_http_digest_limbs(&self.http) else {
            return false;
        };
        let metadata_limbs = metadata_digest_limbs(&bound_metadata(manifest));
        self.semantic_input_sha256 == manifest_sha256(manifest)
            && self.backend == "dac-bw6-761"
            && self.deployment_id == manifest.deployment_id
            && self.logical_id_mapping_version == manifest.logical_id_mapping_version
            && self.policy_version == manifest.policy_version
            && self.schema_version == manifest.schema_version
            && self.profile == manifest.profile
            && self.backend_profile == *backend_profile
            && self.installed_header
                == DacInstalledHeader::from_statement(self.semantic_input_sha256.clone(), statement)
            && self.installed_header.tuple_version == update.tuple_version
            && self.installed_header.state_epoch == update.state_epoch
            && self.installed_header.revocation_epoch == update.revocation_epoch
            && self.installed_header.issued_at == update.issued_at
            && statement.deployment_id == Fq::from(manifest.deployment_id)
            && statement.mapping_version == manifest.logical_id_mapping_version
            && statement.canonical_request_lo == [limbs[0], limbs[1]]
            && statement.canonical_request_hi == [limbs[2], limbs[3]]
            && statement.circuit_id == Fq::from(metadata_limbs[0])
            && statement.verifier_id == Fq::from(metadata_limbs[1])
            && statement.pep_id == Fq::from(metadata_limbs[2])
            && statement.context == Fq::from(metadata_limbs[3])
            && statement.nonce == Fq::from(self.nonce_u64)
            && statement.terminal == self.terminal
            && canonical_hex(&statement.terminal_key) == self.terminal_key
            && statement.resource == self.resource
            && statement.one_hot_action == self.one_hot_action_u16
            && statement.request_lo == self.interval_lo
            && statement.request_hi == self.interval_hi
            && statement.now == self.trusted_now
            && statement.policy_version == self.policy_version
            && statement.schema_version == self.schema_version
            && self.interval_lo <= self.trusted_now
            && self.trusted_now <= self.interval_hi
    }

    /// Narrow compatibility check for the legacy in-process adapter CLI.
    /// The resident verifier additionally calls `matches_statement`, which
    /// binds every manifest and deployment field.
    pub fn matches_public_statement(&self, statement: &FixedPolicyStatement) -> bool {
        let Ok(limbs) = canonical_http_digest_limbs(&self.http) else {
            return false;
        };
        self.installed_header
            == DacInstalledHeader::from_statement(self.semantic_input_sha256.clone(), statement)
            && statement.deployment_id == Fq::from(self.deployment_id)
            && statement.mapping_version == self.logical_id_mapping_version
            && statement.canonical_request_lo == [limbs[0], limbs[1]]
            && statement.canonical_request_hi == [limbs[2], limbs[3]]
            && statement.nonce == Fq::from(self.nonce_u64)
            && statement.terminal == self.terminal
            && canonical_hex(&statement.terminal_key) == self.terminal_key
            && statement.resource == self.resource
            && statement.one_hot_action == self.one_hot_action_u16
            && statement.request_lo == self.interval_lo
            && statement.request_hi == self.interval_hi
            && statement.now == self.trusted_now
            && statement.policy_version == self.policy_version
            && statement.schema_version == self.schema_version
    }
}

impl DacInstalledHeader {
    pub fn from_statement(semantic_input_sha256: String, statement: &FixedPolicyStatement) -> Self {
        Self {
            semantic_input_sha256,
            deployment_id: canonical_hex(&statement.deployment_id),
            tuple_version: statement.tuple_version,
            ra_root: canonical_hex(&statement.ra_root),
            state_root: canonical_hex(&statement.state_root),
            state_epoch: statement.state_epoch,
            revocation_epoch: statement.revocation_epoch,
            issued_at: statement.issued_at,
            mapping_version: statement.mapping_version,
            header_digest: canonical_hex(&statement.header_digest),
            accumulator_value: canonical_hex(&statement.accumulator_value),
        }
    }
}

impl SchnorrSignatureWire {
    fn from_signature(signature: &SchnorrSignature) -> Self {
        Self {
            r: canonical_hex(&signature.r),
            s: canonical_hex(&signature.s),
        }
    }

    fn decode(&self, label: &'static str) -> Result<SchnorrSignature, ServiceWireError> {
        let r_label = if label == "header" {
            "header_signature.r"
        } else {
            "terminal_signature.r"
        };
        let s_label = if label == "header" {
            "header_signature.s"
        } else {
            "terminal_signature.s"
        };
        Ok(SchnorrSignature {
            r: decode_canonical(r_label, &self.r)?,
            s: decode_canonical(s_label, &self.s)?,
        })
    }
}

impl TrustedDacConfigWire {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        semantic_input_sha256: String,
        relation_version: u64,
        statements: &[FixedPolicyStatement],
        generator: &G1Affine,
        registry_public_key: &G1Affine,
        verifying_key: &VerifyingKey<BW6_761>,
        backend_profile: serde_json::Value,
    ) -> Self {
        let statement = statements.first().expect("at least one trusted statement");
        let verifying_key_hex = canonical_hex(verifying_key);
        let verifying_key_bytes = decode_hex("verifying_key", &verifying_key_hex)
            .expect("locally encoded verifying key is hex");
        Self {
            schema: TRUSTED_CONFIG_SCHEMA.to_owned(),
            semantic_input_sha256,
            relation_version,
            deployment_id: canonical_hex(&statement.deployment_id),
            generator: canonical_hex(generator),
            registry_public_key: canonical_hex(registry_public_key),
            verifying_key: verifying_key_hex,
            verifying_key_sha256: crate::semantic_schema::sha256_hex(&verifying_key_bytes),
            trusted_statements: statements
                .iter()
                .map(FixedPolicyStatementWire::from_statement)
                .collect(),
            backend_profile,
        }
    }

    pub fn decode(&self) -> Result<TrustedDacConfig, ServiceWireError> {
        if self.schema != TRUSTED_CONFIG_SCHEMA {
            return Err(ServiceWireError::SchemaMismatch);
        }
        if decode_hex("semantic_input_sha256", &self.semantic_input_sha256)?.len() != 32 {
            return Err(ServiceWireError::InvalidSemanticInputHash);
        }
        let verifying_key_bytes = decode_hex("verifying_key", &self.verifying_key)?;
        if crate::semantic_schema::sha256_hex(&verifying_key_bytes) != self.verifying_key_sha256 {
            return Err(ServiceWireError::TrustedConfigurationMismatch);
        }
        let trusted_statements = self
            .trusted_statements
            .iter()
            .map(FixedPolicyStatementWire::decode)
            .collect::<Result<Vec<_>, _>>()?;
        let deployment_id = decode_canonical("deployment_id", &self.deployment_id)?;
        if trusted_statements.is_empty()
            || trusted_statements
                .iter()
                .any(|statement| statement.deployment_id != deployment_id)
        {
            return Err(ServiceWireError::TrustedConfigurationMismatch);
        }
        Ok(TrustedDacConfig {
            semantic_input_sha256: self.semantic_input_sha256.clone(),
            relation_version: self.relation_version,
            deployment_id,
            generator: decode_canonical("generator", &self.generator)?,
            registry_public_key: decode_canonical(
                "registry_public_key",
                &self.registry_public_key,
            )?,
            verifying_key: decode_canonical("verifying_key", &self.verifying_key)?,
            trusted_statements,
            backend_profile: self.backend_profile.clone(),
        })
    }
}

impl HeaderEnvelope {
    pub fn new(
        semantic_input_sha256: String,
        statement: &FixedPolicyStatement,
        registry_signature: &SchnorrSignature,
    ) -> Self {
        Self {
            header: DacInstalledHeader::from_statement(semantic_input_sha256, statement),
            registry_signature: signature_hex(registry_signature),
        }
    }

    pub fn decode(
        &self,
        statement: &FixedPolicyStatementWire,
    ) -> Result<DecodedHeaderEnvelope, ServiceWireError> {
        if decode_hex("semantic_input_sha256", &self.header.semantic_input_sha256)?.len() != 32 {
            return Err(ServiceWireError::InvalidSemanticInputHash);
        }
        Ok(DecodedHeaderEnvelope {
            semantic_input_sha256: self.header.semantic_input_sha256.clone(),
            statement: statement.decode()?,
            registry_signature: decode_signature_hex(
                "registry_signature",
                &self.registry_signature,
            )?,
        })
    }
}

impl ResidentProofEnvelope {
    pub fn new(
        semantic_input_sha256: String,
        update_index: usize,
        relation_version: u64,
        statement: &FixedPolicyStatement,
        proof: &Proof<BW6_761>,
        terminal_signature: &SchnorrSignature,
    ) -> Self {
        let proof_hex = canonical_hex(proof);
        let proof_bytes = decode_hex("proof", &proof_hex).expect("locally encoded proof is hex");
        Self {
            schema: RESIDENT_PROOF_SCHEMA.to_owned(),
            semantic_input_sha256,
            update_index,
            relation_version,
            statement: FixedPolicyStatementWire::from_statement(statement),
            proof: proof_hex,
            proof_blake2s: proof_digest(&proof_bytes),
            terminal_signature: signature_hex(terminal_signature),
        }
    }

    pub fn decode(&self) -> Result<DecodedResidentProofEnvelope, ServiceWireError> {
        if self.schema != RESIDENT_PROOF_SCHEMA {
            return Err(ServiceWireError::SchemaMismatch);
        }
        if decode_hex("semantic_input_sha256", &self.semantic_input_sha256)?.len() != 32 {
            return Err(ServiceWireError::InvalidSemanticInputHash);
        }
        let proof_bytes = decode_hex("proof", &self.proof)?;
        if proof_digest(&proof_bytes) != self.proof_blake2s {
            return Err(ServiceWireError::ProofDigestMismatch);
        }
        Ok(DecodedResidentProofEnvelope {
            semantic_input_sha256: self.semantic_input_sha256.clone(),
            relation_version: self.relation_version,
            statement: self.statement.decode()?,
            proof: decode_canonical("proof", &self.proof)?,
            proof_bytes,
            terminal_signature: decode_signature_hex(
                "terminal_signature",
                &self.terminal_signature,
            )?,
        })
    }
}

impl ServiceEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        semantic_input_sha256: String,
        relation_version: u64,
        statement: &FixedPolicyStatement,
        generator: &G1Affine,
        registry_public_key: &G1Affine,
        verifying_key: &VerifyingKey<BW6_761>,
        proof: &Proof<BW6_761>,
        header_signature: &SchnorrSignature,
        terminal_signature: &SchnorrSignature,
    ) -> Self {
        let proof_hex = canonical_hex(proof);
        let proof_bytes = decode_hex("proof", &proof_hex).expect("locally encoded proof is hex");
        Self {
            schema: SERVICE_ENVELOPE_SCHEMA.to_owned(),
            semantic_input_sha256,
            relation_version,
            statement: FixedPolicyStatementWire::from_statement(statement),
            generator: canonical_hex(generator),
            registry_public_key: canonical_hex(registry_public_key),
            verifying_key: canonical_hex(verifying_key),
            proof: proof_hex,
            proof_blake2s: proof_digest(&proof_bytes),
            header_signature: SchnorrSignatureWire::from_signature(header_signature),
            terminal_signature: SchnorrSignatureWire::from_signature(terminal_signature),
        }
    }

    pub fn decode(&self) -> Result<DecodedServiceEnvelope, ServiceWireError> {
        if self.schema != SERVICE_ENVELOPE_SCHEMA {
            return Err(ServiceWireError::SchemaMismatch);
        }
        let semantic_hash = decode_hex("semantic_input_sha256", &self.semantic_input_sha256)?;
        if semantic_hash.len() != 32 {
            return Err(ServiceWireError::InvalidSemanticInputHash);
        }
        let proof_bytes = decode_hex("proof", &self.proof)?;
        if proof_digest(&proof_bytes) != self.proof_blake2s {
            return Err(ServiceWireError::ProofDigestMismatch);
        }
        Ok(DecodedServiceEnvelope {
            semantic_input_sha256: self.semantic_input_sha256.clone(),
            relation_version: self.relation_version,
            statement: self.statement.decode()?,
            generator: decode_canonical("generator", &self.generator)?,
            registry_public_key: decode_canonical(
                "registry_public_key",
                &self.registry_public_key,
            )?,
            verifying_key: decode_canonical("verifying_key", &self.verifying_key)?,
            proof: decode_canonical("proof", &self.proof)?,
            proof_bytes,
            header_signature: self.header_signature.decode("header")?,
            terminal_signature: self.terminal_signature.decode("terminal")?,
        })
    }
}

impl DecodedServiceEnvelope {
    /// Verify and commit with a service-owned, long-lived adapter. The caller
    /// must construct `adapter` from trusted deployment configuration rather
    /// than from the untrusted envelope's generator or registry key.
    pub fn verify_and_commit_with_adapter(
        &self,
        adapter: &mut DeltaZeroAdapter,
        expected: &ExpectedServiceRequest,
        trusted_now: u64,
    ) -> Result<(), ServiceWireError> {
        if expected.semantic_input_sha256 != self.semantic_input_sha256
            || !expected.matches_public_statement(&self.statement)
        {
            return Err(ServiceWireError::StatementBindingMismatch);
        }
        adapter.install_header(&self.statement, &self.header_signature)?;
        let ticket = adapter.verify_at_read(
            &self.verifying_key,
            &self.statement,
            self.relation_version,
            &self.proof,
            &self.proof_bytes,
            &self.terminal_signature,
        )?;
        adapter.commit(
            &ticket,
            &self.statement,
            self.relation_version,
            &self.proof_bytes,
            &self.terminal_signature,
            trusted_now,
        )?;
        Ok(())
    }
}
