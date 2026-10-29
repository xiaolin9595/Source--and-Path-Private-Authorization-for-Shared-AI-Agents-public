//! Shared canonical semantic input for matched Joint and DAC fixtures.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SEMANTIC_SCHEMA: &str = "plan-a-paired-semantic-records-v2";
pub const REQUEST_DIGEST_DOMAIN: &[u8] = b"plan-a-request-v1\0";
pub const HTTP_DIGEST_DOMAIN: &[u8] = b"plan-a-matched-http-v1\0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawGrant {
    pub id: String,
    pub issuer: u64,
    pub subject: u64,
    pub resource: u64,
    pub actions: u64,
    pub lo: u64,
    pub hi: u64,
    pub not_before: u64,
    pub expiry: u64,
    pub remaining_depth: u64,
    pub serial: [u64; 2],
    pub parent: Option<String>,
    pub schema_version: u64,
    pub policy_version: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub l_max: usize,
    pub ra_depth: usize,
    pub state_depth: usize,
    pub grant_depth: usize,
    pub revocation_depth: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogicalIds {
    pub owner: u64,
    pub delegate_a: u64,
    pub delegate_b: u64,
    pub terminal: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntitlementSpec {
    pub owner: u64,
    pub resource: u64,
    pub action_mask_u16: u64,
    pub interval_lo: u64,
    pub interval_hi: u64,
    pub permit_expiry: u64,
    pub admission_id_u128_le_limbs: [u64; 2],
    pub registration_salt_u128_le_limbs: [u64; 2],
    pub position: usize,
    pub visibility: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateSpec {
    pub owner: u64,
    pub state_expiry: u64,
    pub state_position: usize,
    pub state_salt_u128_le_limbs: [u64; 2],
    pub visibility: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestSpec {
    pub resource: u64,
    pub one_hot_action_u16: u64,
    pub interval_lo: u64,
    pub interval_hi: u64,
    pub now: u64,
    pub nonce_u64: u64,
    pub terminal: u64,
    pub policy_version: u64,
    pub schema_version: u64,
}

/// Exact service request bytes bound to the public request digest. Field order
/// is ASCII key order, so compact serde JSON is the canonical wire encoding.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CanonicalHttpRequest {
    pub audience: String,
    pub body_sha256: String,
    pub method: String,
    pub path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateSpec {
    pub tuple_version: u64,
    pub state_epoch: u64,
    pub revocation_epoch: u64,
    pub issued_at: u64,
    pub active_root_grants: Vec<String>,
    pub revoked_serials: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SemanticManifest {
    pub schema: String,
    pub profile: Profile,
    pub deployment_id: u64,
    pub logical_id_mapping_version: u64,
    pub policy_version: u64,
    pub schema_version: u64,
    pub logical_ids: LogicalIds,
    pub entitlement: EntitlementSpec,
    pub state: StateSpec,
    pub grants: Vec<RawGrant>,
    pub request: RequestSpec,
    pub updates: Vec<UpdateSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoundMetadata {
    pub schema: String,
    pub profile: Profile,
    pub deployment_id: u64,
    pub logical_id_mapping_version: u64,
    pub policy_version: u64,
    pub schema_version: u64,
    pub entitlement_visibility: String,
    pub state_visibility: String,
}

pub fn canonical_bytes(manifest: &SemanticManifest) -> Vec<u8> {
    serde_json::to_vec(manifest).expect("semantic manifest serialization")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn manifest_sha256(manifest: &SemanticManifest) -> String {
    sha256_hex(&canonical_bytes(manifest))
}

pub fn bound_metadata(manifest: &SemanticManifest) -> BoundMetadata {
    BoundMetadata {
        schema: manifest.schema.clone(),
        profile: manifest.profile.clone(),
        deployment_id: manifest.deployment_id,
        logical_id_mapping_version: manifest.logical_id_mapping_version,
        policy_version: manifest.policy_version,
        schema_version: manifest.schema_version,
        entitlement_visibility: manifest.entitlement.visibility.clone(),
        state_visibility: manifest.state.visibility.clone(),
    }
}

fn digest_limbs(digest: &[u8]) -> [u64; 4] {
    std::array::from_fn(|index| {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&digest[index * 8..(index + 1) * 8]);
        u64::from_le_bytes(limb)
    })
}

pub fn metadata_digest_limbs(metadata: &BoundMetadata) -> [u64; 4] {
    digest_limbs(&Sha256::digest(
        serde_json::to_vec(metadata).expect("bound metadata serialization"),
    ))
}

pub fn request_digest_limbs(request: &RequestSpec) -> [u64; 4] {
    let mut bytes = REQUEST_DIGEST_DOMAIN.to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(request).expect("request serialization"));
    digest_limbs(&Sha256::digest(bytes))
}

pub fn canonical_http_bytes(http: &CanonicalHttpRequest) -> Result<Vec<u8>, &'static str> {
    if http.body_sha256.len() != 64
        || !http
            .body_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("body_sha256 must be 64 lowercase hexadecimal characters");
    }
    if http.audience.is_empty()
        || http.method.is_empty()
        || http.path.is_empty()
        || !http.method.bytes().all(|byte| byte.is_ascii_uppercase())
        || !http
            .audience
            .bytes()
            .chain(http.method.bytes())
            .chain(http.path.bytes())
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
    {
        return Err("HTTP audience/method/path must be nonempty canonical ASCII");
    }
    serde_json::to_vec(http).map_err(|_| "HTTP request serialization failed")
}

pub fn canonical_http_sha256(http: &CanonicalHttpRequest) -> Result<String, &'static str> {
    let mut bytes = HTTP_DIGEST_DOMAIN.to_vec();
    bytes.extend_from_slice(&canonical_http_bytes(http)?);
    Ok(sha256_hex(&bytes))
}

pub fn canonical_http_digest_limbs(http: &CanonicalHttpRequest) -> Result<[u64; 4], &'static str> {
    let mut bytes = HTTP_DIGEST_DOMAIN.to_vec();
    bytes.extend_from_slice(&canonical_http_bytes(http)?);
    Ok(digest_limbs(&Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::{canonical_http_digest_limbs, canonical_http_sha256, CanonicalHttpRequest};

    #[test]
    fn canonical_http_digest_matches_external_fixed_vector() {
        let http = CanonicalHttpRequest {
            audience: "https://matched.service.example".to_owned(),
            body_sha256: "558eab51aa7f1d1fb8e8473aee23b12a66897b5597adaf20a7e11c3566adadd8"
                .to_owned(),
            method: "POST".to_owned(),
            path: "/resource/read".to_owned(),
        };
        let expected = "fbd19add4b0710eb667a353850369197be3d504c8c1fc1585706e8bf61475c42";
        assert_eq!(canonical_http_sha256(&http).unwrap(), expected);

        let expected_limbs = [
            16_938_046_220_962_288_123,
            10_921_570_289_518_475_878,
            6_395_427_633_279_024_574,
            4_781_775_389_517_678_167,
        ];
        assert_eq!(canonical_http_digest_limbs(&http).unwrap(), expected_limbs);
    }
}
