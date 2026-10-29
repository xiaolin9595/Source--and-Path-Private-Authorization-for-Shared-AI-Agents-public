use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderVersion {
    pub id: String,
    pub version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadTicket {
    header: HeaderVersion,
    nonce: Vec<u8>,
    not_before: u64,
    expiry: u64,
    artifact: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterError {
    UnauthenticatedArtifact,
    NonCanonicalTime,
    OutsideValidityWindow,
    MissingHeader,
    StaleHeader,
    NonMonotoneHeader,
    ArtifactChanged,
    NonceChanged,
    Replay,
}

/// In-memory deployment extension shared by the public JWT and UCAN profiles.
///
/// `authenticated` is a caller premise: JWT supplies an external terminal
/// Ed25519 proof plus JWS/business validation, while UCAN supplies validation
/// of its terminal-signed invocation. The adapter binds that result to exact
/// artifact bytes, nonce, clock interval and a monotonic Delta=0 header.
#[derive(Clone, Debug, Default)]
pub struct DeltaZeroAdapter {
    active_header: Option<HeaderVersion>,
    consumed_nonces: BTreeSet<Vec<u8>>,
}

impl DeltaZeroAdapter {
    pub fn install_header(&mut self, next: HeaderVersion) -> Result<(), AdapterError> {
        if let Some(current) = &self.active_header {
            if next.version <= current.version {
                return Err(AdapterError::NonMonotoneHeader);
            }
        }
        self.active_header = Some(next);
        Ok(())
    }

    pub fn verify_at_read(
        &self,
        authenticated: bool,
        header_id: &str,
        nonce: &[u8],
        not_before: u64,
        expiry: u64,
        artifact: &[u8],
        now: u64,
    ) -> Result<ReadTicket, AdapterError> {
        if !authenticated {
            return Err(AdapterError::UnauthenticatedArtifact);
        }
        if not_before > expiry {
            return Err(AdapterError::NonCanonicalTime);
        }
        if now < not_before || now > expiry {
            return Err(AdapterError::OutsideValidityWindow);
        }
        let active = self
            .active_header
            .as_ref()
            .ok_or(AdapterError::MissingHeader)?;
        if active.id != header_id {
            return Err(AdapterError::StaleHeader);
        }
        if self.consumed_nonces.contains(nonce) {
            return Err(AdapterError::Replay);
        }
        Ok(ReadTicket {
            header: active.clone(),
            nonce: nonce.to_vec(),
            not_before,
            expiry,
            artifact: artifact.to_vec(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit(
        &mut self,
        ticket: &ReadTicket,
        authenticated_now: bool,
        header_id: &str,
        nonce: &[u8],
        artifact: &[u8],
        now: u64,
    ) -> Result<(), AdapterError> {
        if !authenticated_now {
            return Err(AdapterError::UnauthenticatedArtifact);
        }
        if now < ticket.not_before || now > ticket.expiry {
            return Err(AdapterError::OutsideValidityWindow);
        }
        let active = self
            .active_header
            .as_ref()
            .ok_or(AdapterError::MissingHeader)?;
        if active != &ticket.header || active.id != header_id {
            return Err(AdapterError::StaleHeader);
        }
        if nonce != ticket.nonce.as_slice() {
            return Err(AdapterError::NonceChanged);
        }
        if artifact != ticket.artifact.as_slice() {
            return Err(AdapterError::ArtifactChanged);
        }
        if !self.consumed_nonces.insert(nonce.to_vec()) {
            return Err(AdapterError::Replay);
        }
        Ok(())
    }
}
