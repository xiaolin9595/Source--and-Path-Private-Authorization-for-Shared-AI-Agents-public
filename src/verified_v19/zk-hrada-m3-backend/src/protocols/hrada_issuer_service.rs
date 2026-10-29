//! Local process-isolation fixture for issuer availability experiments.
//! Bootstrap secrets travel only over anonymous stdin pipes; never argv/files.
//! Parent still creates deterministic fixture keys; this is not remote key custody
//! or a secure-erasure claim. Each child receives exactly one original issuer key.
use crate::protocols::hrada_auth::{AuthFixture, Scheme, Sig};
use ark_crypto_primitives::{signature::schnorr::SecretKey, SignatureScheme};
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective, Fr as Scalar};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use std::{
    io::{Read, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::Duration,
};
const MAX_FRAME: usize = 4096;
fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}
fn enc<T: CanonicalSerialize>(v: &T) -> Vec<u8> {
    let mut b = vec![];
    v.serialize(&mut b).unwrap();
    b
}
fn write_frame(w: &mut impl Write, b: &[u8]) -> Result<(), String> {
    if b.len() > MAX_FRAME {
        return Err("oversized issuer frame".into());
    }
    w.write_all(&(b.len() as u32).to_le_bytes()).map_err(err)?;
    w.write_all(b).map_err(err)?;
    w.flush().map_err(err)
}
fn read_frame(r: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut n = [0; 4];
    r.read_exact(&mut n).map_err(err)?;
    let n = u32::from_le_bytes(n) as usize;
    if n > MAX_FRAME {
        return Err("oversized issuer frame".into());
    }
    let mut b = vec![0; n];
    r.read_exact(&mut b).map_err(err)?;
    Ok(b)
}
fn decode<T: CanonicalDeserialize>(b: &mut &[u8]) -> Result<T, String> {
    T::deserialize(b).map_err(err)
}
/// Main binaries must dispatch --issuer-child here before normal experiment work.
pub fn serve_child() -> Result<(), String> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut bootstrap = read_frame(&mut input)?;
    let mut cursor = bootstrap.as_slice();
    let generator: EdwardsAffine = decode(&mut cursor)?;
    let scalar: Scalar = decode(&mut cursor)?;
    if cursor.len() != 32 {
        return Err("invalid issuer bootstrap length".into());
    }
    let mut params = Scheme::setup(&mut OsRng).map_err(err)?;
    params.generator = generator;
    params.salt.copy_from_slice(cursor);
    let sk = SecretKey::<EdwardsProjective>(scalar);
    // Clear the transport buffer after parsing; allocator/compiler erasure is not promised.
    bootstrap.fill(0);
    use ark_ec::AffineCurve;
    let pk: EdwardsAffine = params.generator.mul(sk.0).into();
    write_frame(&mut output, &enc(&pk))?;
    loop {
        let request = read_frame(&mut input)?;
        if request.len() != 33 || request[0] != 1 {
            return Err("invalid issuer signing request".into());
        }
        let signature = Scheme::sign(&params, &sk, &request[1..], &mut OsRng).map_err(err)?;
        let mut bytes = enc(&signature.prover_response);
        bytes.extend(enc(&signature.verifier_challenge));
        write_frame(&mut output, &bytes)?;
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct IssuerCounters {
    pub issuer: usize,
    pub pid: u32,
    pub signing_requests: u64,
    pub verified_signatures: u64,
    pub health_signatures: u64,
    pub protocol_signatures: u64,
    pub offline_probe_attempts: u64,
    pub offline_io_rejections: u64,
    pub process_exit_confirmed: bool,
}
struct Issuer {
    child: Child,
    input: ChildStdin,
    responses: Receiver<Result<Vec<u8>, String>>,
    reader: Option<JoinHandle<()>>,
    counters: IssuerCounters,
}
impl Issuer {
    fn response(&self) -> Result<Vec<u8>, String> {
        self.responses
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "issuer response missing or timed out".to_string())?
    }
    fn request(&mut self, message: &[u8; 32]) -> Result<Sig, String> {
        self.counters.signing_requests += 1;
        let mut b = vec![1];
        b.extend(message);
        write_frame(&mut self.input, &b)?;
        let response = self.response()?;
        let mut cursor = response.as_slice();
        let prover_response = decode(&mut cursor)?;
        let verifier_challenge = decode(&mut cursor)?;
        if !cursor.is_empty() {
            return Err("issuer response trailing bytes".into());
        }
        Ok(Sig {
            prover_response,
            verifier_challenge,
        })
    }
    fn stop(&mut self) -> Result<(), String> {
        if self.child.try_wait().map_err(err)?.is_none() {
            self.child.kill().map_err(err)?;
        }
        self.child.wait().map_err(err)?;
        if self.child.try_wait().map_err(err)?.is_none() {
            return Err("issuer did not exit".into());
        }
        self.counters.process_exit_confirmed = true;
        self.counters.offline_probe_attempts += 1;
        if self.request(&[0xa5; 32]).is_ok() {
            return Err("terminated issuer unexpectedly signed".into());
        }
        self.counters.offline_io_rejections += 1;
        if let Some(reader) = self.reader.take() {
            reader
                .join()
                .map_err(|_| "issuer pipe reader panicked".to_string())?;
        }
        Ok(())
    }
}
impl Drop for Issuer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
    }
}
pub struct IssuerCluster {
    issuers: Vec<Issuer>,
    params: <Scheme as SignatureScheme>::Parameters,
    public_keys: Vec<EdwardsAffine>,
}
impl IssuerCluster {
    pub fn spawn(fixture: &AuthFixture) -> Result<Self, String> {
        if fixture.issuers_closed || fixture.keys.len() < 5 {
            return Err("issuer fixture keys unavailable".into());
        }
        let mut cluster = Self {
            issuers: vec![],
            params: fixture.base.params.clone(),
            public_keys: fixture.keys[..5].iter().map(|k| k.0).collect(),
        };
        for index in 0..5 {
            let mut child = Command::new(std::env::current_exe().map_err(err)?)
                .arg("--issuer-child")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(err)?;
            let input = child.stdin.take().ok_or("missing issuer stdin")?;
            let mut output = child.stdout.take().ok_or("missing issuer stdout")?;
            let (tx, rx) = mpsc::channel();
            let reader = thread::spawn(move || loop {
                let frame = read_frame(&mut output);
                let failed = frame.is_err();
                if tx.send(frame).is_err() || failed {
                    break;
                }
            });
            let pid = child.id();
            let issuer = Issuer {
                child,
                input,
                responses: rx,
                reader: Some(reader),
                counters: IssuerCounters {
                    issuer: index,
                    pid,
                    signing_requests: 0,
                    verified_signatures: 0,
                    health_signatures: 0,
                    protocol_signatures: 0,
                    offline_probe_attempts: 0,
                    offline_io_rejections: 0,
                    process_exit_confirmed: false,
                },
            };
            cluster.issuers.push(issuer);
            let issuer = cluster.issuers.last_mut().unwrap();
            let mut bootstrap = enc(&cluster.params.generator);
            bootstrap.extend(enc(&fixture.keys[index].1 .0));
            bootstrap.extend(cluster.params.salt);
            let sent = write_frame(&mut issuer.input, &bootstrap);
            bootstrap.fill(0);
            sent?;
            let ready = issuer.response()?;
            let mut cursor = ready.as_slice();
            let ready_pk: EdwardsAffine = decode(&mut cursor)?;
            if !cursor.is_empty() || ready_pk != cluster.public_keys[index] {
                return Err("issuer ready public key mismatch".into());
            }
        }
        let live = cluster.check_live()?;
        if !live.iter().all(|v| *v) {
            return Err("issuer bootstrap health check failed".into());
        }
        Ok(cluster)
    }
    /// Every live service signs a fresh random challenge; stopped services are
    /// checked against OS exit state and a real request/pipe failure, not a flag.
    pub fn check_live(&mut self) -> Result<Vec<bool>, String> {
        let mut out = vec![];
        for (i, issuer) in self.issuers.iter_mut().enumerate() {
            if issuer.child.try_wait().map_err(err)?.is_some() {
                issuer.counters.process_exit_confirmed = true;
                issuer.counters.offline_probe_attempts += 1;
                if issuer.request(&[0x5a; 32]).is_ok() {
                    return Err("exited issuer responded".into());
                }
                issuer.counters.offline_io_rejections += 1;
                out.push(false);
                continue;
            }
            let mut message = [0; 32];
            OsRng.fill_bytes(&mut message);
            let sig = issuer.request(&message)?;
            if !Scheme::verify(&self.params, &self.public_keys[i], &message, &sig).map_err(err)? {
                return Err("issuer health signature invalid".into());
            }
            issuer.counters.verified_signatures += 1;
            issuer.counters.health_signatures += 1;
            out.push(true);
        }
        Ok(out)
    }
    /// Sign a real grant core (or other protocol message) via the issuer process.
    pub fn sign(&mut self, index: usize, message: [u8; 32]) -> Result<Sig, String> {
        let issuer = self.issuers.get_mut(index).ok_or("invalid issuer index")?;
        let sig = issuer.request(&message)?;
        if !Scheme::verify(&self.params, &self.public_keys[index], &message, &sig).map_err(err)? {
            return Err("issuer protocol signature invalid".into());
        }
        issuer.counters.verified_signatures += 1;
        issuer.counters.protocol_signatures += 1;
        Ok(sig)
    }
    pub fn stop_one(&mut self, index: usize) -> Result<(), String> {
        self.issuers
            .get_mut(index)
            .ok_or("invalid issuer index")?
            .stop()
    }
    pub fn stop_all(&mut self) -> Result<(), String> {
        for issuer in &mut self.issuers {
            issuer.stop()?;
        }
        Ok(())
    }
    pub fn counters(&self) -> Vec<IssuerCounters> {
        self.issuers.iter().map(|i| i.counters.clone()).collect()
    }
}
