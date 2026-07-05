use alive_proto::{task, Task};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignError {
    #[error("invalid signing key length (want 32 bytes)")]
    KeyLen,
    #[error("invalid verify key")]
    VerifyKey,
}

/// The server's ed25519 identity: it signs every dispatched task, and agents
/// verify with the public half handed out at enrollment.
pub struct SigningIdentity {
    key: SigningKey,
}

impl SigningIdentity {
    /// Generate a fresh identity.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        Self {
            key: SigningKey::generate(&mut rng),
        }
    }

    /// 32-byte secret seed, for persisting to disk.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// 32-byte public verify key to hand to agents.
    pub fn verify_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

/// Reconstruct a signing identity from its 32-byte seed.
pub fn load_signing_key(seed: &[u8]) -> Result<SigningIdentity, SignError> {
    let arr: [u8; 32] = seed.try_into().map_err(|_| SignError::KeyLen)?;
    Ok(SigningIdentity {
        key: SigningKey::from_bytes(&arr),
    })
}

/// Sign `task` in place: computes the canonical bytes and stores the signature
/// on the task's `signature` field.
pub fn sign_task(identity: &SigningIdentity, task: &mut Task) {
    let bytes = canonical_task_bytes(task);
    let sig = identity.key.sign(&bytes);
    task.signature = sig.to_bytes().to_vec();
}

/// Verify a task's signature against the server's 32-byte verify key.
pub fn verify_task(verify_key: &[u8], task: &Task) -> bool {
    let vk = match verify_key_bytes(verify_key) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let sig_bytes: [u8; SIGNATURE_LENGTH] = match task.signature.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    vk.verify(&canonical_task_bytes(task), &sig).is_ok()
}

pub fn verify_key_bytes(bytes: &[u8]) -> Result<VerifyingKey, SignError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| SignError::VerifyKey)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| SignError::VerifyKey)
}

/// Deterministic byte encoding of a task for signing.
///
/// Excludes the `signature` field. Repeated string fields are sorted so the
/// encoding is stable regardless of the sender's field ordering. Format is a
/// series of length-prefixed fields — impl-independent, unlike raw protobuf.
pub fn canonical_task_bytes(task: &Task) -> Vec<u8> {
    let mut b = Vec::new();
    push_str(&mut b, &task.task_id);

    let mut scope = task.authorized_scope.clone();
    scope.sort();
    push_seq(&mut b, &scope);

    b.extend_from_slice(&task.issued_at.to_le_bytes());

    match &task.body {
        Some(task::Body::Scan(s)) => {
            b.push(1);
            let mut targets = s.targets.clone();
            targets.sort();
            push_seq(&mut b, &targets);
            let mut ids = s.template_ids.clone();
            ids.sort();
            push_seq(&mut b, &ids);
            push_str(&mut b, &s.ports);
        }
        Some(task::Body::Discover(d)) => {
            b.push(2);
            let mut targets = d.targets.clone();
            targets.sort();
            push_seq(&mut b, &targets);
            push_str(&mut b, &d.ports);
        }
        Some(task::Body::CollectInventory(_)) => {
            b.push(3);
        }
        None => b.push(0),
    }
    b
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn push_seq(buf: &mut Vec<u8>, items: &[String]) {
    buf.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for it in items {
        push_str(buf, it);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alive_proto::DiscoverTask;

    fn discover_task() -> Task {
        Task {
            task_id: "t1".into(),
            authorized_scope: vec!["127.0.0.1/32".into()],
            issued_at: 1_700_000_000,
            signature: vec![],
            body: Some(task::Body::Discover(DiscoverTask {
                targets: vec!["127.0.0.1".into()],
                ports: "80,443".into(),
            })),
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let id = SigningIdentity::generate();
        let vk = id.verify_key_bytes();
        let mut t = discover_task();
        sign_task(&id, &mut t);
        assert!(verify_task(&vk, &t));
    }

    #[test]
    fn tampered_task_is_rejected() {
        let id = SigningIdentity::generate();
        let vk = id.verify_key_bytes();
        let mut t = discover_task();
        sign_task(&id, &mut t);
        // mutate a field after signing
        if let Some(task::Body::Discover(d)) = &mut t.body {
            d.targets = vec!["10.0.0.1".into()];
        }
        assert!(!verify_task(&vk, &t));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let id = SigningIdentity::generate();
        let other = SigningIdentity::generate();
        let mut t = discover_task();
        sign_task(&id, &mut t);
        assert!(!verify_task(&other.verify_key_bytes(), &t));
    }

    #[test]
    fn canonical_bytes_are_order_independent() {
        let mut a = discover_task();
        a.authorized_scope = vec!["10.0.0.0/8".into(), "127.0.0.1/32".into()];
        let mut b = a.clone();
        b.authorized_scope = vec!["127.0.0.1/32".into(), "10.0.0.0/8".into()];
        assert_eq!(canonical_task_bytes(&a), canonical_task_bytes(&b));
    }

    #[test]
    fn round_trip_seed() {
        let id = SigningIdentity::generate();
        let seed = id.secret_bytes();
        let restored = load_signing_key(&seed).unwrap();
        assert_eq!(id.verify_key_bytes(), restored.verify_key_bytes());
    }
}
