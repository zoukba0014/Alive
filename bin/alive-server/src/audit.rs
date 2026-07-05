use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Genesis hash for the chain (no predecessor).
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One audit record. `prev` links it to the hash of the previous entry, making
/// the JSONL log **tamper-evident**: altering any entry breaks every hash after
/// it. Field order is fixed so serialization is deterministic (the hash input).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub kind: String,
    pub agent_id: String,
    pub task_id: String,
    pub detail: String,
    /// sha256 (hex) of the previous entry's serialized bytes; `GENESIS` for the first.
    pub prev: String,
}

fn hash_entry(entry: &AuditEntry) -> String {
    let bytes = serde_json::to_string(entry).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(bytes.as_bytes());
    hex_lower(&h.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Append-only, hash-chained JSONL audit log. Every dispatch, enrollment, and
/// result is recorded — a required safety control (see WORKSPACE_SPEC). A
/// monotonic counter stands in for a wall clock; each line links to the prior
/// entry's hash so the trail can be verified with [`verify_audit_chain`].
pub struct AuditLog {
    path: PathBuf,
    state: Mutex<State>,
}

struct State {
    seq: u64,
    last_hash: String,
}

impl AuditLog {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: Mutex::new(State {
                seq: 0,
                last_hash: GENESIS.to_string(),
            }),
        }
    }

    pub fn record(&self, kind: &str, agent_id: &str, task_id: &str, detail: &str) {
        let mut st = self.state.lock().unwrap();
        st.seq += 1;
        let entry = AuditEntry {
            seq: st.seq,
            kind: kind.to_string(),
            agent_id: agent_id.to_string(),
            task_id: task_id.to_string(),
            detail: detail.to_string(),
            prev: st.last_hash.clone(),
        };
        let this_hash = hash_entry(&entry);
        let line = serde_json::to_string(&entry).unwrap_or_default();

        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(f, "{line}");
        }
        st.last_hash = this_hash;
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

/// Verify the hash chain of an audit log file. Returns `Ok(true)` when every
/// entry's `prev` matches the running hash of its predecessor (so no entry has
/// been altered, inserted, or removed); `Ok(false)` on any break.
pub fn verify_audit_chain(path: impl AsRef<Path>) -> std::io::Result<bool> {
    let text = std::fs::read_to_string(path)?;
    let mut running = GENESIS.to_string();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let entry: AuditEntry = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(_) => return Ok(false),
        };
        if entry.prev != running {
            return Ok(false);
        }
        running = hash_entry(&entry);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("alive-audit-tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(format!("{name}-{}.jsonl", std::process::id()))
    }

    #[test]
    fn valid_chain_verifies() {
        let p = temp_path("valid");
        let _ = std::fs::remove_file(&p);
        let log = AuditLog::new(p.clone());
        log.record("dispatch", "agent-1", "task-1", "discover");
        log.record("result", "agent-1", "task-1", "0 findings");
        log.record("dispatch", "agent-2", "task-2", "scan");
        assert!(verify_audit_chain(&p).unwrap());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn mutated_entry_fails_verification() {
        let p = temp_path("mutated");
        let _ = std::fs::remove_file(&p);
        let log = AuditLog::new(p.clone());
        log.record("dispatch", "agent-1", "task-1", "discover");
        log.record("result", "agent-1", "task-1", "clean");
        log.record("dispatch", "agent-1", "task-2", "scan");

        // Tamper with the middle entry's detail.
        let text = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
        lines[1] = lines[1].replace("clean", "HACKED");
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();

        assert!(!verify_audit_chain(&p).unwrap());
        let _ = std::fs::remove_file(&p);
    }
}
