use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// Append-only JSONL audit log. Every dispatch, enrollment, and result is
/// recorded — a required safety control (see WORKSPACE_SPEC). Each line is a
/// self-contained JSON object; a monotonic counter stands in for a wall clock
/// (the binary can add timestamps).
pub struct AuditLog {
    path: PathBuf,
    seq: Mutex<u64>,
}

impl AuditLog {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            seq: Mutex::new(0),
        }
    }

    pub fn record(&self, kind: &str, agent_id: &str, task_id: &str, detail: &str) {
        let seq = {
            let mut s = self.seq.lock().unwrap();
            *s += 1;
            *s
        };
        let line = serde_json::json!({
            "seq": seq,
            "kind": kind,
            "agent_id": agent_id,
            "task_id": task_id,
            "detail": detail,
        });
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
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}
