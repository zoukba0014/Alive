//! Persistent offline result buffer.
//!
//! When the control-plane server is unreachable, the agent keeps executing its
//! cached (still-signature-verified) tasks and stores the results here. On
//! reconnect the buffer is drained in FIFO order and flushed to the server,
//! where results are audit-logged like any other — buffering never bypasses
//! the M6 safety controls.
//!
//! Backed by [`redb`] (pure-Rust embedded KV), so the queue survives process
//! restarts.

use std::path::Path;

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Monotonic sequence -> JSON-encoded [`BufferedResult`]. Ordering by key gives
/// FIFO drain.
const RESULTS: TableDefinition<u64, &[u8]> = TableDefinition::new("results");

#[derive(Debug, Error)]
pub enum BufferError {
    #[error("buffer storage error: {0}")]
    Storage(String),
    #[error("buffer encode/decode error: {0}")]
    Codec(#[from] serde_json::Error),
}

// redb has a family of error types; collapse them into one message.
macro_rules! store_err {
    ($e:expr) => {
        |e| BufferError::Storage(format!("{}: {e}", $e))
    };
}

/// A task result awaiting delivery to the control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BufferedResult {
    pub task_id: String,
    /// JSON-serialized `Vec<alive_core::Finding>`.
    pub findings_json: String,
    pub status: String,
}

/// A durable FIFO queue of pending results.
pub struct Buffer {
    db: Database,
}

impl Buffer {
    /// Open (creating if absent) the buffer at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BufferError> {
        let db = Database::create(path).map_err(store_err!("open"))?;
        // Ensure the table exists so `len`/`drain` work on a fresh db.
        let wt = db.begin_write().map_err(store_err!("begin_write"))?;
        {
            wt.open_table(RESULTS).map_err(store_err!("open_table"))?;
        }
        wt.commit().map_err(store_err!("commit"))?;
        Ok(Self { db })
    }

    /// Append a result to the back of the queue.
    pub fn enqueue(&self, item: &BufferedResult) -> Result<(), BufferError> {
        let bytes = serde_json::to_vec(item)?;
        let wt = self.db.begin_write().map_err(store_err!("begin_write"))?;
        {
            let mut t = wt.open_table(RESULTS).map_err(store_err!("open_table"))?;
            let next = t
                .last()
                .map_err(store_err!("last"))?
                .map(|(k, _)| k.value() + 1)
                .unwrap_or(0);
            t.insert(next, bytes.as_slice())
                .map_err(store_err!("insert"))?;
        }
        wt.commit().map_err(store_err!("commit"))?;
        Ok(())
    }

    /// Number of buffered results.
    pub fn len(&self) -> Result<usize, BufferError> {
        let rt = self.db.begin_read().map_err(store_err!("begin_read"))?;
        let t = rt.open_table(RESULTS).map_err(store_err!("open_table"))?;
        Ok(t.len().map_err(store_err!("len"))? as usize)
    }

    pub fn is_empty(&self) -> Result<bool, BufferError> {
        Ok(self.len()? == 0)
    }

    /// Remove and return all buffered results in FIFO order.
    pub fn drain(&self) -> Result<Vec<BufferedResult>, BufferError> {
        let wt = self.db.begin_write().map_err(store_err!("begin_write"))?;
        let mut out = Vec::new();
        {
            let mut t = wt.open_table(RESULTS).map_err(store_err!("open_table"))?;
            let mut keys = Vec::new();
            for entry in t.iter().map_err(store_err!("iter"))? {
                let (k, v) = entry.map_err(store_err!("entry"))?;
                out.push(serde_json::from_slice::<BufferedResult>(v.value())?);
                keys.push(k.value());
            }
            for k in keys {
                t.remove(k).map_err(store_err!("remove"))?;
            }
        }
        wt.commit().map_err(store_err!("commit"))?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("alive-buffer-tests");
        std::fs::create_dir_all(&dir).unwrap();
        // Unique-ish per test; clean any prior file so runs are independent.
        let p = dir.join(name);
        let _ = std::fs::remove_file(&p);
        p
    }

    fn result(id: &str) -> BufferedResult {
        BufferedResult {
            task_id: id.into(),
            findings_json: "[]".into(),
            status: "ok".into(),
        }
    }

    #[test]
    fn enqueue_reopen_drain_is_fifo_and_survives_restart() {
        let path = tmp_path("fifo.redb");
        {
            let b = Buffer::open(&path).unwrap();
            b.enqueue(&result("t1")).unwrap();
            b.enqueue(&result("t2")).unwrap();
            b.enqueue(&result("t3")).unwrap();
            assert_eq!(b.len().unwrap(), 3);
        } // drop → closes db

        // Reopen a fresh handle: data persisted across "restart".
        let b = Buffer::open(&path).unwrap();
        assert_eq!(b.len().unwrap(), 3);
        let drained = b.drain().unwrap();
        assert_eq!(
            drained
                .iter()
                .map(|r| r.task_id.as_str())
                .collect::<Vec<_>>(),
            vec!["t1", "t2", "t3"]
        );
        // Drained → empty and stays empty.
        assert!(b.is_empty().unwrap());
        assert!(b.drain().unwrap().is_empty());
    }
}
