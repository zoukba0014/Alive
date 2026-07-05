use std::path::{Path, PathBuf};

use thiserror::Error;
use walkdir::WalkDir;

use crate::model::Template;

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("yaml parse error in {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_yaml_ng::Error,
    },
}

/// Parse a single template file.
pub fn load_file(path: impl AsRef<Path>) -> Result<Template, LoadError> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_yaml_ng::from_str(&text).map_err(|source| LoadError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

/// Recursively load all `*.yaml` / `*.yml` templates under `dir`.
///
/// Returns each result paired with its path so callers can report per-file
/// parse failures without aborting the whole load.
pub fn load_dir(dir: impl AsRef<Path>) -> Vec<(PathBuf, Result<Template, LoadError>)> {
    let mut out = Vec::new();
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
            .unwrap_or(false);
        if is_yaml {
            let res = load_file(path);
            out.push((path.to_path_buf(), res));
        }
    }
    out
}
