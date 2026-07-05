use std::path::Path;

use alive_core::{Error, Result};

/// A single username/password pair to try.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

impl Credential {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

/// Parse a credentials file: one `user:pass` per line. Blank lines and lines
/// starting with `#` are ignored. An empty password (`user:`) is allowed; a
/// line with no colon is treated as a username with an empty password.
pub fn load_creds_file(path: impl AsRef<Path>) -> Result<Vec<Credential>> {
    let text = std::fs::read_to_string(path).map_err(Error::Io)?;
    Ok(parse_creds(&text))
}

fn parse_creds(text: &str) -> Vec<Credential> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| match l.split_once(':') {
            Some((u, p)) => Credential::new(u, p),
            None => Credential::new(l, ""),
        })
        .collect()
}

/// A small, clearly-labeled set of well-known default credentials. This is
/// **opt-in** — callers choose to use it explicitly; it is not applied silently
/// and is intentionally tiny (well-known vendor defaults only), not a wordlist.
pub fn wellknown_defaults() -> Vec<Credential> {
    [
        ("root", "root"),
        ("root", "toor"),
        ("admin", "admin"),
        ("admin", "password"),
        ("guest", "guest"),
    ]
    .into_iter()
    .map(|(u, p)| Credential::new(u, p))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_user_pass_and_skips_comments() {
        let creds = parse_creds("root:root\n# comment\n\nadmin:\nsolo\n");
        assert_eq!(creds.len(), 3);
        assert_eq!(creds[0], Credential::new("root", "root"));
        assert_eq!(creds[1], Credential::new("admin", "")); // empty password kept
        assert_eq!(creds[2], Credential::new("solo", "")); // no colon → empty pass
    }
}
