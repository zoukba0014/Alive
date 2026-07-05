use thiserror::Error;

#[derive(Debug, Error)]
pub enum PortParseError {
    #[error("empty port spec")]
    Empty,
    #[error("invalid port token `{0}`")]
    InvalidToken(String),
    #[error("invalid range `{0}` (start > end)")]
    InvalidRange(String),
}

/// Parse a port spec like `80,443,8000-9000` into a sorted, de-duplicated list.
///
/// Tokens are comma-separated; each is either a single port or an inclusive
/// `start-end` range.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, PortParseError> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(PortParseError::Empty);
    }

    let mut ports = Vec::new();
    for token in spec.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        match token.split_once('-') {
            Some((lo, hi)) => {
                let lo: u16 = lo
                    .trim()
                    .parse()
                    .map_err(|_| PortParseError::InvalidToken(token.to_string()))?;
                let hi: u16 = hi
                    .trim()
                    .parse()
                    .map_err(|_| PortParseError::InvalidToken(token.to_string()))?;
                if lo > hi {
                    return Err(PortParseError::InvalidRange(token.to_string()));
                }
                ports.extend(lo..=hi);
            }
            None => ports.push(
                token
                    .parse()
                    .map_err(|_| PortParseError::InvalidToken(token.to_string()))?,
            ),
        }
    }

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn singles_and_ranges() {
        assert_eq!(
            parse_ports("80,443,8000-8002").unwrap(),
            vec![80, 443, 8000, 8001, 8002]
        );
    }

    #[test]
    fn sorts_and_dedups() {
        assert_eq!(parse_ports("443,80,80,443").unwrap(), vec![80, 443]);
    }

    #[test]
    fn rejects_bad_token() {
        assert!(parse_ports("80,abc").is_err());
    }

    #[test]
    fn rejects_reversed_range() {
        assert!(parse_ports("9000-80").is_err());
    }
}
