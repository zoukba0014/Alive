use std::time::Duration;

use alive_core::{Error, Result};
use alive_engine::{TcpClient, TcpResponse};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// tokio-backed TCP runner: connect, write inputs, read a bounded reply.
pub struct TcpRunner {
    timeout: Duration,
}

impl TcpRunner {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait]
impl TcpClient for TcpRunner {
    async fn send(&self, addr: &str, inputs: &[String], read_size: usize) -> Result<TcpResponse> {
        let fut = async {
            let mut stream = TcpStream::connect(addr)
                .await
                .map_err(|e| Error::Other(format!("tcp connect {addr} failed: {e}")))?;

            for input in inputs {
                let bytes = decode_escapes(input);
                stream
                    .write_all(&bytes)
                    .await
                    .map_err(|e| Error::Other(format!("tcp write failed: {e}")))?;
            }
            stream
                .flush()
                .await
                .map_err(|e| Error::Other(format!("tcp flush failed: {e}")))?;

            let cap = read_size.clamp(1, 65536);
            let mut buf = vec![0u8; cap];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            buf.truncate(n);
            Ok::<_, Error>(TcpResponse {
                data: String::from_utf8_lossy(&buf).into_owned(),
            })
        };

        match tokio::time::timeout(self.timeout, fut).await {
            Ok(res) => res,
            Err(_) => Err(Error::Other(format!("tcp timeout talking to {addr}"))),
        }
    }
}

/// Decode common backslash escapes so single-quoted YAML `data` (e.g.
/// `INFO\r\n`) sends real bytes. Double-quoted YAML is already decoded by the
/// parser, and leaves nothing for this to change.
fn decode_escapes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut b = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            continue;
        }
        match chars.next() {
            Some('r') => out.push(b'\r'),
            Some('n') => out.push(b'\n'),
            Some('t') => out.push(b'\t'),
            Some('0') => out.push(0),
            Some('\\') => out.push(b'\\'),
            Some('x') => {
                let hi = chars.next();
                let lo = chars.next();
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    if let Ok(byte) = u8::from_str_radix(&format!("{hi}{lo}"), 16) {
                        out.push(byte);
                    }
                }
            }
            Some(other) => {
                out.push(b'\\');
                let mut b = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut b).as_bytes());
            }
            None => out.push(b'\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_crlf_escapes() {
        assert_eq!(decode_escapes("INFO\\r\\n"), b"INFO\r\n");
    }

    #[test]
    fn decodes_hex_escape() {
        assert_eq!(decode_escapes("\\x41\\x42"), b"AB");
    }

    #[test]
    fn passes_through_plain_text() {
        assert_eq!(decode_escapes("hello"), b"hello");
    }
}
