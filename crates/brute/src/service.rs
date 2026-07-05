use std::time::Duration;

use alive_core::{Error, Result};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::cred::Credential;

/// A service that can be probed with a single credential.
///
/// Implementations use pure-Rust/tokio networking only (no C deps). `try_login`
/// returns `Ok(true)` on a confirmed successful auth, `Ok(false)` on a rejected
/// credential, and `Err` on a connection/protocol failure.
#[async_trait]
pub trait BruteService: Send + Sync {
    fn name(&self) -> &'static str;
    async fn try_login(
        &self,
        host: &str,
        port: u16,
        cred: &Credential,
        timeout: Duration,
    ) -> Result<bool>;
}

async fn connect(host: &str, port: u16, to: Duration) -> Result<TcpStream> {
    let fut = TcpStream::connect((host, port));
    match timeout(to, fut).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(Error::Io(e)),
        Err(_) => Err(Error::Other(format!("connect timeout {host}:{port}"))),
    }
}

/// Redis password auth via the RESP protocol. The username is used for ACL
/// auth (`AUTH user pass`) when non-empty, else legacy `AUTH pass`. Success is
/// a `+OK` reply.
pub struct RedisService;

#[async_trait]
impl BruteService for RedisService {
    fn name(&self) -> &'static str {
        "redis"
    }

    async fn try_login(
        &self,
        host: &str,
        port: u16,
        cred: &Credential,
        to: Duration,
    ) -> Result<bool> {
        let mut stream = connect(host, port, to).await?;
        let cmd = if cred.username.is_empty() {
            resp(&["AUTH", &cred.password])
        } else {
            resp(&["AUTH", &cred.username, &cred.password])
        };
        stream.write_all(cmd.as_bytes()).await.map_err(Error::Io)?;

        let mut buf = [0u8; 256];
        let n = match timeout(to, stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(Error::Io(e)),
            Err(_) => return Err(Error::Other("redis read timeout".into())),
        };
        Ok(buf[..n].starts_with(b"+OK"))
    }
}

/// Encode a RESP array command (`*N\r\n$len\r\narg\r\n...`).
fn resp(args: &[&str]) -> String {
    let mut s = format!("*{}\r\n", args.len());
    for a in args {
        s.push_str(&format!("${}\r\n{}\r\n", a.len(), a));
    }
    s
}

/// FTP auth via `USER`/`PASS`. Success is a `230` reply to `PASS`.
pub struct FtpService;

#[async_trait]
impl BruteService for FtpService {
    fn name(&self) -> &'static str {
        "ftp"
    }

    async fn try_login(
        &self,
        host: &str,
        port: u16,
        cred: &Credential,
        to: Duration,
    ) -> Result<bool> {
        let mut stream = connect(host, port, to).await?;
        // Banner (220).
        read_line(&mut stream, to).await?;

        stream
            .write_all(format!("USER {}\r\n", cred.username).as_bytes())
            .await
            .map_err(Error::Io)?;
        read_line(&mut stream, to).await?; // 331/230/530

        stream
            .write_all(format!("PASS {}\r\n", cred.password).as_bytes())
            .await
            .map_err(Error::Io)?;
        let reply = read_line(&mut stream, to).await?;
        Ok(reply.starts_with("230"))
    }
}

async fn read_line(stream: &mut TcpStream, to: Duration) -> Result<String> {
    let mut buf = [0u8; 512];
    let n = match timeout(to, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(Error::Io(e)),
        Err(_) => return Err(Error::Other("read timeout".into())),
    };
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resp_encoding_is_wellformed() {
        assert_eq!(resp(&["AUTH", "pw"]), "*2\r\n$4\r\nAUTH\r\n$2\r\npw\r\n");
    }
}
