use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::Serialize;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// A service identified on an open port.
#[derive(Debug, Clone, Serialize)]
pub struct Service {
    pub ip: IpAddr,
    pub port: u16,
    /// Coarse service name (`http`, `redis`, `ssh`, ...).
    pub name: String,
    /// Banner captured during detection, if any (truncated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

/// Well-known-port → coarse service name.
pub fn service_for_port(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 587 => "smtp",
        53 => "dns",
        80 | 8080 | 8000 | 8888 => "http",
        110 => "pop3",
        135 => "msrpc",
        139 | 445 => "smb",
        143 => "imap",
        161 => "snmp",
        389 => "ldap",
        443 | 8443 => "https",
        1433 => "mssql",
        1521 => "oracle",
        2375 | 2376 => "docker",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgres",
        5900 => "vnc",
        6379 => "redis",
        9200 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        _ => return None,
    })
}

/// Detect the service on an open `(ip, port)`.
///
/// Starts from the well-known-port table, then optionally refines using a
/// best-effort banner grab: connect, read up to a few hundred bytes with a
/// short deadline, and let banner keywords override the port guess (e.g. an
/// `SSH-2.0-...` banner on a nonstandard port).
pub async fn detect(ip: IpAddr, port: u16, timeout: Duration) -> Service {
    let banner = grab_banner(ip, port, timeout).await;
    let name = classify(port, banner.as_deref());
    Service {
        ip,
        port,
        name,
        banner,
    }
}

fn classify(port: u16, banner: Option<&str>) -> String {
    if let Some(b) = banner {
        let lower = b.to_ascii_lowercase();
        if lower.starts_with("ssh-") {
            return "ssh".to_string();
        }
        if lower.contains("http/") || lower.contains("server:") {
            return "http".to_string();
        }
        if lower.starts_with("220") && lower.contains("ftp") {
            return "ftp".to_string();
        }
        if lower.starts_with("220") {
            return "smtp".to_string();
        }
        if lower.contains("-err") || lower.contains("redis") {
            return "redis".to_string();
        }
    }
    service_for_port(port)
        .map(str::to_string)
        .unwrap_or_else(|| "unknown".to_string())
}

/// Read whatever the server volunteers on connect (many services send a
/// greeting; HTTP does not, which is fine — an empty banner just leaves the
/// port-table guess in place).
async fn grab_banner(ip: IpAddr, port: u16, timeout: Duration) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}
