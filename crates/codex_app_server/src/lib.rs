use anyhow::{Context, Result, anyhow, bail};
use std::time::Duration;
use tokio::{net::TcpStream, time::timeout};
use url::Url;

#[derive(Debug, Clone)]
pub struct CodexAppServerClient {
    endpoint: Url,
    connect_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmokeConnection {
    pub endpoint: String,
}

impl CodexAppServerClient {
    pub fn new(endpoint: &str) -> Result<Self> {
        let endpoint = Url::parse(endpoint).context("endpoint must be a valid URL")?;
        ensure_supported_scheme(&endpoint)?;

        Ok(Self {
            endpoint,
            connect_timeout: Duration::from_secs(2),
        })
    }

    pub fn with_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    pub async fn connect_smoke(&self) -> Result<SmokeConnection> {
        let target = endpoint_socket_address(&self.endpoint)?;
        let connect_future = TcpStream::connect(&target);

        timeout(self.connect_timeout, connect_future)
            .await
            .with_context(|| format!("timed out connecting to {}", self.endpoint))?
            .with_context(|| format!("failed connecting to {}", target))?;

        Ok(SmokeConnection {
            endpoint: self.endpoint.to_string(),
        })
    }
}

fn ensure_supported_scheme(endpoint: &Url) -> Result<()> {
    match endpoint.scheme() {
        "http" | "https" | "ws" | "wss" => Ok(()),
        other => bail!("unsupported endpoint scheme: {other}"),
    }
}

fn endpoint_socket_address(endpoint: &Url) -> Result<String> {
    let host = endpoint
        .host_str()
        .ok_or_else(|| anyhow!("endpoint is missing a host"))?;

    let port = endpoint
        .port_or_known_default()
        .ok_or_else(|| anyhow!("endpoint is missing a port and no default is known"))?;

    if host.contains(':') {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn connect_smoke_reaches_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });

        let endpoint = format!("http://{addr}");
        let client = CodexAppServerClient::new(&endpoint).unwrap();
        let result = client.connect_smoke().await;

        accept_task.await.unwrap();

        assert!(result.is_ok());
        assert_eq!(result.unwrap().endpoint, format!("{endpoint}/"));
    }

    #[test]
    fn rejects_unsupported_scheme() {
        let error = CodexAppServerClient::new("ftp://127.0.0.1:8080").unwrap_err();
        assert!(error.to_string().contains("unsupported endpoint scheme"));
    }
}
