use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use reqwest::redirect::Policy;
use reqwest::{StatusCode, Url};
use thiserror::Error;

/// Limits applied to each download.
#[derive(Clone, Copy, Debug)]
pub struct FetchLimits {
    pub max_bytes: u64,
    pub timeout: Duration,
    pub max_redirects: usize,
}

impl Default for FetchLimits {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024 * 1024,
            timeout: Duration::from_secs(60),
            max_redirects: 5,
        }
    }
}

/// Validators from the previous download, for HTTP conditional requests.
#[derive(Clone, Debug, Default)]
pub struct Conditional {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// The result of a download.
#[derive(Debug)]
pub enum FetchOutcome {
    NotModified,
    Body {
        text: String,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

/// Why a download failed.
#[derive(Debug, Error)]
pub enum FetchError {
    #[error("invalid list URL: {0}")]
    InvalidUrl(String),
    #[error("list URLs must use http or https")]
    UnsupportedScheme,
    #[error("list URLs can't point at loopback or private addresses")]
    PrivateAddress,
    #[error("the list is larger than the {0} byte limit")]
    TooLarge(u64),
    #[error("the server responded with HTTP {0}")]
    Status(u16),
    #[error("the list isn't valid UTF-8")]
    NotUtf8,
    #[error("download failed: {0}")]
    Http(String),
}

/// Whether an address is reachable on the public Internet.
pub fn is_public_ip(address: IpAddr) -> bool {
    match address.to_canonical() {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => is_public_v6(ip),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    let carrier_nat = first == 100 && (64..128).contains(&second);
    let reserved = first >= 240 || first == 0;
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || carrier_nat
        || reserved)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    let unique_local = first & 0xfe00 == 0xfc00;
    let link_local = first & 0xffc0 == 0xfe80;
    let documentation = first == 0x2001 && ip.segments()[1] == 0x0db8;
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || unique_local
        || link_local
        || documentation)
}

/// Resolves names but only returns public addresses, so a hostname can't reach internal services.
///
/// The connection uses the returned addresses, so a later DNS answer can't change the destination.
struct PublicOnlyResolver;

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = format!("{}:0", name.as_str());
            let addresses: Vec<SocketAddr> = tokio::net::lookup_host(host)
                .await?
                .filter(|address| is_public_ip(address.ip()))
                .collect();
            if addresses.is_empty() {
                return Err(Box::new(FetchError::PrivateAddress)
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            let addresses: Addrs = Box::new(addresses.into_iter());
            Ok(addresses)
        })
    }
}

fn host_allowed(url: &Url, allow_private: bool) -> Result<(), FetchError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(FetchError::UnsupportedScheme);
    }
    if allow_private {
        return Ok(());
    }
    // Literal addresses never reach the resolver, so they're checked here.
    let address = match url.host() {
        Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
        Some(url::Host::Domain(_)) => None,
        None => return Err(FetchError::InvalidUrl("the URL has no host".to_owned())),
    };
    if address.is_some_and(|ip| !is_public_ip(ip)) {
        return Err(FetchError::PrivateAddress);
    }
    Ok(())
}

/// Downloads lists with SSRF protections and size, time and redirect limits.
#[derive(Clone)]
pub struct Fetcher {
    client: reqwest::Client,
    limits: FetchLimits,
    allow_private: bool,
}

impl Fetcher {
    /// Builds a fetcher. `allow_private` permits loopback and private destinations.
    pub fn new(limits: FetchLimits, allow_private: bool) -> Result<Self, FetchError> {
        // Selects ring for all TLS in the process. Repeated calls have no effect.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let max_redirects = limits.max_redirects;
        let redirects = Policy::custom(move |attempt| {
            if attempt.previous().len() >= max_redirects {
                return attempt.error(FetchError::Http("too many redirects".to_owned()));
            }
            match host_allowed(attempt.url(), allow_private) {
                Ok(()) => attempt.follow(),
                Err(error) => attempt.error(error),
            }
        });
        let mut builder = reqwest::Client::builder()
            .timeout(limits.timeout)
            .redirect(redirects)
            .user_agent(concat!("FerrixDNS/", env!("CARGO_PKG_VERSION")));
        if !allow_private {
            builder = builder.dns_resolver(Arc::new(PublicOnlyResolver));
        }
        let client = builder
            .build()
            .map_err(|error| FetchError::Http(error.to_string()))?;
        Ok(Self {
            client,
            limits,
            allow_private,
        })
    }

    /// Checks that a URL could be downloaded, without contacting it.
    pub fn validate_url(&self, url: &str) -> Result<(), FetchError> {
        let parsed = Url::parse(url).map_err(|error| FetchError::InvalidUrl(error.to_string()))?;
        host_allowed(&parsed, self.allow_private)
    }

    /// Downloads a list, sending validators from the previous download if there are any.
    pub async fn fetch(
        &self,
        url: &str,
        conditional: &Conditional,
    ) -> Result<FetchOutcome, FetchError> {
        let parsed = Url::parse(url).map_err(|error| FetchError::InvalidUrl(error.to_string()))?;
        host_allowed(&parsed, self.allow_private)?;

        let mut request = self.client.get(parsed);
        if let Some(etag) = &conditional.etag {
            request = request.header(IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &conditional.last_modified {
            request = request.header(IF_MODIFIED_SINCE, last_modified);
        }

        let mut response = request.send().await.map_err(describe)?;
        let status = response.status();
        if status == StatusCode::NOT_MODIFIED {
            return Ok(FetchOutcome::NotModified);
        }
        if !status.is_success() {
            return Err(FetchError::Status(status.as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.limits.max_bytes)
        {
            return Err(FetchError::TooLarge(self.limits.max_bytes));
        }

        let header = |name| {
            response
                .headers()
                .get(name)
                .and_then(|value: &reqwest::header::HeaderValue| value.to_str().ok())
                .map(ToOwned::to_owned)
        };
        let etag = header(ETAG);
        let last_modified = header(LAST_MODIFIED);

        // Content-Length can be absent or wrong, so the limit also applies while reading.
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(describe)? {
            let total = u64::try_from(body.len() + chunk.len()).unwrap_or(u64::MAX);
            if total > self.limits.max_bytes {
                return Err(FetchError::TooLarge(self.limits.max_bytes));
            }
            body.extend_from_slice(&chunk);
        }
        let text = String::from_utf8(body).map_err(|_| FetchError::NotUtf8)?;
        Ok(FetchOutcome::Body {
            text,
            etag,
            last_modified,
        })
    }
}

/// Keeps the useful cause, because reqwest's top-level message omits it.
fn describe(error: reqwest::Error) -> FetchError {
    let mut message = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        if cause
            .downcast_ref::<FetchError>()
            .is_some_and(|inner| matches!(inner, FetchError::PrivateAddress))
        {
            return FetchError::PrivateAddress;
        }
        message = format!("{message}: {cause}");
        source = cause.source();
    }
    FetchError::Http(message)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn classifies_addresses() {
        for public in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(is_public_ip(ip(public)), "{public}");
        }
        for private in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "2001:db8::1",
        ] {
            assert!(!is_public_ip(ip(private)), "{private}");
        }
    }

    fn fetcher(allow_private: bool, max_bytes: u64) -> Fetcher {
        Fetcher::new(
            FetchLimits {
                max_bytes,
                timeout: Duration::from_secs(5),
                max_redirects: 2,
            },
            allow_private,
        )
        .unwrap()
    }

    /// Serves one canned HTTP response per connection and reports the last request's text.
    async fn serve(response: String) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/list", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0_u8; 4096];
            let length = stream.read(&mut buffer).await.unwrap();
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
            vec![String::from_utf8_lossy(&buffer[..length]).into_owned()]
        });
        (url, task)
    }

    fn ok(body: &str, extra: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn downloads_a_list_and_returns_validators() {
        let (url, _) = serve(ok(
            "a.example\n",
            "ETag: \"v1\"\r\nLast-Modified: yesterday\r\n",
        ))
        .await;
        let outcome = fetcher(true, 1024)
            .fetch(&url, &Conditional::default())
            .await
            .unwrap();
        let FetchOutcome::Body {
            text,
            etag,
            last_modified,
        } = outcome
        else {
            panic!("expected a body");
        };
        assert_eq!(text, "a.example\n");
        assert_eq!(etag.as_deref(), Some("\"v1\""));
        assert_eq!(last_modified.as_deref(), Some("yesterday"));
    }

    #[tokio::test]
    async fn sends_validators_and_understands_not_modified() {
        let (url, task) =
            serve("HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_owned()).await;
        let conditional = Conditional {
            etag: Some("\"v1\"".into()),
            last_modified: Some("yesterday".into()),
        };
        let outcome = fetcher(true, 1024).fetch(&url, &conditional).await.unwrap();
        assert!(matches!(outcome, FetchOutcome::NotModified));
        let request = task.await.unwrap().remove(0).to_ascii_lowercase();
        assert!(request.contains("if-none-match: \"v1\""), "{request}");
        assert!(
            request.contains("if-modified-since: yesterday"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn enforces_the_size_limit_with_and_without_content_length() {
        let (url, _) = serve(ok(&"a".repeat(100), "")).await;
        let error = fetcher(true, 10)
            .fetch(&url, &Conditional::default())
            .await
            .unwrap_err();
        assert!(matches!(error, FetchError::TooLarge(10)), "{error}");

        let body = "a".repeat(100);
        let (url, _) = serve(format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{body}"
        ))
        .await;
        let error = fetcher(true, 10)
            .fetch(&url, &Conditional::default())
            .await
            .unwrap_err();
        assert!(matches!(error, FetchError::TooLarge(10)), "{error}");
    }

    #[tokio::test]
    async fn reports_http_errors() {
        let (url, _) = serve(
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
        )
        .await;
        let error = fetcher(true, 1024)
            .fetch(&url, &Conditional::default())
            .await
            .unwrap_err();
        assert!(matches!(error, FetchError::Status(404)), "{error}");
    }

    #[tokio::test]
    async fn blocks_private_destinations_by_default() {
        let strict = fetcher(false, 1024);
        for url in [
            "http://127.0.0.1/list",
            "http://[::1]/list",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/list",
            "http://localhost/list",
        ] {
            let error = strict
                .fetch(url, &Conditional::default())
                .await
                .unwrap_err();
            assert!(
                matches!(error, FetchError::PrivateAddress),
                "{url}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn blocks_redirects_to_private_destinations() {
        // The allow_private check has to apply to redirects even if the first host is allowed.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let attempt = Url::parse(&format!("http://{address}/")).unwrap();
        assert!(matches!(
            host_allowed(&attempt, false),
            Err(FetchError::PrivateAddress)
        ));
    }

    #[test]
    fn rejects_other_schemes_and_bad_urls() {
        let strict = fetcher(false, 1024);
        assert!(matches!(
            strict.validate_url("file:///etc/passwd"),
            Err(FetchError::UnsupportedScheme)
        ));
        assert!(matches!(
            strict.validate_url("ftp://lists.example/hosts"),
            Err(FetchError::UnsupportedScheme)
        ));
        assert!(matches!(
            strict.validate_url("not a url"),
            Err(FetchError::InvalidUrl(_))
        ));
        assert!(strict.validate_url("https://lists.example/hosts").is_ok());
    }
}
