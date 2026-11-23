//! Scope validation and bounded, read-only collection of owner-selected resources.
use reqwest::{Client, Response, Url, redirect::Policy};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::lookup_host,
    time::{Instant, timeout_at},
};

const MAX_BODY: usize = 512 * 1024;
const MAX_TIME: Duration = Duration::from_secs(12);
type Error = &'static str;

/// Raw response lives only until the rules produce redacted observations.
pub struct HttpEvidence {
    pub final_url: String,
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

pub struct Scope {
    base: Url,
    expires_at: i64,
    upgrade: bool,
    #[cfg(test)]
    fixture_peer: Option<std::net::SocketAddr>,
}

fn parse_resource(input: &str) -> Result<Url, Error> {
    if input.len() > 2048
        || input.bytes().any(|b| b <= 32 || b >= 127)
        || input.contains(['%', '\\', '?', '#', '@'])
        || input.split('/').any(|s| matches!(s, "." | ".."))
    {
        return Err("unsupported URL characters");
    }
    let url = Url::parse(input).map_err(|_| "invalid URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url
            .path()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.~".contains(&b))
        || url.path().contains("//")
    {
        return Err("unsupported resource URL");
    }
    Ok(url)
}

/// Keep the origin for display. Paths, query strings and fragments can contain secrets.
pub fn safe_url(input: &str) -> String {
    Url::parse(input)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_else(|| "[redacted]".to_string())
}

// Egress uses public IPv4 only. Reject special-use, multicast and reserved space.
fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !matches!(
        (a, b, c),
        (0 | 10 | 127 | 224..=255, _, _)
            | (100, 64..=127, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, _)
            | (192, 88, 99)
            | (192, 168, _)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
    )
}

async fn read_body(
    response: &mut Response,
    limit: usize,
    size_error: Error,
) -> Result<String, Error> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "incomplete response")? {
        if chunk.len() > limit - bytes.len() {
            return Err(size_error);
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| "unsupported text encoding")
}

impl Scope {
    pub fn new(base: &str, expires_at: i64) -> Result<Self, Error> {
        let scope = Self {
            base: parse_resource(base)?,
            expires_at,
            upgrade: false,
            #[cfg(test)]
            fixture_peer: None,
        };
        scope.active()?;
        Ok(scope)
    }

    pub fn with_upgrade(mut self, upgrade: bool) -> Result<Self, Error> {
        if upgrade && (self.base.scheme() != "http" || self.base.port().is_some()) {
            return Err("upgrade requires default HTTP port");
        }
        self.upgrade = upgrade;
        Ok(self)
    }

    pub fn is_https(&self) -> bool {
        self.base.scheme() == "https"
    }

    fn active(&self) -> Result<(), Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "invalid clock")?;
        if self.expires_at <= now.as_secs() as i64 {
            Err("scope expired")
        } else {
            Ok(())
        }
    }

    fn allows(&self, url: &Url) -> bool {
        let prefix = self.base.path().trim_end_matches('/');
        (self.base.origin() == url.origin()
            || (self.upgrade
                && url.scheme() == "https"
                && url.port().is_none()
                && url.host() == self.base.host()))
            && (url.path() == prefix
                || url
                    .path()
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/')))
    }

    fn redirect_target(&self, url: &Url, location: &str) -> Result<Url, Error> {
        if location.contains(['%', '\\', '?', '#', '@'])
            || location.bytes().any(|b| b <= 32 || b >= 127)
        {
            return Err("unsupported redirect");
        }
        let next = url.join(location).map_err(|_| "invalid redirect")?;
        if url.scheme() == "https" && next.scheme() == "http" {
            return Err("redirect downgrade");
        }
        let next = parse_resource(next.as_str())?;
        if !self.allows(&next) {
            return Err("outside approved scope");
        }
        Ok(next)
    }

    pub fn contains(&self, resource: &str) -> bool {
        self.active().is_ok() && parse_resource(resource).is_ok_and(|url| self.allows(&url))
    }

    pub fn challenge_url(&self) -> String {
        format!(
            "{}/rustscope-verification.txt",
            self.base.as_str().trim_end_matches('/')
        )
    }

    pub async fn verify(&self, token: &str) -> Result<(), Error> {
        if token.len() < 32
            || token.len() > 128
            || !token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Err("invalid verification token");
        }
        let primary = self.challenge_url();
        self.prove(&primary, token).await?;
        if self.upgrade {
            let secure = primary.replacen("http:", "https:", 1);
            self.prove(&secure, token).await?;
        }
        Ok(())
    }

    async fn prove(&self, url: &str, token: &str) -> Result<(), Error> {
        let proof = self.collect(url, false).await?;
        if proof.status == 200 && proof.body.trim_end_matches(['\r', '\n']) == token {
            Ok(())
        } else {
            Err("control verification failed")
        }
    }

    pub async fn fetch(&self, resource: &str) -> Result<HttpEvidence, Error> {
        self.collect(resource, true).await
    }

    async fn collect(&self, resource: &str, redirects: bool) -> Result<HttpEvidence, Error> {
        let mut url = parse_resource(resource)?;
        let deadline = Instant::now() + MAX_TIME;
        let (url, mut response) = timeout_at(deadline, async {
            for _ in 0..4 {
                self.active()?;
                if !self.allows(&url) {
                    return Err("outside approved scope");
                }
                let host = url.host_str().ok_or("missing host")?;
                let port = url.port_or_known_default().ok_or("missing port")?;
                let addr = lookup_host((host, port))
                    .await
                    .map_err(|_| "DNS unavailable")?
                    .find(|addr| {
                        #[cfg(test)]
                        if addr.ip().is_loopback() && Some(*addr) == self.fixture_peer {
                            return true;
                        }
                        matches!(addr.ip(), IpAddr::V4(ip) if public_v4(ip))
                    })
                    .ok_or("public IPv4 destination required")?;
                let client = Client::builder()
                    .no_proxy()
                    .redirect(Policy::none())
                    .resolve(host, addr)
                    .timeout(MAX_TIME)
                    .build()
                    .map_err(|_| "client unavailable")?;
                let response = client
                    .get(url.clone())
                    .send()
                    .await
                    .map_err(|_| "request failed")?;
                if response.remote_addr() != Some(addr) {
                    return Err("unexpected peer");
                }
                let status = response.status().as_u16();
                if !redirects && status != 200 {
                    return Err(match status {
                        300..=399 => "verification redirected",
                        401 | 403 => "verification forbidden",
                        404 => "verification file missing",
                        _ => "verification HTTP error",
                    });
                }
                if redirects && matches!(status, 301 | 302 | 303 | 307 | 308) {
                    let location = response
                        .headers()
                        .get("location")
                        .and_then(|h| h.to_str().ok())
                        .ok_or("invalid redirect")?;
                    url = self.redirect_target(&url, location)?;
                    continue;
                }
                return Ok((url, response));
            }
            Err("redirect limit reached")
        })
        .await
        .map_err(|_| "collection timed out")??;

        let mut headers = BTreeMap::new();
        for name in [
            "content-type",
            "strict-transport-security",
            "x-content-type-options",
        ] {
            let values: Vec<_> = response
                .headers()
                .get_all(name)
                .iter()
                .map(|v| v.to_str().unwrap_or("invalid"))
                .collect();
            if !values.is_empty() {
                headers.insert(name.to_owned(), values.join(","));
            }
        }
        let html = headers.get("content-type").is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/html"))
        });
        let body = if redirects && !html {
            String::new()
        } else {
            let (limit, size_error) = if redirects {
                (MAX_BODY, "response too large")
            } else {
                (256, "verification response too large")
            };
            match timeout_at(deadline, read_body(&mut response, limit, size_error)).await {
                Ok(Ok(body)) => body,
                // Only a complete HTML document can be evaluated, but its headers are useful.
                _ if redirects => String::new(),
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err("collection timed out"),
            }
        };
        self.active()?;
        Ok(HttpEvidence {
            final_url: url.to_string(),
            status: response.status().as_u16(),
            headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_scope_and_egress() {
        let scope = Scope::new("https://example.org/app", i64::MAX).unwrap();
        for url in [
            "https://example.org/application",
            "https://example.net/app",
            "https://example.org:8443/app",
            "http://example.org/app",
        ] {
            assert!(!scope.allows(&parse_resource(url).unwrap()));
        }
        assert!(scope.allows(&parse_resource("https://example.org/app/download").unwrap()));
        for url in [
            "http://example.org/app/%252e",
            "http://example.org/app/../admin",
            "http://user@example.org",
            "http://example.org/?password=example",
        ] {
            assert!(parse_resource(url).is_err());
        }
        for ip in [
            "127.0.0.1",
            "169.254.169.254",
            "10.1.1.1",
            "100.64.0.1",
            "192.0.2.1",
            "224.0.0.1",
        ] {
            assert!(!public_v4(ip.parse().unwrap()));
        }
        assert!(public_v4("8.8.8.8".parse().unwrap()));
        assert!(Scope::new("https://example.org", 0).is_err());
        assert_eq!(
            safe_url("https://user:pass@example.org/person/secret?token=x"),
            "https://example.org"
        );
        assert_eq!(
            scope.challenge_url(),
            "https://example.org/app/rustscope-verification.txt"
        );
    }

    #[test]
    fn separately_approved_https_origin() {
        let scope = Scope::new("http://example.org/app", i64::MAX)
            .unwrap()
            .with_upgrade(true)
            .unwrap();
        assert!(scope.contains("https://example.org/app/login"));
        assert!(!scope.contains("https://example.org:8080/app"));
        assert!(!scope.contains("https://example.org/outside"));
    }

    #[test]
    fn approved_upgrade_assesses_final_password_form() {
        use crate::{domain::Outcome, model::Policy, web};
        let scope = Scope::new("http://example.org/app", i64::MAX)
            .unwrap()
            .with_upgrade(true)
            .unwrap();
        let requested = parse_resource("http://example.org/app/login").unwrap();
        assert!(scope.allows(&requested));
        let final_url = scope
            .redirect_target(&requested, "https://example.org/app/sign-in")
            .unwrap();
        let evidence = HttpEvidence {
            final_url: final_url.to_string(),
            status: 200,
            headers: [("content-type".into(), "text/html".into())].into(),
            body: "<form id=login action='/submit'><input type=password></form>".into(),
        };
        let policy = Policy {
            download: false,
            hsts_min: None,
            sri: false,
            expected_form: Some("login".into()),
        };
        let results = web::evaluate(Ok(&evidence), &policy);
        for rule in ["A04-01", "A04-02"] {
            let outcomes: Vec<_> = results
                .iter()
                .filter(|obs| obs.rule == rule)
                .map(|obs| obs.outcome)
                .collect();
            assert_eq!(outcomes, [Outcome::Passed], "{rule}");
        }
    }

    #[tokio::test]
    async fn real_redirect_cannot_leave_approved_path() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let peer = listener.local_addr().unwrap();
        let base = format!("http://{peer}/approved");
        let mut scope = Scope::new(&base, i64::MAX).unwrap();
        scope.fixture_peer = Some(peer);
        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let mut count = 0;
            while !buf[..count].windows(4).any(|s| s == b"\r\n\r\n") {
                let n = conn.read(&mut buf[count..]).await.unwrap();
                assert!(n > 0);
                count += n;
            }
            assert!(buf.starts_with(b"GET /approved/start HTTP/1.1\r\n"));
            conn.write_all(b"HTTP/1.1 302 Found\r\nLocation: /outside\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            listener
        });
        let result = scope.fetch(&format!("{base}/start")).await;
        assert_eq!(result.err(), Some("outside approved scope"));
        let listener = server.await.unwrap().into_std().unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn large_download_retains_header_evidence() {
        use crate::{domain::Outcome, model::Policy, web};
        use axum::{Router, routing::get};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let peer = listener.local_addr().unwrap();
        let resource = format!("http://{peer}/download");
        let mut scope = Scope::new(&resource, i64::MAX).unwrap();
        scope.fixture_peer = Some(peer);
        let router = Router::new().route(
            "/download",
            get(|| async {
                (
                    [
                        ("content-type", "application/octet-stream"),
                        ("x-content-type-options", "nosniff"),
                    ],
                    vec![0u8; MAX_BODY + 1],
                )
            }),
        );
        let server = tokio::spawn(axum::serve(listener, router).into_future());
        let policy = Policy {
            download: true,
            hsts_min: None,
            sri: false,
            expected_form: None,
        };

        let response = scope.fetch(&resource).await;
        let results = web::evaluate(response.as_ref().map_err(|&err| err), &policy);
        server.abort();
        let header = results.iter().find(|obs| obs.rule == "A02-01").unwrap();
        assert_eq!(header.outcome, Outcome::Passed);
    }

    #[tokio::test]
    async fn oversized_html_retains_headers_without_using_the_body_prefix() {
        use crate::{domain::Outcome, model::Policy, web};
        use axum::{Router, response::Html, routing::get};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let peer = listener.local_addr().unwrap();
        let resource = format!("http://{peer}/download");
        let mut scope = Scope::new(&resource, i64::MAX).unwrap();
        scope.fixture_peer = Some(peer);
        let router = Router::new().route(
            "/download",
            get(|| async {
                let form = "<form id=login action='https://example.test/session'><input type=password></form>";
                (
                    [("x-content-type-options", "nosniff")],
                    Html(format!("{form}<!--{}-->", " ".repeat(MAX_BODY))),
                )
            }),
        );
        let server = tokio::spawn(axum::serve(listener, router).into_future());
        let policy = Policy {
            download: true,
            hsts_min: None,
            sri: true,
            expected_form: Some("login".into()),
        };

        let response = scope.fetch(&resource).await;
        let results = web::evaluate(response.as_ref().map_err(|&err| err), &policy);
        server.abort();
        for (rule, expected) in [
            ("A02-01", Outcome::Passed),
            ("A04-01", Outcome::Insufficient),
            ("A04-02", Outcome::Insufficient),
            ("A08-04", Outcome::Insufficient),
        ] {
            let outcomes: Vec<_> = results
                .iter()
                .filter(|obs| obs.rule == rule)
                .map(|obs| obs.outcome)
                .collect();
            assert_eq!(outcomes, [expected], "{rule}");
        }
    }

    #[tokio::test]
    async fn real_rescan_requires_a_visible_fixed_form() {
        use crate::{
            domain::{ChangeStatus, EvaluationProvenance, Round, compare},
            model::Policy,
            web,
        };
        use axum::{Router, http::StatusCode, response::Html, routing::get};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let peer = listener.local_addr().unwrap();
        async fn login(
            axum::extract::State(count): axum::extract::State<std::sync::Arc<AtomicUsize>>,
        ) -> (StatusCode, Html<&'static str>) {
            const INSECURE: &str =
                "<form id=login action='http://example.test/session'><input type=password></form>";
            const FIXED: &str =
                "<form id=login action='https://example.test/session'><input type=password></form>";
            match count.fetch_add(1, Ordering::SeqCst) {
                0 | 2 => (StatusCode::OK, Html(INSECURE)),
                1 => (StatusCode::FORBIDDEN, Html("")),
                3 => (StatusCode::OK, Html(FIXED)),
                _ => (StatusCode::NOT_FOUND, Html("")),
            }
        }
        let route = Router::new()
            .route("/login", get(login))
            .with_state(std::sync::Arc::new(AtomicUsize::new(0)));
        let server = tokio::spawn(axum::serve(listener, route).into_future());
        let resource = format!("http://{peer}/login");
        let mut scope = Scope::new(&resource, i64::MAX).unwrap();
        scope.fixture_peer = Some(peer);
        let policy = Policy {
            download: false,
            hsts_min: None,
            sri: false,
            expected_form: Some("login".into()),
        };
        let mut provenance = EvaluationProvenance::at_enqueue();
        provenance.record_web_evaluation();
        let mut results = Vec::new();
        for (status, expected) in [
            (200, ChangeStatus::New),
            (403, ChangeStatus::NotComparable),
            (200, ChangeStatus::Persistent),
            (200, ChangeStatus::VerifiedFixed),
        ] {
            let response = scope.fetch(&resource).await.unwrap();
            assert_eq!(response.status, status);
            results.push(web::evaluate(Ok(&response), &policy));
            let rounds = results
                .iter()
                .map(|r| Round {
                    project: "local",
                    target: &resource,
                    version: "1",
                    policy: "unchanged",
                    provenance: &provenance,
                    observations: r,
                })
                .collect::<Vec<_>>();
            let changes = compare(&rounds);
            let form = changes.iter().find(|v| v.rule == "A04-02").unwrap();
            assert_eq!(form.status, expected);
        }
        server.abort();
    }

    #[tokio::test]
    async fn verification_distinguishes_error_pages_from_token_files() {
        use axum::{Router, http::StatusCode, routing::get};
        const TOKEN: &str = "12345678901234567890123456789012";
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let peer = listener.local_addr().unwrap();
        let router = Router::new()
            .route(
                "/missing/rustscope-verification.txt",
                get(|| async { (StatusCode::NOT_FOUND, "error page".repeat(100)) }),
            )
            .route(
                "/fallback/rustscope-verification.txt",
                get(|| async { axum::response::Html("<p>fallback page</p>".repeat(100)) }),
            )
            .route(
                "/valid/rustscope-verification.txt",
                get(|| async { format!("{TOKEN}\n") }),
            );
        let server = tokio::spawn(axum::serve(listener, router).into_future());
        for (path, expected) in [
            ("missing", Err("verification file missing")),
            ("fallback", Err("verification response too large")),
            ("valid", Ok(())),
        ] {
            let mut scope = Scope::new(&format!("http://{peer}/{path}"), i64::MAX).unwrap();
            scope.fixture_peer = Some(peer);
            assert_eq!(scope.verify(TOKEN).await, expected);
        }
        server.abort();
    }

    #[tokio::test]
    async fn rejects_private_and_unapproved_before_connecting() {
        let scope = Scope::new("http://127.0.0.1/approved", i64::MAX).unwrap();
        assert_eq!(
            scope.fetch("http://127.0.0.1/other").await.err(),
            Some("outside approved scope")
        );
        assert_eq!(
            scope.fetch("http://127.0.0.1/approved/file").await.err(),
            Some("public IPv4 destination required")
        );
        assert_eq!(
            scope.verify("short").await.err(),
            Some("invalid verification token")
        );
    }
}
