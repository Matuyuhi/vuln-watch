use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::header::{HeaderName, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LINK};

use crate::db::Db;

pub const USER_AGENT: &str = concat!(
    "vuln-watch/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/Matuyuhi/vuln-watch)"
);

/// Upper bound for a response body; a hostile or broken feed must not exhaust memory.
const MAX_BODY_BYTES: u64 = 64 * 1024 * 1024;

pub struct Http {
    client: Client,
}

pub struct Resp {
    pub status: u16,
    pub body: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// RFC 8288 Link header (pagination).
    pub link: Option<String>,
    /// `X-RateLimit-Remaining` (GitHub API).
    pub rate_remaining: Option<u32>,
}

impl Resp {
    pub fn not_modified(&self) -> bool {
        self.status == 304
    }
}

/// Conditional-request validators remembered per URL.
#[derive(Debug, Default, Clone)]
pub struct Validators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl Validators {
    fn etag_key(url: &str) -> String {
        format!("etag:{url}")
    }
    fn lm_key(url: &str) -> String {
        format!("lastmod:{url}")
    }

    pub fn load(db: &Db, url: &str) -> Result<Self> {
        Ok(Self {
            etag: db.get_kv(&Self::etag_key(url))?,
            last_modified: db.get_kv(&Self::lm_key(url))?,
        })
    }

    /// Key/value pairs to persist once the response has been fully processed.
    pub fn commit_pairs(url: &str, resp: &Resp) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if let Some(e) = &resp.etag {
            out.push((Self::etag_key(url), e.clone()));
        }
        if let Some(l) = &resp.last_modified {
            out.push((Self::lm_key(url), l.clone()));
        }
        out
    }
}

impl Http {
    pub fn new(timeout_secs: u64) -> Result<Self> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(timeout_secs))
            .connect_timeout(Duration::from_secs(10))
            .gzip(true)
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self { client })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    /// GET a URL that is itself a secret (heartbeat check-in URLs embed a token): errors never
    /// carry the URL, so they are safe to log.
    pub fn ping(&self, url: &str) -> Result<()> {
        let resp = self
            .client
            .get(url)
            .send()
            .map_err(|e| e.without_url())
            .context("heartbeat request failed")?;
        let status = resp.status();
        if !status.is_success() {
            bail!("heartbeat endpoint returned HTTP {}", status.as_u16());
        }
        Ok(())
    }

    /// GET with optional extra headers and conditional validators.
    /// Returns an error for anything except 2xx and 304.
    pub fn get(
        &self,
        url: &str,
        headers: &[(&str, String)],
        validators: Option<&Validators>,
    ) -> Result<Resp> {
        let mut req: RequestBuilder = self.client.get(url);
        for (k, v) in headers {
            req = req.header(*k, v.as_str());
        }
        if let Some(v) = validators {
            if let Some(e) = &v.etag {
                req = req.header(IF_NONE_MATCH, e.as_str());
            }
            if let Some(l) = &v.last_modified {
                req = req.header(IF_MODIFIED_SINCE, l.as_str());
            }
        }
        let resp = req.send().with_context(|| format!("GET {url}"))?;
        let status = resp.status().as_u16();
        let header = |name: reqwest::header::HeaderName| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let etag = header(ETAG);
        let last_modified = header(LAST_MODIFIED);
        let link = header(LINK);
        let rate_remaining = header(HeaderName::from_static("x-ratelimit-remaining"))
            .and_then(|v| v.trim().parse().ok());
        if status == 304 {
            return Ok(Resp {
                status,
                body: String::new(),
                etag,
                last_modified,
                link,
                rate_remaining,
            });
        }
        let body = read_capped(resp).with_context(|| format!("reading body of {url}"))?;
        if !(200..300).contains(&status) {
            bail!(
                "GET {url} returned HTTP {status}: {}",
                crate::text::truncate(&body, 300)
            );
        }
        Ok(Resp {
            status,
            body,
            etag,
            last_modified,
            link,
            rate_remaining,
        })
    }
}

/// Read a body as text, failing instead of buffering more than `MAX_BODY_BYTES`.
fn read_capped(resp: reqwest::blocking::Response) -> Result<String> {
    if resp.content_length().is_some_and(|n| n > MAX_BODY_BYTES) {
        bail!("response body larger than {MAX_BODY_BYTES} bytes");
    }
    read_text_capped(resp, MAX_BODY_BYTES)
}

/// Bounded read applied to the decoded stream, so it also covers chunked and gzip responses.
/// Invalid UTF-8 is rejected rather than lossily expanded (which could triple memory use).
fn read_text_capped(reader: impl std::io::Read, limit: u64) -> Result<String> {
    use std::io::Read;
    let mut buf = Vec::new();
    reader.take(limit + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > limit {
        bail!("response body larger than {limit} bytes");
    }
    String::from_utf8(buf).map_err(|_| anyhow::anyhow!("response body is not valid UTF-8"))
}

/// Extract the `rel="next"` URL from a Link header.
pub fn next_link(link: &str) -> Option<String> {
    link.split(',').find_map(|part| {
        let mut pieces = part.split(';');
        let url = pieces.next()?.trim();
        let is_next = pieces.any(|p| {
            let p = p.trim();
            p == "rel=\"next\"" || p == "rel=next"
        });
        (is_next && url.starts_with('<') && url.ends_with('>'))
            .then(|| url[1..url.len() - 1].to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_next_link() {
        let h = r#"<https://api.github.com/advisories?after=abc&per_page=100>; rel="next", <https://api.github.com/advisories?before=xyz>; rel="prev""#;
        assert_eq!(
            next_link(h).as_deref(),
            Some("https://api.github.com/advisories?after=abc&per_page=100")
        );
        assert_eq!(next_link(r#"<https://x>; rel="prev""#), None);
    }

    #[test]
    fn body_cap_accepts_limit_and_rejects_above() {
        assert_eq!(read_text_capped(&b"abcd"[..], 4).unwrap(), "abcd");
        assert!(read_text_capped(&b"abcde"[..], 4).is_err());
    }

    #[test]
    fn body_cap_rejects_invalid_utf8() {
        assert!(read_text_capped(&[0xffu8; 4][..], 8).is_err());
    }
}
