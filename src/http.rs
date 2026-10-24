use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};

use crate::db::Db;

pub const USER_AGENT: &str = concat!(
    "vuln-watch/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/Matuyuhi/vuln-watch)"
);

pub struct Http {
    client: Client,
}

pub struct Resp {
    pub status: u16,
    pub body: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
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
        if status == 304 {
            return Ok(Resp {
                status,
                body: String::new(),
                etag,
                last_modified,
            });
        }
        let body = resp
            .text()
            .with_context(|| format!("reading body of {url}"))?;
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
        })
    }
}
