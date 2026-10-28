pub mod advisory;
pub mod cvelist;
pub mod feed;
pub mod ghsa;
pub mod kev;
pub mod usn;

use anyhow::Result;

use crate::config::{Config, SourceConfig, SourceKind};
use crate::db::Db;
use crate::http::Http;
use crate::model::Item;

pub struct Ctx<'a> {
    pub http: &'a Http,
    pub db: &'a Db,
    pub cfg: &'a Config,
    pub github_token: Option<String>,
    /// First run for this source: only record the current state, don't fetch details.
    pub bootstrap: bool,
    /// Dry-run: cap the number of items returned.
    pub limit: Option<usize>,
    /// Ubuntu release of this machine (from `[installed]`), used by `usn` sources.
    pub release: Option<String>,
}

#[derive(Default)]
pub struct Fetched {
    pub items: Vec<Item>,
    /// kv pairs (cursors, ETags) to persist after the items have been handled.
    pub commit: Vec<(String, String)>,
    /// kv keys to delete together with `commit`.
    pub remove: Vec<String>,
}

impl Fetched {
    pub fn empty() -> Self {
        Self::default()
    }
}

pub fn fetch(src: &SourceConfig, ctx: &Ctx) -> Result<Fetched> {
    let name = src.name();
    let mut fetched = match src.kind {
        SourceKind::Kev => kev::fetch(&name, src.url.as_deref(), ctx),
        SourceKind::Ghsa => ghsa::fetch(&name, src.url.as_deref(), ctx),
        SourceKind::Cvelist => cvelist::fetch(&name, src.url.as_deref(), ctx),
        SourceKind::Feed => feed::fetch(&name, src.url.as_deref().unwrap_or_default(), ctx),
        SourceKind::Usn => usn::fetch(
            &name,
            src.url.as_deref(),
            src.release.as_deref().or(ctx.release.as_deref()),
            ctx,
        ),
        SourceKind::Advisory => {
            advisory::fetch(&name, src.url.as_deref(), src.branch.as_deref(), ctx)
        }
    }?;
    if !src.ignore_title_prefixes.is_empty() {
        let prefixes: Vec<String> = src
            .ignore_title_prefixes
            .iter()
            .map(|p| p.to_lowercase())
            .collect();
        fetched.items.retain(|item| {
            let title = item.title.trim_start().to_lowercase();
            !prefixes.iter().any(|p| title.starts_with(p.as_str()))
        });
    }
    if let Some(limit) = ctx.limit {
        fetched.items.truncate(limit);
    }
    Ok(fetched)
}

/// `Authorization` header for `url` when it is `https://api.github.com/...`; `None` for any
/// other scheme, host or port, so a mistyped or mirror URL never receives the token.
pub fn github_auth(url: &str, token: &str) -> Option<(&'static str, String)> {
    let url = reqwest::Url::parse(url).ok()?;
    let github = url.scheme() == "https"
        && url.host_str() == Some("api.github.com")
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    github.then(|| ("Authorization", format!("Bearer {token}")))
}

/// `GITHUB_TOKEN` of one source fetch: sent only where `github_auth` allows, with one
/// warning per fetch when it is withheld.
pub struct GithubAuth<'a> {
    name: &'a str,
    token: Option<&'a str>,
    warned: std::cell::Cell<bool>,
}

impl<'a> GithubAuth<'a> {
    pub fn new(name: &'a str, token: Option<&'a str>) -> Self {
        Self {
            name,
            token,
            warned: std::cell::Cell::new(false),
        }
    }

    /// `base` plus the `Authorization` header when `url` may receive the token.
    pub fn headers(
        &self,
        url: &str,
        base: &[(&'static str, String)],
    ) -> Vec<(&'static str, String)> {
        let mut headers = base.to_vec();
        let Some(token) = self.token else {
            return headers;
        };
        match github_auth(url, token) {
            Some(h) => headers.push(h),
            None if !self.warned.replace(true) => {
                // Scheme, host and port only: no path, query or credentials of the URL.
                let origin = reqwest::Url::parse(url)
                    .map(|u| u.origin().ascii_serialization())
                    .unwrap_or_else(|_| "an unparsable URL".into());
                tracing::warn!(
                    "{}: GITHUB_TOKEN not sent to {origin} (only https://api.github.com)",
                    self.name
                );
            }
            None => {}
        }
        headers
    }
}

/// Map a severity label to a representative CVSS score when no numeric score exists.
pub fn severity_to_score(label: &str) -> Option<f32> {
    match label.to_ascii_lowercase().as_str() {
        "critical" => Some(9.0),
        "high" => Some(7.0),
        "medium" | "moderate" => Some(5.0),
        "low" => Some(2.0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_auth_only_for_https_api_github_com() {
        let h = github_auth("https://api.github.com/advisories?per_page=100", "t").unwrap();
        assert_eq!(h, ("Authorization", "Bearer t".to_string()));
        assert!(github_auth("https://API.GitHub.com/repos/o/r", "t").is_some());
        assert!(github_auth("https://api.github.com:443/repos/o/r", "t").is_some());
        for url in [
            "http://api.github.com/advisories",
            "https://api.github.com.evil.example/advisories",
            "https://mirror.example/api.github.com/advisories",
            "https://github.com/o/r",
            "https://api.github.com:8443/advisories",
            "https://user@api.github.com/advisories",
            "http://127.0.0.1:1234/repos/o/r",
            "not a url",
        ] {
            assert!(github_auth(url, "t").is_none(), "{url}");
        }
    }

    #[test]
    fn github_auth_headers_keep_base_and_add_token_only_for_github() {
        let base = [("Accept", "application/json".to_string())];
        let auth = GithubAuth::new("s", Some("t"));
        let gh = auth.headers("https://api.github.com/advisories", &base);
        assert_eq!(gh.len(), 2);
        assert!(gh
            .iter()
            .any(|(k, v)| *k == "Authorization" && v == "Bearer t"));
        let other = auth.headers("https://other.example/advisories?page=2", &base);
        assert_eq!(other, base.to_vec());
        let none = GithubAuth::new("s", None).headers("https://api.github.com/x", &base);
        assert_eq!(none, base.to_vec());
    }
}
