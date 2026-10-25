//! Advisories written by the scheduled Claude research, one TOML file per advisory under
//! `advisories/` of a GitHub repository branch. Only files whose blob SHA changed since the
//! last run are downloaded.

use anyhow::{bail, Context, Result};
use chrono::NaiveDate;
use serde::Deserialize;

use super::{Ctx, Fetched};
use crate::http::Validators;
use crate::model::{Confidence, Item};
use crate::text::{collapse_ws, truncate};

pub const DEFAULT_URL: &str = "https://github.com/Matuyuhi/vuln-watch";
pub const DEFAULT_BRANCH: &str = "advisories";
const DIR: &str = "advisories/";
/// Upper bound of advisory files downloaded per run; the rest follow on later runs.
const MAX_FILES_PER_RUN: usize = 50;

#[derive(Deserialize)]
struct Tree {
    #[serde(default)]
    tree: Vec<TreeEntry>,
    #[serde(default)]
    truncated: bool,
}

#[derive(Deserialize)]
struct TreeEntry {
    path: String,
    #[serde(rename = "type")]
    kind: String,
    sha: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Advisory {
    id: String,
    revision: u32,
    status: Status,
    published: toml::value::Datetime,
    #[serde(default)]
    updated: Option<toml::value::Datetime>,
    expires: toml::value::Datetime,
    severity: Severity,
    confidence: Confidence,
    title: String,
    summary: String,
    #[serde(default)]
    affects: Vec<Affected>,
    #[serde(default)]
    cves: Vec<String>,
    #[serde(default)]
    actions: Vec<String>,
    references: Vec<Reference>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Active,
    Resolved,
    Withdrawn,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Affected {
    name: String,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    fixed_versions: Vec<String>,
    #[serde(default)]
    deb: Vec<DebFix>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DebFix {
    package: String,
    fixed_version: String,
    /// Ubuntu codename the version applies to. Unset = any release.
    #[serde(default)]
    release: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RefKind {
    Primary,
    Secondary,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    url: String,
    kind: RefKind,
    #[serde(default)]
    title: Option<String>,
    /// Verbatim excerpt of the page, checked by the advisory repository's CI.
    #[serde(default)]
    #[allow(dead_code)]
    quote: Option<String>,
}

/// API base and web base of a repository URL:
/// `https://github.com/o/r` -> (`https://api.github.com/repos/o/r`, `https://github.com/o/r`).
/// Any other URL is taken as the API base itself (GitHub Enterprise, tests).
fn repo_urls(url: &str) -> Result<(String, String)> {
    let url = url.trim_end_matches('/').trim_end_matches(".git");
    if let Some(rest) = url.strip_prefix("https://github.com/") {
        let mut parts = rest.split('/');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(o), Some(r), None) if !o.is_empty() && !r.is_empty() => {
                return Ok((
                    format!("https://api.github.com/repos/{o}/{r}"),
                    format!("https://github.com/{o}/{r}"),
                ))
            }
            _ => bail!("advisory url must be https://github.com/<owner>/<repo>, got {url}"),
        }
    }
    Ok((url.to_string(), url.to_string()))
}

fn sha_key(name: &str, path: &str) -> String {
    format!("advisory:{name}:{path}")
}

pub fn fetch(name: &str, url: Option<&str>, branch: Option<&str>, ctx: &Ctx) -> Result<Fetched> {
    let (api, web) = repo_urls(url.unwrap_or(DEFAULT_URL))?;
    let branch = branch.unwrap_or(DEFAULT_BRANCH);
    let mut headers = vec![
        ("Accept", "application/vnd.github+json".to_string()),
        ("X-GitHub-Api-Version", "2022-11-28".to_string()),
    ];
    if let Some(token) = &ctx.github_token {
        headers.push(("Authorization", format!("Bearer {token}")));
    }

    let tree_url = format!("{api}/git/trees/{branch}?recursive=1");
    let validators = Validators::load(ctx.db, &tree_url)?;
    let resp = ctx.http.get(&tree_url, &headers, Some(&validators))?;
    if resp.not_modified() {
        return Ok(Fetched::empty());
    }
    let tree: Tree = serde_json::from_str(&resp.body).context("parsing repository tree")?;
    if tree.truncated {
        tracing::warn!("{name}: repository tree is truncated; some advisories may be missed");
    }

    let mut changed = Vec::new();
    for e in tree.tree {
        if e.kind != "blob" || !e.path.starts_with(DIR) || !e.path.ends_with(".toml") {
            continue;
        }
        if ctx.db.get_kv(&sha_key(name, &e.path))?.as_deref() != Some(e.sha.as_str()) {
            changed.push(e);
        }
    }
    // Remember the tree only once every changed file has been read, so a capped run
    // fetches the tree again next time instead of getting 304.
    let mut commit = if changed.len() <= MAX_FILES_PER_RUN {
        Validators::commit_pairs(&tree_url, &resp)
    } else {
        tracing::info!(
            "{name}: {} changed advisories, reading {MAX_FILES_PER_RUN} this run",
            changed.len()
        );
        changed.truncate(MAX_FILES_PER_RUN);
        Vec::new()
    };

    let mut raw_headers = headers.clone();
    raw_headers[0].1 = "application/vnd.github.raw+json".to_string();
    let today = chrono::Utc::now().date_naive();
    let mut items = Vec::new();
    for e in changed {
        let blob = ctx
            .http
            .get(&format!("{api}/git/blobs/{}", e.sha), &raw_headers, None)?;
        let html_url = format!("{web}/blob/{branch}/{}", e.path);
        // A broken file is skipped, not retried: fixing it changes its SHA.
        match parse(
            name,
            &e.path,
            &blob.body,
            &html_url,
            ctx.release.as_deref(),
            today,
        ) {
            Ok(Some(item)) => items.push(item),
            Ok(None) => {}
            Err(err) => tracing::warn!("{name}: skipping {}: {err:#}", e.path),
        }
        commit.push((sha_key(name, &e.path), e.sha));
    }
    Ok(Fetched { items, commit })
}

fn to_date(d: &toml::value::Datetime) -> Result<NaiveDate> {
    let date = d.date.context("expected a date such as 2026-10-25")?;
    NaiveDate::from_ymd_opt(date.year.into(), date.month.into(), date.day.into())
        .context("invalid date")
}

/// Parse one advisory file. `Ok(None)` for advisories that are no longer active or expired.
fn parse(
    source: &str,
    path: &str,
    body: &str,
    html_url: &str,
    release: Option<&str>,
    today: NaiveDate,
) -> Result<Option<Item>> {
    let a: Advisory = toml::from_str(body).context("invalid advisory")?;
    let stem = path
        .rsplit('/')
        .next()
        .and_then(|f| f.strip_suffix(".toml"))
        .unwrap_or_default();
    if a.id != stem {
        bail!("id `{}` does not match the file name", a.id);
    }
    if a.revision == 0 || a.title.trim().is_empty() {
        bail!("revision must be >= 1 and title must not be empty");
    }
    if a.references.is_empty() {
        bail!("no references");
    }
    let published = to_date(&a.published)?;
    let expires = to_date(&a.expires)?;
    if a.status != Status::Active || expires < today {
        return Ok(None);
    }

    let mut item = Item::new(source, format!("{}@r{}", a.id, a.revision));
    item.title = a.title.trim().to_string();
    item.summary = truncate(&collapse_ws(&a.summary), 800);
    item.url = html_url.to_string();
    item.severity = Some(a.severity.as_str().to_string());
    item.published = Some(match &a.updated {
        Some(u) => to_date(u)?.to_string(),
        None => published.to_string(),
    });
    // Without a primary source the advisory is treated as unverified, whatever it claims.
    let has_primary = a.references.iter().any(|r| r.kind == RefKind::Primary);
    item.confidence = Some(if has_primary {
        a.confidence
    } else {
        Confidence::Unverified
    });

    let mut fixed_versions = Vec::new();
    for af in &a.affects {
        item.products.push(af.name.clone());
        item.products.extend(af.keywords.iter().cloned());
        item.packages.extend(af.packages.iter().cloned());
        if !af.fixed_versions.is_empty() {
            fixed_versions.push(format!("{}: {}", af.name, af.fixed_versions.join(", ")));
        }
        for d in &af.deb {
            if d.release.is_none() || d.release.as_deref() == release {
                item.fixed
                    .push((d.package.clone(), d.fixed_version.clone()));
            }
        }
    }

    if !a.actions.is_empty() {
        let actions: Vec<String> = a
            .actions
            .iter()
            .map(|s| format!("・{}", s.trim()))
            .collect();
        item.extra.push(("対策".into(), actions.join("\n")));
    }
    if !fixed_versions.is_empty() {
        item.extra
            .push(("修正版".into(), fixed_versions.join("\n")));
    }
    let mut refs: Vec<&Reference> = a.references.iter().collect();
    refs.sort_by_key(|r| r.kind != RefKind::Primary);
    let refs: Vec<String> = refs
        .iter()
        .take(5)
        .map(|r| match &r.title {
            Some(t) => format!("[{}](<{}>)", t.replace(['[', ']'], ""), r.url),
            None => r.url.clone(),
        })
        .collect();
    item.extra.push(("出典".into(), refs.join("\n")));
    if !a.cves.is_empty() {
        item.extra.push(("CVE".into(), a.cves.join(", ")));
    }
    item.extra.push(("期限".into(), expires.to_string()));
    Ok(Some(item))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "advisories/2026/VWA-2026-1025-emudhra.toml";
    const URL: &str =
        "https://github.com/o/r/blob/advisories/advisories/2026/VWA-2026-1025-emudhra.toml";

    const ADVISORY: &str = r#"
id = "VWA-2026-1025-emudhra"
revision = 2
status = "active"
published = 2026-10-25
updated = 2026-10-26
expires = 2026-11-24
severity = "high"
confidence = "confirmed"
title = "Electron apps and CA bundles must be updated"
summary = """
Eight intermediate CA keys
were compromised."""
cves = []
actions = ["Update Electron apps", "Update ca-certificates"]

[[affects]]
name = "Electron"
keywords = ["electron"]
packages = ["npm:electron"]
fixed_versions = ["44.9.1", "43.8.1"]

[[affects]]
name = "ca-certificates"
deb = [
  { package = "ca-certificates", fixed_version = "20260101~24.04.1", release = "noble" },
  { package = "ca-certificates", fixed_version = "20260101~22.04.1", release = "jammy" },
]

[[references]]
url = "https://example.com/vendor"
kind = "primary"
title = "Vendor notice"
quote = "the keys were compromised"

[[references]]
url = "https://example.com/news"
kind = "secondary"
"#;

    fn day(s: &str) -> NaiveDate {
        s.parse().unwrap()
    }

    #[test]
    fn parses_advisory() {
        let item = parse("adv", PATH, ADVISORY, URL, Some("noble"), day("2026-10-25"))
            .unwrap()
            .unwrap();
        assert_eq!(item.id, "VWA-2026-1025-emudhra@r2");
        assert_eq!(item.cve, None);
        assert_eq!(item.url, URL);
        assert_eq!(item.summary, "Eight intermediate CA keys were compromised.");
        assert_eq!(item.severity.as_deref(), Some("high"));
        assert_eq!(item.confidence, Some(Confidence::Confirmed));
        assert_eq!(item.published.as_deref(), Some("2026-10-26"));
        assert_eq!(
            item.products,
            vec!["Electron", "electron", "ca-certificates"]
        );
        assert_eq!(item.packages, vec!["npm:electron"]);
        assert_eq!(
            item.fixed,
            vec![(
                "ca-certificates".to_string(),
                "20260101~24.04.1".to_string()
            )]
        );
        let extra: std::collections::HashMap<_, _> = item.extra.iter().cloned().collect();
        assert_eq!(
            extra["対策"],
            "・Update Electron apps\n・Update ca-certificates"
        );
        assert_eq!(extra["修正版"], "Electron: 44.9.1, 43.8.1");
        assert!(extra["出典"].starts_with("[Vendor notice](<https://example.com/vendor>)"));
        assert_eq!(extra["期限"], "2026-11-24");
    }

    #[test]
    fn skips_expired_and_inactive() {
        assert!(parse("adv", PATH, ADVISORY, URL, None, day("2026-11-25"))
            .unwrap()
            .is_none());
        let resolved = ADVISORY.replace("status = \"active\"", "status = \"resolved\"");
        assert!(parse("adv", PATH, &resolved, URL, None, day("2026-10-25"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn without_primary_source_is_unverified() {
        let body = ADVISORY.replace("kind = \"primary\"", "kind = \"secondary\"");
        let item = parse("adv", PATH, &body, URL, None, day("2026-10-25"))
            .unwrap()
            .unwrap();
        assert_eq!(item.confidence, Some(Confidence::Unverified));
    }

    #[test]
    fn rejects_mismatched_id_and_unknown_fields() {
        let other = "advisories/2026/VWA-2026-1025-other.toml";
        assert!(parse("adv", other, ADVISORY, URL, None, day("2026-10-25")).is_err());
        let body = format!("{ADVISORY}\nunknown = 1\n");
        assert!(parse("adv", PATH, &body, URL, None, day("2026-10-25")).is_err());
    }

    #[test]
    fn repo_urls_from_github_url() {
        assert_eq!(
            repo_urls("https://github.com/Matuyuhi/vuln-watch.git/").unwrap(),
            (
                "https://api.github.com/repos/Matuyuhi/vuln-watch".to_string(),
                "https://github.com/Matuyuhi/vuln-watch".to_string()
            )
        );
        assert!(repo_urls("https://github.com/Matuyuhi").is_err());
    }

    fn serve(routes: Vec<(String, String)>) -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap() == 0 || h == "\r\n" {
                        break;
                    }
                }
                let (status, body) = routes
                    .iter()
                    .find(|(p, _)| path.contains(p.as_str()))
                    .map(|(_, b)| (200, b.as_str()))
                    .unwrap_or((404, "not found"));
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        format!("http://{addr}/repos/o/r")
    }

    #[test]
    fn fetches_only_changed_files() {
        let tree = format!(
            r#"{{"sha": "t", "truncated": false, "tree": [
                {{"path": "advisories", "type": "tree", "sha": "d"}},
                {{"path": "{PATH}", "type": "blob", "sha": "aaa"}},
                {{"path": "advisories/2026/VWA-2026-1020-old.toml", "type": "blob", "sha": "bbb"}},
                {{"path": "README.md", "type": "blob", "sha": "ccc"}}
            ]}}"#
        );
        let body = ADVISORY.replace("expires = 2026-11-24", "expires = 2999-01-01");
        let base = serve(vec![
            ("/git/trees/advisories".into(), tree),
            ("/git/blobs/aaa".into(), body),
        ]);
        let db = crate::db::Db::open_in_memory().unwrap();
        db.set_kv(
            &sha_key("adv", "advisories/2026/VWA-2026-1020-old.toml"),
            "bbb",
        )
        .unwrap();
        let cfg = crate::config::Config::parse("").unwrap();
        let http = crate::http::Http::new(5).unwrap();
        let ctx = Ctx {
            http: &http,
            db: &db,
            cfg: &cfg,
            github_token: None,
            bootstrap: false,
            limit: None,
            release: None,
        };
        let fetched = fetch("adv", Some(&base), None, &ctx).unwrap();
        let ids: Vec<_> = fetched.items.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, vec!["VWA-2026-1025-emudhra@r2"]);
        assert_eq!(
            fetched.items[0].url,
            format!("{base}/blob/advisories/{PATH}")
        );
        assert!(fetched
            .commit
            .contains(&(sha_key("adv", PATH), "aaa".to_string())));
    }
}
