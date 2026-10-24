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
