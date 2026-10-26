//! Ubuntu Security Notices via the JSON API.
//!
//! Unlike the RSS feed this API is paged (so nothing is lost after downtime) and lists the
//! fixed package versions per release, which lets notices be matched against the packages
//! actually installed on this machine (`[installed]`).

use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Deserialize;

use super::{Ctx, Fetched};
use crate::http::Validators;
use crate::model::Item;
use crate::text::{collapse_ws, truncate};

pub const DEFAULT_URL: &str = "https://ubuntu.com/security/notices.json";
const PAGE_SIZE: usize = 20;
/// Walk back at most this many pages (PAGE_SIZE notices each) to the previous position.
const MAX_PAGES: usize = 25;

#[derive(Deserialize)]
struct Page {
    // Required: if the API renames the field, fail loudly instead of reading empty pages.
    notices: Vec<Notice>,
}

#[derive(Deserialize)]
struct Notice {
    id: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    cves_ids: Option<Vec<String>>,
    #[serde(default)]
    is_hidden: Option<bool>,
    #[serde(default)]
    release_packages: Option<HashMap<String, Vec<Package>>>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    is_source: Option<bool>,
}

fn page_url(base: &str, offset: usize, release: Option<&str>) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let mut url = format!("{base}{sep}limit={PAGE_SIZE}&offset={offset}");
    if let Some(r) = release {
        url.push_str("&release=");
        url.push_str(r);
    }
    url
}

pub fn fetch(name: &str, url: Option<&str>, release: Option<&str>, ctx: &Ctx) -> Result<Fetched> {
    let base = url.unwrap_or(DEFAULT_URL);
    let first = page_url(base, 0, release);
    let validators = Validators::load(ctx.db, &first)?;
    let resp = ctx.http.get(&first, &[], Some(&validators))?;
    if resp.not_modified() {
        return Ok(Fetched::empty());
    }
    let commit = Validators::commit_pairs(&first, &resp);

    let mut items = Vec::new();
    let mut body = resp.body;
    let mut page = 0;
    loop {
        let (parsed, raw_count) = parse(name, &body, release)?;
        let mut reached_seen = false;
        for item in &parsed {
            if ctx.db.is_seen(name, &item.id)? {
                reached_seen = true;
            }
        }
        items.extend(parsed);
        if ctx.bootstrap || ctx.limit.is_some() || reached_seen || raw_count < PAGE_SIZE {
            break;
        }
        page += 1;
        if page >= MAX_PAGES {
            tracing::warn!(
                "{name}: stopped after {MAX_PAGES} pages without reaching a known notice"
            );
            break;
        }
        body = ctx
            .http
            .get(&page_url(base, page * PAGE_SIZE, release), &[], None)?
            .body;
    }
    if page > 0 {
        tracing::info!("{name}: walked {} pages to catch up", page + 1);
    }
    Ok(Fetched {
        items,
        commit,
        ..Fetched::default()
    })
}

/// Parse one page. Returns the items (hidden notices skipped) and the raw notice count.
pub fn parse(source: &str, body: &str, release: Option<&str>) -> Result<(Vec<Item>, usize)> {
    let page: Page = serde_json::from_str(body).context("parsing Ubuntu notices")?;
    let raw = page.notices.len();
    let items = page
        .notices
        .into_iter()
        .filter(|n| !n.is_hidden.unwrap_or(false))
        .map(|n| to_item(source, n, release))
        .collect();
    Ok((items, raw))
}

fn to_item(source: &str, n: Notice, release: Option<&str>) -> Item {
    let mut item = Item::new(source, n.id.clone());
    let title = n.title.unwrap_or_default();
    item.title = if title.is_empty() {
        n.id.clone()
    } else {
        format!("{}: {}", n.id, title)
    };
    let text = n
        .description
        .filter(|d| !d.trim().is_empty())
        .or(n.summary)
        .unwrap_or_default();
    item.summary = truncate(&collapse_ws(&text), 800);
    item.url = format!("https://ubuntu.com/security/notices/{}", n.id);
    item.published = n.published;

    // A USN means "a patch is available"; keep it separate from CVE-based de-duplication.
    let cves = n.cves_ids.unwrap_or_default();
    if !cves.is_empty() {
        let shown: Vec<_> = cves.iter().take(8).cloned().collect();
        let mut v = shown.join(", ");
        if cves.len() > shown.len() {
            v.push_str(&format!(" 他{}件", cves.len() - shown.len()));
        }
        item.extra.push(("CVE".into(), v));
    }

    let mut releases: Vec<(String, Vec<Package>)> =
        n.release_packages.unwrap_or_default().into_iter().collect();
    releases.sort_by(|a, b| a.0.cmp(&b.0));
    if let Some(r) = release {
        releases.retain(|(k, _)| k == r);
    }
    for (_, pkgs) in &releases {
        for p in pkgs {
            if p.is_source.unwrap_or(false) {
                let label = format!("ubuntu:{}", p.name);
                if !item.products.contains(&label) {
                    item.products.push(label);
                }
            } else {
                if !item.packages.contains(&p.name) {
                    item.packages.push(p.name.clone());
                }
                if release.is_some() {
                    if let Some(v) = p.version.as_ref().filter(|v| !v.is_empty()) {
                        item.fixed.push((p.name.clone(), v.clone()));
                    }
                }
            }
        }
    }
    if !item.fixed.is_empty() {
        item.extra.push((
            "対処".into(),
            "sudo apt update && sudo apt upgrade（カーネル・libc 等は再起動も）".into(),
        ));
    }
    item
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "notices": [
        {
          "id": "USN-8954-1",
          "title": "zlib vulnerability",
          "summary": "zlib could be made to crash.",
          "description": "Ali Firas discovered that zlib incorrectly handled\ncertain writes.",
          "published": "2026-10-22T19:54:53.531412",
          "is_hidden": false,
          "cves_ids": ["CVE-2026-85091"],
          "cves": [{"id": "CVE-2026-85091", "notices_ids": ["USN-8954-1"]}],
          "instructions": "In general, a standard system update will make all the necessary changes.",
          "references": [],
          "release_packages": {
            "noble": [
              {"name": "zlib", "version": "1:1.3.dfsg-3.1ubuntu2.3", "description": "Lossless", "is_source": true},
              {"name": "zlib1g", "version": "1:1.3.dfsg-3.1ubuntu2.3", "is_source": false, "is_visible": true, "pocket": "security"},
              {"name": "zlib1g-dev", "version": "1:1.3.dfsg-3.1ubuntu2.3", "is_source": false, "is_visible": true, "pocket": "security"}
            ],
            "resolute": [
              {"name": "zlib", "version": "1:1.3.dfsg+really1.3.1-1ubuntu3.2", "is_source": true},
              {"name": "zlib1g", "version": "1:1.3.dfsg+really1.3.1-1ubuntu3.2", "is_source": false}
            ]
          }
        },
        {"id": "USN-1-1", "title": "hidden", "is_hidden": true}
      ],
      "offset": 0, "limit": 20, "total_results": 1616
    }"#;

    #[test]
    fn parses_notices_for_release() {
        let (items, raw) = parse("usn", SAMPLE, Some("noble")).unwrap();
        assert_eq!(raw, 2);
        assert_eq!(items.len(), 1);
        let i = &items[0];
        assert_eq!(i.id, "USN-8954-1");
        assert_eq!(i.title, "USN-8954-1: zlib vulnerability");
        assert_eq!(i.cve, None);
        assert_eq!(i.products, vec!["ubuntu:zlib"]);
        assert_eq!(i.packages, vec!["zlib1g", "zlib1g-dev"]);
        assert_eq!(
            i.fixed,
            vec![
                ("zlib1g".to_string(), "1:1.3.dfsg-3.1ubuntu2.3".to_string()),
                (
                    "zlib1g-dev".to_string(),
                    "1:1.3.dfsg-3.1ubuntu2.3".to_string()
                ),
            ]
        );
        assert!(i.summary.starts_with("Ali Firas discovered"));
        assert!(i
            .extra
            .iter()
            .any(|(k, v)| k == "CVE" && v == "CVE-2026-85091"));
        assert_eq!(i.url, "https://ubuntu.com/security/notices/USN-8954-1");
    }

    #[test]
    fn without_release_lists_all_packages_but_no_fixed_versions() {
        let (items, _) = parse("usn", SAMPLE, None).unwrap();
        assert_eq!(items[0].packages, vec!["zlib1g", "zlib1g-dev"]);
        assert!(items[0].fixed.is_empty());
    }

    #[test]
    fn page_without_notices_field_is_an_error() {
        assert!(parse("usn", r#"{"offset": 0, "limit": 20}"#, None).is_err());
        assert!(parse("usn", r#"{"items": [{"id": "USN-1-1"}]}"#, None).is_err());
        let (items, raw) = parse("usn", r#"{"notices": []}"#, None).unwrap();
        assert!(items.is_empty());
        assert_eq!(raw, 0);
    }

    #[test]
    fn builds_page_urls() {
        assert_eq!(
            page_url(DEFAULT_URL, 40, Some("noble")),
            "https://ubuntu.com/security/notices.json?limit=20&offset=40&release=noble"
        );
        assert_eq!(
            page_url("https://x/n.json?foo=1", 0, None),
            "https://x/n.json?foo=1&limit=20&offset=0"
        );
    }
}
