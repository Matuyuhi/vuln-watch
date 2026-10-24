//! GitHub Advisory Database (global advisories REST API).

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::{severity_to_score, Ctx, Fetched};
use crate::http::{next_link, Validators};
use crate::model::Item;
use crate::text::{collapse_ws, truncate};

/// Sorted by `updated`, not `published`: advisories imported from NVD keep their original
/// `published_at` when GitHub reviews them later, so a published-sorted list would never
/// show them on the first page.
pub const DEFAULT_URL: &str =
    "https://api.github.com/advisories?type=reviewed&sort=updated&direction=desc&per_page=100";
/// Upper bound of pages walked back to the previous position (100 advisories per page).
const MAX_PAGES: usize = 20;

#[derive(Deserialize)]
struct Advisory {
    ghsa_id: String,
    cve_id: Option<String>,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
    #[serde(default)]
    withdrawn_at: Option<String>,
    #[serde(default)]
    vulnerabilities: Option<Vec<Vulnerability>>,
    #[serde(default)]
    cvss: Option<Cvss>,
    #[serde(default)]
    cvss_severities: Option<CvssSeverities>,
    #[serde(default)]
    epss: Option<Epss>,
}

#[derive(Deserialize)]
struct Vulnerability {
    package: Option<Package>,
    #[serde(default)]
    first_patched_version: Option<String>,
    #[serde(default)]
    vulnerable_version_range: Option<String>,
}

#[derive(Deserialize)]
struct Package {
    #[serde(default)]
    ecosystem: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct Cvss {
    score: Option<f32>,
}

#[derive(Deserialize)]
struct CvssSeverities {
    cvss_v3: Option<Cvss>,
    cvss_v4: Option<Cvss>,
}

#[derive(Deserialize)]
struct Epss {
    percentage: Option<f64>,
}

fn cursor_key(name: &str) -> String {
    format!("ghsa:{name}:updated_cursor")
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

pub fn fetch(name: &str, url: Option<&str>, ctx: &Ctx) -> Result<Fetched> {
    let first_url = url.unwrap_or(DEFAULT_URL);
    let mut headers = vec![
        ("Accept", "application/vnd.github+json".to_string()),
        ("X-GitHub-Api-Version", "2022-11-28".to_string()),
    ];
    if let Some(token) = &ctx.github_token {
        headers.push(("Authorization", format!("Bearer {token}")));
    }
    let cursor = ctx
        .db
        .get_kv(&cursor_key(name))?
        .as_deref()
        .and_then(parse_time);

    let validators = Validators::load(ctx.db, first_url)?;
    let mut resp = ctx.http.get(first_url, &headers, Some(&validators))?;
    if resp.not_modified() {
        return Ok(Fetched::empty());
    }
    let mut commit = Validators::commit_pairs(first_url, &resp);

    let mut items = Vec::new();
    let mut newest = cursor;
    let mut page = 1;
    loop {
        let parsed = parse_page(name, &resp.body)?;
        let reached_cursor = parsed
            .iter()
            .any(|(_, t)| matches!((t, cursor), (Some(t), Some(c)) if *t <= c));
        for (item, t) in parsed {
            if let Some(t) = t {
                newest = Some(newest.map_or(t, |n| n.max(t)));
            }
            if let Some(item) = item {
                items.push(item);
            }
        }
        // Without a cursor (first run / dry-run) one page is enough.
        if cursor.is_none() || ctx.bootstrap || ctx.limit.is_some() || reached_cursor {
            break;
        }
        let Some(next) = resp.link.as_deref().and_then(next_link) else {
            break;
        };
        if page >= MAX_PAGES {
            tracing::warn!(
                "{name}: stopped after {MAX_PAGES} pages without reaching the previous position"
            );
            break;
        }
        page += 1;
        resp = ctx.http.get(&next, &headers, None)?;
    }
    if page > 1 {
        tracing::info!("{name}: walked {page} pages to catch up");
    }
    if let Some(n) = newest {
        commit.push((cursor_key(name), n.to_rfc3339()));
    }
    Ok(Fetched { items, commit })
}

fn max_score(scores: impl IntoIterator<Item = Option<f32>>) -> Option<f32> {
    scores
        .into_iter()
        .flatten()
        .filter(|s| *s > 0.0)
        .fold(None, |acc: Option<f32>, s| {
            Some(acc.map_or(s, |a| a.max(s)))
        })
}

#[cfg(test)]
pub fn parse(source: &str, body: &str) -> Result<Vec<Item>> {
    Ok(parse_page(source, body)?
        .into_iter()
        .filter_map(|(i, _)| i)
        .collect())
}

/// Each advisory with its `updated_at`; withdrawn advisories yield `None` for the item.
#[allow(clippy::type_complexity)]
fn parse_page(source: &str, body: &str) -> Result<Vec<(Option<Item>, Option<DateTime<Utc>>)>> {
    let advisories: Vec<Advisory> =
        serde_json::from_str(body).context("parsing GitHub advisories")?;
    Ok(advisories
        .into_iter()
        .map(|a| {
            let updated = a.updated_at.as_deref().and_then(parse_time);
            if a.withdrawn_at.is_some() {
                (None, updated)
            } else {
                (Some(to_item(source, a)), updated)
            }
        })
        .collect())
}

fn to_item(source: &str, a: Advisory) -> Item {
    let mut item = Item::new(source, a.ghsa_id.clone());
    item.cve = a.cve_id.filter(|c| !c.is_empty());
    item.title = a.summary;
    item.summary = truncate(&collapse_ws(a.description.as_deref().unwrap_or("")), 600);
    item.url = if a.html_url.is_empty() {
        format!("https://github.com/advisories/{}", a.ghsa_id)
    } else {
        a.html_url
    };
    let sev = a.cvss_severities.as_ref();
    item.cvss = max_score([
        a.cvss.as_ref().and_then(|c| c.score),
        sev.and_then(|s| s.cvss_v3.as_ref()).and_then(|c| c.score),
        sev.and_then(|s| s.cvss_v4.as_ref()).and_then(|c| c.score),
    ])
    .or_else(|| a.severity.as_deref().and_then(severity_to_score));
    item.severity = a.severity;
    item.published = a.published_at;

    let mut patched = Vec::new();
    for v in a.vulnerabilities.unwrap_or_default() {
        if let Some(p) = v.package {
            if p.name.is_empty() {
                continue;
            }
            let label = format!("{}:{}", p.ecosystem, p.name);
            if !item.products.contains(&label) {
                item.products.push(label);
            }
            if !item.packages.contains(&p.name) {
                item.packages.push(p.name.clone());
            }
            let range = v.vulnerable_version_range.unwrap_or_default();
            match v.first_patched_version.filter(|s| !s.is_empty()) {
                Some(fix) => patched.push(format!("{} {} → {}", p.name, range, fix)),
                None => patched.push(format!("{} {} → 修正版なし", p.name, range)),
            }
        }
    }
    if !patched.is_empty() {
        item.extra
            .push(("修正バージョン".into(), truncate(&patched.join("\n"), 1000)));
    }
    if let Some(p) = a.epss.and_then(|e| e.percentage) {
        item.extra
            .push(("EPSS".into(), format!("{:.2}%", p * 100.0)));
    }
    item
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[
      {
        "id": 1,
        "ghsa_id": "GHSA-abcd-1234-efgh",
        "cve_id": "CVE-2026-11111",
        "url": "https://api.github.com/advisories/GHSA-abcd-1234-efgh",
        "html_url": "https://github.com/advisories/GHSA-abcd-1234-efgh",
        "summary": "OkHttp header injection",
        "description": "A   header\n injection.",
        "type": "reviewed",
        "severity": "high",
        "identifiers": [],
        "references": [],
        "published_at": "2026-10-23T02:30:56Z",
        "updated_at": "2026-10-23T02:30:56Z",
        "withdrawn_at": null,
        "vulnerabilities": [
          {
            "package": {"ecosystem": "maven", "name": "com.squareup.okhttp3:okhttp"},
            "first_patched_version": "5.1.1",
            "vulnerable_version_range": "< 5.1.1",
            "vulnerable_functions": []
          }
        ],
        "cvss": {"vector_string": null, "score": null},
        "cvss_severities": {
          "cvss_v3": {"vector_string": "CVSS:3.1/AV:N", "score": 7.5},
          "cvss_v4": {"vector_string": null, "score": 0.0}
        },
        "cwes": [],
        "epss": {"percentage": 0.0123, "percentile": "0.16001e0"},
        "credits": []
      },
      {
        "ghsa_id": "GHSA-zzzz-zzzz-zzzz",
        "cve_id": null,
        "html_url": "https://github.com/advisories/GHSA-zzzz-zzzz-zzzz",
        "summary": "No score",
        "description": null,
        "severity": "critical",
        "published_at": "2026-10-22T00:00:00Z",
        "withdrawn_at": null,
        "vulnerabilities": [],
        "cvss": null,
        "cvss_severities": null,
        "epss": null
      },
      {
        "ghsa_id": "GHSA-wwww-wwww-wwww",
        "summary": "Withdrawn",
        "withdrawn_at": "2026-10-22T00:00:00Z"
      }
    ]"#;

    #[test]
    fn page_keeps_updated_at_of_withdrawn() {
        let body = r#"[
          {"ghsa_id": "GHSA-a", "summary": "a", "updated_at": "2026-10-24T06:00:00Z"},
          {"ghsa_id": "GHSA-b", "summary": "b", "updated_at": "2026-10-24T05:00:00Z",
           "withdrawn_at": "2026-10-24T05:00:00Z"}
        ]"#;
        let page = parse_page("ghsa", body).unwrap();
        assert_eq!(page.len(), 2);
        assert!(page[0].0.is_some());
        assert!(page[1].0.is_none());
        assert_eq!(page[1].1, parse_time("2026-10-24T05:00:00Z"));
    }

    #[test]
    fn parses_advisories() {
        let items = parse("ghsa", SAMPLE).unwrap();
        assert_eq!(items.len(), 2);
        let a = &items[0];
        assert_eq!(a.cve.as_deref(), Some("CVE-2026-11111"));
        assert_eq!(a.cvss, Some(7.5));
        assert_eq!(a.summary, "A header injection.");
        assert_eq!(a.packages, vec!["com.squareup.okhttp3:okhttp"]);
        assert_eq!(a.products, vec!["maven:com.squareup.okhttp3:okhttp"]);
        assert!(a
            .extra
            .iter()
            .any(|(k, v)| k == "修正バージョン" && v.contains("5.1.1")));
        assert!(a.extra.iter().any(|(k, v)| k == "EPSS" && v == "1.23%"));

        let b = &items[1];
        assert_eq!(b.cve, None);
        assert_eq!(b.cvss, Some(9.0));
    }
}
