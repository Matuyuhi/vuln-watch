//! GitHub Advisory Database (global advisories REST API).

use anyhow::{Context, Result};
use serde::Deserialize;

use super::{severity_to_score, Ctx, Fetched};
use crate::http::Validators;
use crate::model::Item;
use crate::text::{collapse_ws, truncate};

pub const DEFAULT_URL: &str =
    "https://api.github.com/advisories?type=reviewed&sort=published&direction=desc&per_page=100";

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

pub fn fetch(name: &str, url: Option<&str>, ctx: &Ctx) -> Result<Fetched> {
    let url = url.unwrap_or(DEFAULT_URL);
    let mut headers = vec![
        ("Accept", "application/vnd.github+json".to_string()),
        ("X-GitHub-Api-Version", "2022-11-28".to_string()),
    ];
    if let Some(token) = &ctx.github_token {
        headers.push(("Authorization", format!("Bearer {token}")));
    }
    let validators = Validators::load(ctx.db, url)?;
    let resp = ctx.http.get(url, &headers, Some(&validators))?;
    let commit = Validators::commit_pairs(url, &resp);
    if resp.not_modified() {
        return Ok(Fetched::empty());
    }
    let items = parse(name, &resp.body)?;
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

pub fn parse(source: &str, body: &str) -> Result<Vec<Item>> {
    let advisories: Vec<Advisory> =
        serde_json::from_str(body).context("parsing GitHub advisories")?;
    Ok(advisories
        .into_iter()
        .filter(|a| a.withdrawn_at.is_none())
        .map(|a| {
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
        })
        .collect())
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
