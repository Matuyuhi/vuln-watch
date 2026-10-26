//! GitHub Advisory Database (global advisories REST API).

use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;

use super::{severity_to_score, Ctx, Fetched};
use crate::http::{next_link, Resp, Validators};
use crate::model::Item;
use crate::text::{collapse_ws, truncate};

/// Sorted by `updated`, not `published`: advisories imported from NVD keep their original
/// `published_at` when GitHub reviews them later, so a published-sorted list would never
/// show them on the first page.
pub const DEFAULT_URL: &str =
    "https://api.github.com/advisories?type=reviewed&sort=updated&direction=desc&per_page=100";
/// Upper bound of pages walked back to the previous position (100 advisories per page).
const MAX_PAGES: usize = 20;
/// Pages of a backfill window read per run.
const BACKFILL_PAGES: usize = 5;
/// Backfill only while more API requests than this remain in the rate-limit window: an hour
/// of normal polling (every two minutes) without `GITHUB_TOKEN`, where the limit is 60.
const RATE_RESERVE: u32 = 30;

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

pub fn backfill_key(name: &str) -> String {
    format!("ghsa:{name}:backfill")
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// `updated_at` range a walk stopped by `MAX_PAGES` did not read (both ends inclusive).
/// Stored as `<from>..<to>[ <next page URL>]` and filled in ascending order on later runs.
#[derive(Debug, Clone, PartialEq)]
struct Window {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    /// Where the previous run stopped, so a run of advisories sharing one `updated_at`
    /// longer than a run's page budget cannot hold `from` in place forever.
    next: Option<String>,
}

impl Window {
    fn new(from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        Self {
            from,
            to,
            next: None,
        }
    }

    fn parse(s: &str) -> Option<Self> {
        let (range, next) = match s.split_once(' ') {
            Some((range, next)) => (range, Some(next.to_string())),
            None => (s, None),
        };
        let (from, to) = range.split_once("..")?;
        Some(Self {
            from: parse_time(from)?,
            to: parse_time(to)?,
            next,
        })
    }

    /// The API's `updated` range filter syntax.
    fn range(&self) -> String {
        let f = |t: DateTime<Utc>| t.to_rfc3339_opts(SecondsFormat::Secs, true);
        format!("{}..{}", f(self.from), f(self.to))
    }

    fn encode(&self) -> String {
        match &self.next {
            Some(next) => format!("{} {next}", self.range()),
            None => self.range(),
        }
    }

    /// The page link belongs to the old range, so the merged range starts over.
    fn merge(&self, other: &Self) -> Self {
        Self::new(self.from.min(other.from), self.to.max(other.to))
    }
}

/// The configured list URL turned into an ascending query over `window`.
fn backfill_url(base: &str, window: &Window) -> Result<String> {
    let mut url = reqwest::Url::parse(base).with_context(|| format!("parsing {base}"))?;
    let keep: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| {
            !matches!(
                k.as_ref(),
                "sort" | "direction" | "updated" | "after" | "before"
            )
        })
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(keep)
        .append_pair("sort", "updated")
        .append_pair("direction", "asc")
        .append_pair("updated", &window.range());
    Ok(url.into())
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
    let window = ctx
        .db
        .get_kv(&backfill_key(name))?
        .as_deref()
        .and_then(Window::parse);
    let validators = Validators::load(ctx.db, first_url)?;
    let walk = Walk {
        name,
        first_url,
        cursor,
        window,
        // Without a cursor (first run / dry-run) one page is enough.
        one_page: ctx.bootstrap || ctx.limit.is_some(),
        backfill_pages: BACKFILL_PAGES,
    };
    walk.run(|url, first| ctx.http.get(url, &headers, first.then_some(&validators)))
}

struct Walk<'a> {
    name: &'a str,
    first_url: &'a str,
    cursor: Option<DateTime<Utc>>,
    window: Option<Window>,
    one_page: bool,
    backfill_pages: usize,
}

impl Walk<'_> {
    /// `get(url, first)`: `first` is the conditional request for page 1 of the list.
    fn run(&self, mut get: impl FnMut(&str, bool) -> Result<Resp>) -> Result<Fetched> {
        let name = self.name;
        let cursor = self.cursor;
        let mut fetched = Fetched::empty();
        let mut resp = get(self.first_url, true)?;
        let mut remaining = resp.rate_remaining;
        let mut limit_hit = false;
        if !resp.not_modified() {
            fetched.commit = Validators::commit_pairs(self.first_url, &resp);
            let mut newest = cursor;
            let mut oldest: Option<DateTime<Utc>> = None;
            let mut page = 1;
            loop {
                let parsed = parse_page(name, &resp.body)?;
                let reached_cursor = parsed
                    .iter()
                    .any(|(_, t)| matches!((t, cursor), (Some(t), Some(c)) if *t <= c));
                for (item, t) in parsed {
                    if let Some(t) = t {
                        newest = Some(newest.map_or(t, |n| n.max(t)));
                        oldest = Some(oldest.map_or(t, |o| o.min(t)));
                    }
                    if let Some(item) = item {
                        fetched.items.push(item);
                    }
                }
                if cursor.is_none() || self.one_page || reached_cursor {
                    break;
                }
                let Some(next) = resp.link.as_deref().and_then(next_link) else {
                    break;
                };
                if page >= MAX_PAGES {
                    limit_hit = true;
                    break;
                }
                page += 1;
                resp = get(&next, false)?;
                remaining = resp.rate_remaining;
            }
            if page > 1 {
                tracing::info!("{name}: walked {page} pages to catch up");
            }
            if let Some(n) = newest {
                fetched.commit.push((cursor_key(name), n.to_rfc3339()));
            }
            // Written first: a run that stops part way through the commit must not leave
            // the new cursor or ETag without the gap behind it.
            if let (true, Some(from), Some(to)) = (limit_hit, cursor, oldest) {
                let gap = Window::new(from, to);
                let window = self.window.as_ref().map_or(gap.clone(), |w| w.merge(&gap));
                tracing::warn!(
                    "{name}: stopped after {MAX_PAGES} pages without reaching the previous position; \
                     advisories updated in {} will be read on later runs",
                    window.range()
                );
                fetched
                    .commit
                    .insert(0, (backfill_key(name), window.encode()));
            }
        }
        // A new gap waits for the next run: this one already used its page budget.
        if self.one_page || limit_hit {
            return Ok(fetched);
        }
        if let Some(window) = &self.window {
            match self.backfill(window, remaining, &mut get, &mut fetched.items) {
                Ok(Some(rest)) => fetched.commit.push((backfill_key(name), rest.encode())),
                Ok(None) => {
                    tracing::info!("{name}: backfill of {} complete", window.range());
                    fetched.remove.push(backfill_key(name));
                }
                Err(e) => {
                    tracing::warn!("{name}: backfill of {} failed: {e:#}", window.range());
                    // Keep the range for the next run, but query it afresh in case the
                    // stored page link is what fails.
                    if window.next.is_some() {
                        let fresh = Window::new(window.from, window.to);
                        fetched.commit.push((backfill_key(name), fresh.encode()));
                    }
                }
            }
        }
        Ok(fetched)
    }

    /// Read up to `backfill_pages` pages of `window`, oldest first, keeping `RATE_RESERVE`
    /// requests for normal polling. Returns the part still unread, or `None` when the window
    /// is exhausted.
    fn backfill(
        &self,
        window: &Window,
        mut remaining: Option<u32>,
        get: &mut impl FnMut(&str, bool) -> Result<Resp>,
        items: &mut Vec<Item>,
    ) -> Result<Option<Window>> {
        let mut next = window.next.clone();
        let mut url = match &next {
            Some(next) => next.clone(),
            None => backfill_url(self.first_url, window)?,
        };
        let mut from = window.from;
        for _ in 0..self.backfill_pages {
            if remaining.is_some_and(|r| r <= RATE_RESERVE) {
                tracing::debug!(
                    "{}: backfill paused, {remaining:?} API requests left",
                    self.name
                );
                break;
            }
            let resp = get(&url, false)?;
            remaining = resp.rate_remaining;
            let parsed = parse_page(self.name, &resp.body)?;
            if parsed.is_empty() {
                return Ok(None);
            }
            for (item, t) in parsed {
                if let Some(t) = t {
                    from = from.max(t);
                }
                if let Some(item) = item {
                    items.push(item);
                }
            }
            match resp.link.as_deref().and_then(next_link) {
                Some(link) => {
                    url = link.clone();
                    next = Some(link);
                }
                None => return Ok(None),
            }
        }
        Ok(Some(Window {
            from: from.min(window.to),
            to: window.to,
            next,
        }))
    }
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

    fn t(s: &str) -> DateTime<Utc> {
        parse_time(s).unwrap()
    }

    /// One advisory per timestamp.
    fn page(times: &[DateTime<Utc>]) -> String {
        let advisories: Vec<String> = times
            .iter()
            .map(|t| {
                let t = t.to_rfc3339_opts(SecondsFormat::Secs, true);
                format!(r#"{{"ghsa_id": "GHSA-{t}", "summary": "s", "updated_at": "{t}"}}"#)
            })
            .collect();
        format!("[{}]", advisories.join(","))
    }

    fn resp(status: u16, body: String, next: bool) -> Resp {
        Resp {
            status,
            body,
            etag: None,
            last_modified: None,
            link: next.then(|| r#"<https://api.github.com/next>; rel="next""#.to_string()),
            rate_remaining: None,
        }
    }

    fn walk(cursor: &str, window: Option<Window>) -> Walk<'static> {
        Walk {
            name: "ghsa",
            first_url: DEFAULT_URL,
            cursor: Some(t(cursor)),
            window,
            one_page: false,
            backfill_pages: 2,
        }
    }

    fn kv<'a>(f: &'a Fetched, key: &str) -> Option<&'a str> {
        f.commit
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Every list page is newer than the cursor and has a next page: one hour older per page.
    fn run_past_limit(w: &Walk) -> (Fetched, Vec<String>) {
        let mut urls = Vec::new();
        let mut n = 0;
        let f = w
            .run(|url, _| {
                urls.push(url.to_string());
                let time = t("2026-10-25T00:00:00Z") - chrono::Duration::hours(n);
                n += 1;
                Ok(resp(200, page(&[time]), true))
            })
            .unwrap();
        (f, urls)
    }

    #[test]
    fn limit_hit_stores_window() {
        let (f, urls) = run_past_limit(&walk("2026-10-01T00:00:00Z", None));
        assert_eq!(urls.len(), MAX_PAGES);
        assert_eq!(f.items.len(), MAX_PAGES);
        assert_eq!(
            kv(&f, &backfill_key("ghsa")),
            Some("2026-10-01T00:00:00Z..2026-10-24T05:00:00Z")
        );
        // Persisted before the cursor and validators.
        assert_eq!(f.commit[0].0, backfill_key("ghsa"));
        assert_eq!(
            kv(&f, &cursor_key("ghsa")),
            Some(t("2026-10-25T00:00:00Z").to_rfc3339().as_str())
        );
        assert!(f.remove.is_empty());
    }

    #[test]
    fn second_limit_hit_merges_with_window() {
        let old = Window::parse("2026-09-01T00:00:00Z..2026-09-05T00:00:00Z");
        let (f, urls) = run_past_limit(&walk("2026-10-01T00:00:00Z", old));
        // The page budget of this run is spent: no backfill request.
        assert!(urls.iter().all(|u| !u.contains("direction=asc")));
        assert_eq!(
            kv(&f, &backfill_key("ghsa")),
            Some("2026-09-01T00:00:00Z..2026-10-24T05:00:00Z")
        );
    }

    #[test]
    fn backfill_page_moves_from() {
        let window = Window::parse("2026-10-01T00:00:00Z..2026-10-10T00:00:00Z");
        let mut urls = Vec::new();
        let mut n = 0;
        let f = walk("2026-10-20T00:00:00Z", window)
            .run(|url, first| {
                urls.push(url.to_string());
                if first {
                    return Ok(resp(304, String::new(), false));
                }
                n += 1;
                let time = t("2026-10-01T00:00:00Z") + chrono::Duration::hours(n);
                Ok(resp(
                    200,
                    page(&[time - chrono::Duration::minutes(30), time]),
                    true,
                ))
            })
            .unwrap();
        assert_eq!(urls.len(), 3);
        assert!(urls[1].contains("direction=asc"));
        assert!(urls[1].contains("updated=2026-10-01T00%3A00%3A00Z..2026-10-10T00%3A00%3A00Z"));
        assert_eq!(f.items.len(), 4);
        assert_eq!(
            kv(&f, &backfill_key("ghsa")),
            Some("2026-10-01T02:00:00Z..2026-10-10T00:00:00Z https://api.github.com/next")
        );
        assert_eq!(kv(&f, &cursor_key("ghsa")), None);
        assert!(f.remove.is_empty());
    }

    #[test]
    fn empty_backfill_page_removes_window() {
        let window = Window::parse("2026-10-01T00:00:00Z..2026-10-10T00:00:00Z");
        let f = walk("2026-10-20T00:00:00Z", window)
            .run(|_, first| {
                Ok(if first {
                    resp(200, page(&[t("2026-10-19T00:00:00Z")]), true)
                } else {
                    resp(200, "[]".into(), false)
                })
            })
            .unwrap();
        assert_eq!(f.items.len(), 1);
        assert_eq!(kv(&f, &backfill_key("ghsa")), None);
        assert_eq!(f.remove, vec![backfill_key("ghsa")]);
    }

    #[test]
    fn last_backfill_page_removes_window() {
        let window = Window::parse("2026-10-01T00:00:00Z..2026-10-10T00:00:00Z");
        let f = walk("2026-10-20T00:00:00Z", window)
            .run(|_, first| {
                Ok(if first {
                    resp(304, String::new(), false)
                } else {
                    resp(200, page(&[t("2026-10-02T00:00:00Z")]), false)
                })
            })
            .unwrap();
        assert_eq!(f.items.len(), 1);
        assert_eq!(f.remove, vec![backfill_key("ghsa")]);
    }

    #[test]
    fn backfill_keeps_rate_limit_reserve() {
        let window = Window::parse("2026-10-01T00:00:00Z..2026-10-10T00:00:00Z");
        let mut calls = 0;
        let f = walk("2026-10-20T00:00:00Z", window.clone())
            .run(|_, first| {
                calls += 1;
                let mut r = if first {
                    resp(304, String::new(), false)
                } else {
                    resp(200, page(&[t("2026-10-02T00:00:00Z")]), true)
                };
                r.rate_remaining = Some(if first {
                    RATE_RESERVE + 1
                } else {
                    RATE_RESERVE
                });
                Ok(r)
            })
            .unwrap();
        // One backfill page, then it stops to leave the reserve for normal polling.
        assert_eq!(calls, 2);
        assert_eq!(
            kv(&f, &backfill_key("ghsa")),
            Some("2026-10-02T00:00:00Z..2026-10-10T00:00:00Z https://api.github.com/next")
        );

        let f = walk("2026-10-20T00:00:00Z", window)
            .run(|_, _| {
                let mut r = resp(304, String::new(), false);
                r.rate_remaining = Some(RATE_RESERVE);
                Ok(r)
            })
            .unwrap();
        assert_eq!(
            kv(&f, &backfill_key("ghsa")),
            Some("2026-10-01T00:00:00Z..2026-10-10T00:00:00Z")
        );
    }

    #[test]
    fn backfill_continues_from_stored_page_link() {
        // All advisories of the window share one timestamp: `from` cannot move, the page
        // link does.
        let window = Window::parse(
            "2026-10-01T00:00:00Z..2026-10-10T00:00:00Z https://api.github.com/stored",
        );
        let mut urls = Vec::new();
        let f = walk("2026-10-20T00:00:00Z", window)
            .run(|url, first| {
                urls.push(url.to_string());
                Ok(if first {
                    resp(304, String::new(), false)
                } else {
                    resp(200, page(&[t("2026-10-01T00:00:00Z")]), true)
                })
            })
            .unwrap();
        assert_eq!(urls[1], "https://api.github.com/stored");
        assert_eq!(
            kv(&f, &backfill_key("ghsa")),
            Some("2026-10-01T00:00:00Z..2026-10-10T00:00:00Z https://api.github.com/next")
        );
    }

    #[test]
    fn equal_timestamps_beyond_page_budget_do_not_stall_backfill() {
        // Four full pages share one `updated_at`, the fifth holds a newer advisory.
        let tie = t("2026-10-01T00:00:00Z");
        let newer = t("2026-10-02T00:00:00Z");
        let serve = |url: &str| {
            let n: usize = url
                .strip_prefix("https://api.github.com/p")
                .map_or(0, |n| n.parse().unwrap());
            let time = if n < 4 { tie } else { newer };
            let mut r = resp(200, page(&[time]), n < 4);
            r.link = r
                .link
                .map(|_| format!(r#"<https://api.github.com/p{}>; rel="next""#, n + 1));
            r
        };
        let mut stored = Window::parse("2026-10-01T00:00:00Z..2026-10-10T00:00:00Z");
        let mut read = Vec::new();
        for _ in 0..3 {
            let f = walk("2026-10-20T00:00:00Z", stored.clone())
                .run(|url, first| {
                    Ok(if first {
                        resp(304, String::new(), false)
                    } else {
                        serve(url)
                    })
                })
                .unwrap();
            read.extend(f.items.iter().map(|i| i.id.clone()));
            stored = kv(&f, &backfill_key("ghsa")).and_then(Window::parse);
            if f.remove.contains(&backfill_key("ghsa")) {
                break;
            }
        }
        assert_eq!(read.len(), 5);
        assert_eq!(read.last().unwrap(), "GHSA-2026-10-02T00:00:00Z");
        assert_eq!(stored, None);
    }

    #[test]
    fn failed_stored_page_link_falls_back_to_range() {
        let window = Window::parse(
            "2026-10-01T00:00:00Z..2026-10-10T00:00:00Z https://api.github.com/stored",
        );
        let f = walk("2026-10-20T00:00:00Z", window)
            .run(|_, first| {
                if first {
                    Ok(resp(304, String::new(), false))
                } else {
                    anyhow::bail!("HTTP 422")
                }
            })
            .unwrap();
        assert_eq!(
            kv(&f, &backfill_key("ghsa")),
            Some("2026-10-01T00:00:00Z..2026-10-10T00:00:00Z")
        );
    }

    #[test]
    fn merge_drops_page_link() {
        let old = Window::parse("2026-09-01T00:00:00Z..2026-09-05T00:00:00Z https://x").unwrap();
        let new = Window::parse("2026-10-01T00:00:00Z..2026-10-02T00:00:00Z").unwrap();
        assert_eq!(
            old.merge(&new).encode(),
            "2026-09-01T00:00:00Z..2026-10-02T00:00:00Z"
        );
    }

    #[test]
    fn failed_backfill_keeps_window() {
        let window = Window::parse("2026-10-01T00:00:00Z..2026-10-10T00:00:00Z");
        let f = walk("2026-10-20T00:00:00Z", window)
            .run(|_, first| {
                if first {
                    Ok(resp(200, page(&[t("2026-10-19T00:00:00Z")]), true))
                } else {
                    anyhow::bail!("HTTP 403")
                }
            })
            .unwrap();
        assert_eq!(f.items.len(), 1);
        assert_eq!(kv(&f, &backfill_key("ghsa")), None);
        assert!(f.remove.is_empty());
    }

    #[test]
    fn one_page_neither_backfills_nor_stores_window() {
        let mut w = walk("2026-10-01T00:00:00Z", None);
        w.one_page = true;
        w.window = Window::parse("2026-09-01T00:00:00Z..2026-09-05T00:00:00Z");
        let (f, urls) = run_past_limit(&w);
        assert_eq!(urls.len(), 1);
        assert_eq!(kv(&f, &backfill_key("ghsa")), None);
        assert!(f.remove.is_empty());
    }

    #[test]
    fn backfill_url_replaces_order_and_range() {
        let window = Window::parse("2026-10-01T00:00:00Z..2026-10-10T00:00:00Z").unwrap();
        let url = backfill_url(DEFAULT_URL, &window).unwrap();
        assert_eq!(
            url,
            "https://api.github.com/advisories?type=reviewed&per_page=100&sort=updated\
             &direction=asc&updated=2026-10-01T00%3A00%3A00Z..2026-10-10T00%3A00%3A00Z"
        );
    }

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
