//! CVEProject/cvelistV5 — the official CVE List, updated every few minutes.
//!
//! Each run reads `cves/delta.json` (changes from the latest sync). When a sync may have
//! been missed — the previous run is too old, or the commit history shows more than one
//! sync since our cursor — `cves/deltaLog.json` (~30 days of deltas) is read instead.
//! New CVE ids are queued in the `pending` table before the cursor advances, so a backlog
//! larger than `cvelist_max_records` or a failed record download is retried, not dropped.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::Value;

use super::{Ctx, Fetched};
use crate::http::Validators;
use crate::model::Item;
use crate::text::{collapse_ws, truncate};

const BASE: &str = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves";
/// GitHub contents API: not behind the raw CDN cache (~5 min), so changes are seen sooner.
const API_BASE: &str = "https://api.github.com/repos/CVEProject/cvelistV5/contents/cves";
const KEY_CURSOR: &str = "cvelist:last_fetch_time";
const KEY_LAST_OK: &str = "cvelist:last_ok_at";
const COMMITS_URL: &str = "https://api.github.com/repos/CVEProject/cvelistV5/commits";
/// delta.json is regenerated roughly every 7 minutes; older gaps need deltaLog.json.
const MAX_GAP_MINUTES: i64 = 10;
/// A record that keeps failing to download is dropped after this many runs.
const MAX_RECORD_ATTEMPTS: i64 = 10;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Delta {
    pub fetch_time: String,
    #[serde(default)]
    pub new: Vec<DeltaEntry>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeltaEntry {
    pub cve_id: String,
    #[serde(default)]
    pub github_link: Option<String>,
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// Parse either delta.json (object) or deltaLog.json (array of objects).
pub fn parse_deltas(body: &str) -> Result<Vec<Delta>> {
    let v: Value = serde_json::from_str(body).context("parsing CVE delta")?;
    Ok(match v {
        Value::Array(_) => serde_json::from_value(v).context("parsing deltaLog.json")?,
        Value::Object(_) => vec![serde_json::from_value(v).context("parsing delta.json")?],
        _ => bail!("unexpected delta JSON shape"),
    })
}

/// New CVE entries strictly after `cursor`, oldest first, plus the newest fetchTime seen.
pub fn select_new(
    deltas: Vec<Delta>,
    cursor: Option<DateTime<Utc>>,
) -> (Vec<DeltaEntry>, Option<String>) {
    let mut deltas: Vec<(DateTime<Utc>, Delta)> = deltas
        .into_iter()
        .filter_map(|d| parse_time(&d.fetch_time).map(|t| (t, d)))
        .filter(|(t, _)| cursor.is_none_or(|c| *t > c))
        .collect();
    deltas.sort_by_key(|(t, _)| *t);
    let newest = deltas.last().map(|(_, d)| d.fetch_time.clone());
    let mut out: Vec<DeltaEntry> = Vec::new();
    for (_, d) in deltas {
        for e in d.new {
            if !out.iter().any(|x| x.cve_id == e.cve_id) {
                out.push(e);
            }
        }
    }
    (out, newest)
}

/// URL and headers for one of the delta files. With a GitHub token (and no custom base URL)
/// the contents API is used, which avoids the raw.githubusercontent.com CDN delay.
fn delta_request<'a>(
    base_override: Option<&str>,
    token: Option<&str>,
    file: &str,
) -> (String, Vec<(&'a str, String)>) {
    match (base_override, token) {
        (None, Some(token)) => (
            format!("{API_BASE}/{file}"),
            vec![
                ("Accept", "application/vnd.github.raw+json".to_string()),
                ("X-GitHub-Api-Version", "2022-11-28".to_string()),
                ("Authorization", format!("Bearer {token}")),
            ],
        ),
        _ => (
            format!(
                "{}/{file}",
                base_override.unwrap_or(BASE).trim_end_matches('/')
            ),
            Vec::new(),
        ),
    }
}

/// Read one of the delta files. Returns None on 304 Not Modified.
fn read_deltas(
    ctx: &Ctx,
    base_override: Option<&str>,
    file: &str,
    commit: &mut Vec<(String, String)>,
) -> Result<Option<Vec<Delta>>> {
    let (url, headers) = delta_request(base_override, ctx.github_token.as_deref(), file);
    let validators = Validators::load(ctx.db, &url)?;
    let resp = ctx.http.get(&url, &headers, Some(&validators))?;
    if resp.not_modified() {
        return Ok(None);
    }
    commit.extend(Validators::commit_pairs(&url, &resp));
    Ok(Some(parse_deltas(&resp.body)?))
}

/// Number of cvelistV5 commits since `since` (capped at 5).
fn commits_since(ctx: &Ctx, token: &str, since: DateTime<Utc>) -> Result<usize> {
    let url = format!(
        "{COMMITS_URL}?since={}&per_page=5",
        since.format("%Y-%m-%dT%H:%M:%SZ")
    );
    let headers = [
        ("Accept", "application/vnd.github+json".to_string()),
        ("X-GitHub-Api-Version", "2022-11-28".to_string()),
        ("Authorization", format!("Bearer {token}")),
    ];
    let resp = ctx.http.get(&url, &headers, None)?;
    let commits: Vec<Value> = serde_json::from_str(&resp.body).context("parsing commits")?;
    Ok(commits.len())
}

pub fn fetch(name: &str, base_override: Option<&str>, ctx: &Ctx) -> Result<Fetched> {
    let base = base_override.unwrap_or(BASE).trim_end_matches('/');
    let now = Utc::now();
    let cursor = ctx.db.get_kv(KEY_CURSOR)?.as_deref().and_then(parse_time);
    let last_ok = ctx.db.get_kv(KEY_LAST_OK)?.as_deref().and_then(parse_time);
    let mut commit = vec![(KEY_LAST_OK.to_string(), now.to_rfc3339())];

    let stale =
        cursor.is_some() && last_ok.is_none_or(|t| now - t > Duration::minutes(MAX_GAP_MINUTES));
    let deltas = if stale {
        tracing::info!("{name}: previous run is old, catching up via deltaLog.json");
        read_deltas(ctx, base_override, "deltaLog.json", &mut commit)?
    } else {
        let latest = read_deltas(ctx, base_override, "delta.json", &mut commit)?;
        // delta.json only holds the latest sync. If more than one sync happened since our
        // cursor (commit of the delta we processed + the current one = 2), one was missed.
        let has_new = latest.as_ref().is_some_and(|ds| {
            ds.iter()
                .filter_map(|d| parse_time(&d.fetch_time))
                .any(|t| cursor.is_none_or(|c| t > c))
        });
        match (has_new, cursor, ctx.github_token.as_deref(), base_override) {
            (true, Some(c), Some(token), None) => match commits_since(ctx, token, c) {
                Ok(n) if n >= 3 => {
                    tracing::info!("{name}: {n} syncs since last delta, reading deltaLog.json");
                    read_deltas(ctx, base_override, "deltaLog.json", &mut commit)?
                }
                Ok(_) => latest,
                Err(e) => {
                    tracing::warn!("{name}: commit check failed ({e:#}), reading deltaLog.json");
                    read_deltas(ctx, base_override, "deltaLog.json", &mut commit)?
                }
            },
            _ => latest,
        }
    };

    let (entries, newest) = select_new(deltas.unwrap_or_default(), cursor);
    if let Some(n) = newest {
        commit.push((KEY_CURSOR.to_string(), n));
    }
    if ctx.bootstrap {
        return Ok(Fetched {
            items: Vec::new(),
            commit,
        });
    }

    // Queue new ids durably before the cursor moves, then work through the backlog.
    for e in &entries {
        let link = e
            .github_link
            .clone()
            .unwrap_or_else(|| record_url(base, &e.cve_id));
        ctx.db.add_pending(name, &e.cve_id, &link)?;
    }
    ctx.db.prune_pending_seen(name)?;

    let mut max = ctx.cfg.runtime.cvelist_max_records;
    if let Some(limit) = ctx.limit {
        max = max.min(limit);
    }
    let backlog = ctx.db.pending_count(name)?;
    if backlog as usize > max {
        tracing::info!("{name}: {backlog} CVE records queued, processing {max} this run");
    }

    let mut items = Vec::new();
    for row in ctx.db.pending(name, max)? {
        let result = ctx.http.get(&row.data, &[], None).and_then(|resp| {
            serde_json::from_str::<Value>(&resp.body).context("parsing CVE record")
        });
        match result {
            Ok(record) => match parse_record(name, &record) {
                Some(item) => items.push(item),
                // Rejected record: nothing to report.
                None => ctx.db.mark_seen(name, &row.id)?,
            },
            Err(e) => {
                tracing::warn!("{name}: fetching {} failed: {e:#}", row.id);
                if row.attempts + 1 >= MAX_RECORD_ATTEMPTS {
                    tracing::warn!("{name}: giving up on {}", row.id);
                    ctx.db.remove_pending(name, &row.id)?;
                } else {
                    ctx.db.bump_pending_attempt(name, &row.id)?;
                }
            }
        }
    }
    Ok(Fetched { items, commit })
}

/// Fallback URL: cves/<year>/<bucket>xxx/CVE-<year>-<num>.json
fn record_url(base: &str, cve: &str) -> String {
    let parts: Vec<&str> = cve.split('-').collect();
    if parts.len() == 3 {
        let num = parts[2];
        let bucket = if num.len() > 3 {
            format!("{}xxx", &num[..num.len() - 3])
        } else {
            "0xxx".to_string()
        };
        format!("{base}/{}/{bucket}/{cve}.json", parts[1])
    } else {
        format!("{base}/{cve}.json")
    }
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for p in path {
        cur = cur.get(*p)?;
    }
    cur.as_str()
}

/// Collect CVSS scores from a `metrics` array (CNA or ADP container).
fn scan_metrics(metrics: Option<&Value>, best: &mut Option<(f32, Option<String>)>, kev: &mut bool) {
    let Some(arr) = metrics.and_then(Value::as_array) else {
        return;
    };
    for m in arr {
        for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"] {
            if let Some(c) = m.get(key) {
                if let Some(score) = c.get("baseScore").and_then(Value::as_f64) {
                    let score = score as f32;
                    let sev = c
                        .get("baseSeverity")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    if best.as_ref().is_none_or(|(b, _)| score > *b) {
                        *best = Some((score, sev));
                    }
                }
            }
        }
        if let Some(other) = m.get("other") {
            if other
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|t| t.eq_ignore_ascii_case("kev"))
            {
                *kev = true;
            }
        }
    }
}

fn affected_field<'a>(a: &'a Value, key: &str) -> Option<&'a str> {
    a.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("n/a"))
}

/// Convert a CVE JSON 5.x record into an Item. Returns None for rejected records.
pub fn parse_record(source: &str, v: &Value) -> Option<Item> {
    let id = str_at(v, &["cveMetadata", "cveId"])?.to_string();
    if str_at(v, &["cveMetadata", "state"]).is_some_and(|s| s.eq_ignore_ascii_case("REJECTED")) {
        return None;
    }
    let cna = v.get("containers").and_then(|c| c.get("cna"));

    let description = cna
        .and_then(|c| c.get("descriptions"))
        .and_then(Value::as_array)
        .and_then(|ds| {
            ds.iter()
                .find(|d| {
                    d.get("lang")
                        .and_then(Value::as_str)
                        .is_some_and(|l| l.to_ascii_lowercase().starts_with("en"))
                })
                .or_else(|| ds.first())
        })
        .and_then(|d| d.get("value"))
        .and_then(Value::as_str)
        .map(collapse_ws)
        .unwrap_or_default();

    let mut item = Item::new(source, id.clone());
    item.cve = Some(id.clone());
    item.title = cna
        .and_then(|c| c.get("title"))
        .and_then(Value::as_str)
        .map(collapse_ws)
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| truncate(&description, 120));
    item.summary = truncate(&description, 800);
    item.url = format!("https://www.cve.org/CVERecord?id={id}");
    item.published = str_at(v, &["cveMetadata", "datePublished"]).map(str::to_string);

    if let Some(affected) = cna
        .and_then(|c| c.get("affected"))
        .and_then(Value::as_array)
    {
        for a in affected {
            let label = match (affected_field(a, "vendor"), affected_field(a, "product")) {
                (Some(v), Some(p)) => format!("{v} {p}"),
                (Some(v), None) => v.to_string(),
                (None, Some(p)) => p.to_string(),
                (None, None) => continue,
            };
            if !item.products.contains(&label) {
                item.products.push(label);
            }
            if let Some(pkg) = affected_field(a, "packageName") {
                if !item.packages.iter().any(|p| p == pkg) {
                    item.packages.push(pkg.to_string());
                }
            }
        }
    }

    let mut best: Option<(f32, Option<String>)> = None;
    let mut kev = false;
    scan_metrics(cna.and_then(|c| c.get("metrics")), &mut best, &mut kev);
    if let Some(adps) = v
        .get("containers")
        .and_then(|c| c.get("adp"))
        .and_then(Value::as_array)
    {
        for adp in adps {
            scan_metrics(adp.get("metrics"), &mut best, &mut kev);
        }
    }
    if let Some((score, sev)) = best {
        item.cvss = Some(score);
        item.severity = sev;
    }
    item.kev = kev;
    Some(item)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_delta_and_log() {
        let delta = r#"{
          "fetchTime": "2026-10-24T06:00:00.000Z",
          "numberOfChanges": 2,
          "new": [{"cveId": "CVE-2026-1", "cveOrgLink": "x", "githubLink": "https://example/1.json", "dateUpdated": "2026-10-24T05:59:00.000Z"}],
          "updated": [{"cveId": "CVE-2025-9", "cveOrgLink": "x", "githubLink": "x", "dateUpdated": "x"}],
          "error": []
        }"#;
        let d = parse_deltas(delta).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].new[0].cve_id, "CVE-2026-1");

        let log = r#"[
          {"fetchTime": "2026-10-24T06:00:00.000Z", "numberOfChanges": 1, "new": [{"cveId": "CVE-2026-3"}], "updated": [], "error": []},
          {"fetchTime": "2026-10-24T05:50:00.000Z", "numberOfChanges": 2, "new": [{"cveId": "CVE-2026-2"}, {"cveId": "CVE-2026-3"}], "updated": [], "error": []},
          {"fetchTime": "2026-10-24T05:40:00.000Z", "numberOfChanges": 1, "new": [{"cveId": "CVE-2026-1"}], "updated": [], "error": []}
        ]"#;
        let deltas = parse_deltas(log).unwrap();
        let cursor = parse_time("2026-10-24T05:40:00.000Z");
        let (entries, newest) = select_new(deltas, cursor);
        let ids: Vec<_> = entries.iter().map(|e| e.cve_id.as_str()).collect();
        assert_eq!(ids, vec!["CVE-2026-2", "CVE-2026-3"]);
        assert_eq!(newest.as_deref(), Some("2026-10-24T06:00:00.000Z"));

        let (entries, newest) = select_new(
            parse_deltas(log).unwrap(),
            parse_time("2026-10-24T06:00:00Z"),
        );
        assert!(entries.is_empty());
        assert!(newest.is_none());
    }

    #[test]
    fn uses_api_with_token() {
        let (url, headers) = delta_request(None, Some("t"), "delta.json");
        assert_eq!(url, format!("{API_BASE}/delta.json"));
        assert!(headers
            .iter()
            .any(|(k, v)| *k == "Authorization" && v == "Bearer t"));
        let (url, headers) = delta_request(None, None, "delta.json");
        assert_eq!(url, format!("{BASE}/delta.json"));
        assert!(headers.is_empty());
        let (url, _) = delta_request(Some("https://mirror/cves/"), Some("t"), "deltaLog.json");
        assert_eq!(url, "https://mirror/cves/deltaLog.json");
    }

    #[test]
    fn builds_record_url() {
        assert_eq!(
            record_url(BASE, "CVE-2026-12345"),
            format!("{BASE}/2026/12xxx/CVE-2026-12345.json")
        );
        assert_eq!(
            record_url(BASE, "CVE-2026-0042"),
            format!("{BASE}/2026/0xxx/CVE-2026-0042.json")
        );
    }

    #[test]
    fn parses_record() {
        let rec: Value = serde_json::from_str(
            r#"{
          "dataType": "CVE_RECORD",
          "dataVersion": "5.1",
          "cveMetadata": {"cveId": "CVE-2026-5555", "state": "PUBLISHED", "datePublished": "2026-10-24T05:00:00.000Z"},
          "containers": {
            "cna": {
              "title": "nginx  resolver heap overflow",
              "descriptions": [
                {"lang": "es", "value": "Desbordamiento"},
                {"lang": "en", "value": "A heap   overflow in the nginx resolver."}
              ],
              "affected": [
                {"vendor": "F5", "product": "NGINX Open Source", "versions": []},
                {"vendor": "n/a", "product": "n/a"},
                {"vendor": "Acme", "product": "lib", "packageName": "acme-lib"}
              ],
              "metrics": [{"cvssV3_1": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]
            },
            "adp": [
              {"metrics": [
                {"cvssV4_0": {"baseScore": 9.2, "baseSeverity": "CRITICAL"}},
                {"other": {"type": "kev", "content": {"dateAdded": "2026-10-24"}}}
              ]}
            ]
          }
        }"#,
        )
        .unwrap();
        let item = parse_record("cvelist", &rec).unwrap();
        assert_eq!(item.id, "CVE-2026-5555");
        assert_eq!(item.title, "nginx resolver heap overflow");
        assert_eq!(item.summary, "A heap overflow in the nginx resolver.");
        assert_eq!(item.products, vec!["F5 NGINX Open Source", "Acme lib"]);
        assert_eq!(item.packages, vec!["acme-lib"]);
        assert_eq!(item.cvss, Some(9.2));
        assert_eq!(item.severity.as_deref(), Some("CRITICAL"));
        assert!(item.kev);
    }

    #[test]
    fn skips_rejected_and_falls_back_to_description() {
        let rejected: Value = serde_json::from_str(
            r#"{"cveMetadata": {"cveId": "CVE-2026-1", "state": "REJECTED"}, "containers": {"cna": {}}}"#,
        )
        .unwrap();
        assert!(parse_record("cvelist", &rejected).is_none());

        let no_title: Value = serde_json::from_str(
            r#"{"cveMetadata": {"cveId": "CVE-2026-2", "state": "PUBLISHED"},
                "containers": {"cna": {"descriptions": [{"lang": "en-US", "value": "Short desc."}]}}}"#,
        )
        .unwrap();
        let item = parse_record("cvelist", &no_title).unwrap();
        assert_eq!(item.title, "Short desc.");
        assert_eq!(item.cvss, None);
        assert!(!item.kev);
    }
}
