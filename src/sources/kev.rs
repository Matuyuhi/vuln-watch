//! CISA Known Exploited Vulnerabilities catalog.

use anyhow::{Context, Result};
use serde::Deserialize;

use super::{Ctx, Fetched};
use crate::http::Validators;
use crate::model::Item;

pub const DEFAULT_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Deserialize)]
struct Catalog {
    vulnerabilities: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(default)]
    vendor_project: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    vulnerability_name: String,
    #[serde(default)]
    date_added: String,
    #[serde(default)]
    short_description: String,
    #[serde(default)]
    required_action: String,
    #[serde(default)]
    due_date: String,
    #[serde(default)]
    known_ransomware_campaign_use: String,
}

pub fn fetch(name: &str, url: Option<&str>, ctx: &Ctx) -> Result<Fetched> {
    let url = url.unwrap_or(DEFAULT_URL);
    let validators = Validators::load(ctx.db, url)?;
    let resp = ctx.http.get(url, &[], Some(&validators))?;
    let commit = Validators::commit_pairs(url, &resp);
    if resp.not_modified() {
        return Ok(Fetched::empty());
    }
    let items = parse(name, &resp.body)?;
    Ok(Fetched { items, commit })
}

pub fn parse(source: &str, body: &str) -> Result<Vec<Item>> {
    let catalog: Catalog = serde_json::from_str(body).context("parsing KEV catalog")?;
    let mut entries = catalog.vulnerabilities;
    // Newest first (dateAdded is YYYY-MM-DD).
    entries.sort_by(|a, b| b.date_added.cmp(&a.date_added));
    Ok(entries
        .into_iter()
        .map(|e| {
            let mut item = Item::new(source, e.cve_id.clone());
            item.cve = Some(e.cve_id.clone());
            item.title = if e.vulnerability_name.is_empty() {
                format!("{} {}", e.vendor_project, e.product)
            } else {
                e.vulnerability_name
            };
            item.summary = e.short_description;
            item.url = format!("https://www.cve.org/CVERecord?id={}", e.cve_id);
            item.products = vec![format!("{} {}", e.vendor_project, e.product)];
            item.kev = true;
            item.published = Some(e.date_added.clone());
            item.extra.push(("KEV追加日".into(), e.date_added));
            if !e.due_date.is_empty() {
                item.extra.push(("対応期限(米連邦機関)".into(), e.due_date));
            }
            if e.known_ransomware_campaign_use
                .eq_ignore_ascii_case("known")
            {
                item.extra
                    .push(("ランサムウェア".into(), "悪用が確認されている".into()));
            }
            if !e.required_action.is_empty() {
                item.extra.push((
                    "推奨対応".into(),
                    crate::text::truncate(&e.required_action, 300),
                ));
            }
            item
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "title": "CISA Catalog of Known Exploited Vulnerabilities",
      "catalogVersion": "2026.10.23",
      "dateReleased": "2026-10-23T17:00:00.000Z",
      "count": 2,
      "vulnerabilities": [
        {
          "cveID": "CVE-2025-0001",
          "vendorProject": "Acme",
          "product": "Router",
          "vulnerabilityName": "Acme Router Command Injection",
          "dateAdded": "2025-01-10",
          "shortDescription": "Command injection.",
          "requiredAction": "Apply mitigations per vendor instructions.",
          "dueDate": "2025-01-31",
          "knownRansomwareCampaignUse": "Unknown",
          "notes": "",
          "cwes": ["CWE-78"]
        },
        {
          "cveID": "CVE-2026-1234",
          "vendorProject": "nginx",
          "product": "nginx",
          "vulnerabilityName": "nginx Buffer Overflow",
          "dateAdded": "2026-10-23",
          "shortDescription": "Overflow in resolver.",
          "requiredAction": "Update.",
          "dueDate": "2026-11-13",
          "knownRansomwareCampaignUse": "Known",
          "notes": "",
          "cwes": []
        }
      ]
    }"#;

    #[test]
    fn parses_catalog_newest_first() {
        let items = parse("kev", SAMPLE).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].id, "CVE-2026-1234");
        assert!(items[0].kev);
        assert_eq!(items[0].products, vec!["nginx nginx"]);
        assert!(items[0].extra.iter().any(|(k, _)| k == "ランサムウェア"));
        assert!(!items[1].extra.iter().any(|(k, _)| k == "ランサムウェア"));
    }
}
