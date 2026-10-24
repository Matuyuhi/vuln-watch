//! Generic RSS / Atom feed (Ubuntu USN, vendor bulletins, GitHub releases, ...).

use anyhow::{Context, Result};

use super::{Ctx, Fetched};
use crate::http::Validators;
use crate::model::{find_cves, Item};
use crate::text::{strip_html, truncate};

pub fn fetch(name: &str, url: &str, ctx: &Ctx) -> Result<Fetched> {
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
    let feed = feed_rs::parser::parse(body.as_bytes())
        .with_context(|| format!("parsing feed for {source}"))?;
    Ok(feed
        .entries
        .into_iter()
        .map(|e| {
            let title = e.title.map(|t| strip_html(&t.content)).unwrap_or_default();
            let summary_raw = e
                .summary
                .map(|t| t.content)
                .or_else(|| e.content.and_then(|c| c.body))
                .unwrap_or_default();
            let summary = strip_html(&summary_raw);
            let url = e.links.first().map(|l| l.href.clone()).unwrap_or_default();
            let id = if e.id.is_empty() { url.clone() } else { e.id };

            let mut item = Item::new(source, id);
            let cves = find_cves(&format!("{title} {summary}"));
            if cves.len() == 1 {
                item.cve = Some(cves[0].clone());
            } else if cves.len() > 1 {
                let shown: Vec<_> = cves.iter().take(8).cloned().collect();
                let mut v = shown.join(", ");
                if cves.len() > shown.len() {
                    v.push_str(&format!(" 他{}件", cves.len() - shown.len()));
                }
                item.extra.push(("CVE".into(), v));
            }
            item.title = if title.is_empty() {
                truncate(&summary, 120)
            } else {
                title
            };
            item.summary = truncate(&summary, 800);
            item.url = url;
            item.published = e.published.or(e.updated).map(|d| d.to_rfc3339());
            item
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSS: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>Ubuntu security notices</title>
    <link>https://ubuntu.com/security/notices</link>
    <description>Recent content</description>
    <item>
      <title>USN-8954-1: zlib vulnerability</title>
      <link>https://ubuntu.com/security/notices/USN-8954-1</link>
      <description>&lt;p&gt;It was discovered that zlib did not correctly handle memory (CVE-2026-40001).&lt;/p&gt;</description>
      <guid isPermaLink="true">https://ubuntu.com/security/notices/USN-8954-1</guid>
      <pubDate>Thu, 23 Oct 2026 12:00:00 +0000</pubDate>
    </item>
    <item>
      <title>USN-8953-1: Linux kernel vulnerabilities</title>
      <link>https://ubuntu.com/security/notices/USN-8953-1</link>
      <description>Several issues: CVE-2026-1, CVE-2026-10001, CVE-2026-10002.</description>
      <guid isPermaLink="true">https://ubuntu.com/security/notices/USN-8953-1</guid>
    </item>
  </channel>
</rss>"#;

    #[test]
    fn parses_rss() {
        let items = parse("usn", RSS).unwrap();
        assert_eq!(items.len(), 2);
        let a = &items[0];
        assert_eq!(a.title, "USN-8954-1: zlib vulnerability");
        assert_eq!(a.url, "https://ubuntu.com/security/notices/USN-8954-1");
        assert_eq!(a.cve.as_deref(), Some("CVE-2026-40001"));
        assert!(a.summary.starts_with("It was discovered"));
        assert!(a.published.is_some());

        let b = &items[1];
        assert_eq!(b.cve, None);
        assert!(b
            .extra
            .iter()
            .any(|(k, v)| k == "CVE" && v == "CVE-2026-10001, CVE-2026-10002"));
    }

    #[test]
    fn parses_atom() {
        let atom = r#"<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Releases</title>
  <id>tag:github.com,2008:releases</id>
  <updated>2026-10-23T00:00:00Z</updated>
  <entry>
    <id>tag:github.com,2008:Repository/1/v1.2.3</id>
    <updated>2026-10-23T00:00:00Z</updated>
    <link rel="alternate" type="text/html" href="https://github.com/o/r/releases/tag/v1.2.3"/>
    <title>v1.2.3</title>
    <content type="html">&lt;p&gt;Security fix&lt;/p&gt;</content>
  </entry>
</feed>"#;
        let items = parse("rel", atom).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "tag:github.com,2008:Repository/1/v1.2.3");
        assert_eq!(items[0].title, "v1.2.3");
        assert_eq!(items[0].summary, "Security fix");
        assert_eq!(items[0].url, "https://github.com/o/r/releases/tag/v1.2.3");
    }
}
