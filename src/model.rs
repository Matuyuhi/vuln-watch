use serde::{Deserialize, Serialize};

/// A single vulnerability / advisory / notice, normalized across sources.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Item {
    /// Name of the configured source this item came from.
    pub source: String,
    /// Unique id within the source (CVE id, GHSA id, feed guid, ...).
    pub id: String,
    /// CVE id when known. Used to de-duplicate across sources.
    pub cve: Option<String>,
    pub title: String,
    pub summary: String,
    pub url: String,
    /// Highest known CVSS base score.
    pub cvss: Option<f32>,
    /// Severity label such as "critical" / "HIGH".
    pub severity: Option<String>,
    /// Human readable affected products, e.g. "nginx nginx" or "maven:com.squareup.okhttp3:okhttp".
    pub products: Vec<String>,
    /// Exact package names (ecosystem-specific), matched against `watch.packages`.
    pub packages: Vec<String>,
    /// Listed in CISA Known Exploited Vulnerabilities.
    pub kev: bool,
    pub published: Option<String>,
    /// Additional key/value pairs shown in the notification.
    pub extra: Vec<(String, String)>,
    /// Distro packages and the version that fixes them, for the configured release
    /// (Ubuntu Security Notices). Compared against installed packages.
    #[serde(default)]
    pub fixed: Vec<(String, String)>,
    /// Set only for advisories written by the scheduled Claude research (`advisory` sources);
    /// they are decided by their own rule instead of KEV / CVSS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// How well an advisory is backed by primary sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Only news / blogs, or nothing that could be checked.
    Unverified,
    Likely,
    /// Confirmed by a primary source (vendor, CERT, NVD, GHSA).
    Confirmed,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Unverified => "未検証",
            Confidence::Likely => "可能性高",
            Confidence::Confirmed => "一次情報で確認済み",
        }
    }
}

impl Item {
    pub fn new(source: &str, id: impl Into<String>) -> Self {
        Self {
            source: source.to_string(),
            id: id.into(),
            ..Default::default()
        }
    }

    /// Key used to avoid notifying the same vulnerability twice via different sources.
    pub fn dedupe_key(&self) -> String {
        match &self.cve {
            Some(cve) => cve.to_ascii_uppercase(),
            None => format!("{}:{}", self.source, self.id),
        }
    }

    /// Key for notification de-duplication. A KEV listing is tracked separately so that
    /// "now exploited in the wild" is still reported for a CVE that was already notified.
    pub fn alert_key(&self) -> String {
        if self.kev {
            format!("{}#kev", self.dedupe_key())
        } else {
            self.dedupe_key()
        }
    }

    /// Id shown to the user: the CVE id, or a short form of URL-like feed ids
    /// (e.g. ".../notices/USN-8954-1" -> "USN-8954-1").
    pub fn display_id(&self) -> &str {
        if let Some(cve) = &self.cve {
            return cve;
        }
        if self.id.contains("://") || self.id.starts_with("tag:") {
            if let Some(last) = self
                .id
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
            {
                return last;
            }
        }
        &self.id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Level {
    Ignore = 0,
    Digest = 1,
    Urgent = 2,
}

impl Level {
    pub fn as_i64(self) -> i64 {
        self as i64
    }

    pub fn from_i64(v: i64) -> Self {
        match v {
            2 => Level::Urgent,
            1 => Level::Digest,
            _ => Level::Ignore,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub level: Level,
    pub reason: String,
}

impl Decision {
    pub fn new(level: Level, reason: impl Into<String>) -> Self {
        Self {
            level,
            reason: reason.into(),
        }
    }
}

/// Extract all CVE ids (deduplicated, in order of appearance) from free text.
pub fn find_cves(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        if bytes[i..].len() >= 4 && bytes[i..i + 4].eq_ignore_ascii_case(b"CVE-") {
            let start = i;
            let mut j = i + 4;
            let year_start = j;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j - year_start == 4 && j < bytes.len() && bytes[j] == b'-' {
                j += 1;
                let num_start = j;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                if j - num_start >= 4 {
                    let id = text[start..j].to_ascii_uppercase();
                    if !out.contains(&id) {
                        out.push(id);
                    }
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_cves() {
        let t = "Fixes CVE-2026-12345 and cve-2025-0001, again CVE-2026-12345. Not CVE-26-1 or CVE-2026-12.";
        assert_eq!(find_cves(t), vec!["CVE-2026-12345", "CVE-2025-0001"]);
    }

    #[test]
    fn dedupe_key_prefers_cve() {
        let mut item = Item::new("ghsa", "GHSA-xxxx");
        assert_eq!(item.dedupe_key(), "ghsa:GHSA-xxxx");
        item.cve = Some("cve-2026-1111".into());
        assert_eq!(item.dedupe_key(), "CVE-2026-1111");
        assert_eq!(item.display_id(), "cve-2026-1111");
        assert_eq!(item.alert_key(), "CVE-2026-1111");
        item.kev = true;
        assert_eq!(item.alert_key(), "CVE-2026-1111#kev");
    }

    #[test]
    fn display_id_shortens_urls() {
        let item = Item::new("usn", "https://ubuntu.com/security/notices/USN-8954-1");
        assert_eq!(item.display_id(), "USN-8954-1");
        let item = Item::new("rel", "tag:github.com,2008:Repository/1/release-1.31.8");
        assert_eq!(item.display_id(), "release-1.31.8");
        let item = Item::new("ghsa", "GHSA-xxxx");
        assert_eq!(item.display_id(), "GHSA-xxxx");
    }
}
