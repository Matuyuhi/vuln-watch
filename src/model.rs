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

    /// Id shown to the user (prefers the CVE id).
    pub fn display_id(&self) -> &str {
        self.cve.as_deref().unwrap_or(&self.id)
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
    }
}
