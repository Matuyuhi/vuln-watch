use std::collections::HashSet;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub discord: DiscordConfig,
    #[serde(default)]
    pub rules: Rules,
    #[serde(default)]
    pub runtime: Runtime,
    #[serde(default)]
    pub installed: InstalledConfig,
    #[serde(default, rename = "watch")]
    pub watches: Vec<Watch>,
    #[serde(default, rename = "source")]
    pub sources: Vec<SourceConfig>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryMode {
    /// Direct message from a bot (needs DISCORD_BOT_TOKEN and user_id).
    #[default]
    Dm,
    /// Incoming webhook of a channel (needs DISCORD_WEBHOOK_URL).
    Webhook,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscordConfig {
    #[serde(default)]
    pub mode: DeliveryMode,
    /// Discord user id to DM. Can be overridden by the DISCORD_USER_ID env var.
    pub user_id: Option<String>,
    /// Display name when sending through a webhook.
    pub username: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    /// Items in CISA KEV are always urgent.
    #[serde(default = "default_true")]
    pub kev_urgent: bool,
    /// A watch-list match is urgent when CVSS >= this (or when CVSS is unknown);
    /// otherwise it goes to the daily digest.
    #[serde(default = "default_watch_urgent_cvss")]
    pub watch_urgent_cvss: f32,
    /// Any item with CVSS >= this is urgent even without a watch-list match. Unset = disabled.
    #[serde(default)]
    pub urgent_cvss: Option<f32>,
    /// Any item with CVSS >= this goes to the digest. Unset = disabled.
    #[serde(default = "default_digest_cvss")]
    pub digest_cvss: Option<f32>,
    /// Items whose text contains any of these (case-insensitive, word match) are ignored
    /// unless they are in KEV or match the watch list.
    #[serde(default)]
    pub exclude_keywords: Vec<String>,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            kev_urgent: true,
            watch_urgent_cvss: default_watch_urgent_cvss(),
            urgent_cvss: None,
            digest_cvss: default_digest_cvss(),
            exclude_keywords: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    /// Maximum urgent messages per run; the rest go to the digest.
    #[serde(default = "default_max_urgent")]
    pub max_urgent_per_run: usize,
    /// Send a warning after this many consecutive failures of one source.
    #[serde(default = "default_alert_after")]
    pub alert_after_failures: u32,
    #[serde(default = "default_timeout")]
    pub http_timeout_secs: u64,
    /// Pinged after every successful run (e.g. healthchecks.io). HEARTBEAT_URL env overrides.
    #[serde(default)]
    pub heartbeat_url: Option<String>,
    /// Send a digest message even when there is nothing to report.
    #[serde(default)]
    pub digest_send_empty: bool,
    /// Upper bound of CVE records fetched per run from the CVE List.
    #[serde(default = "default_cvelist_max")]
    pub cvelist_max_records: usize,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            max_urgent_per_run: default_max_urgent(),
            alert_after_failures: default_alert_after(),
            http_timeout_secs: default_timeout(),
            heartbeat_url: None,
            digest_send_empty: false,
            cvelist_max_records: default_cvelist_max(),
        }
    }
}

/// What to do with a notice whose packages are installed but already at the fixed version.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AlreadyFixed {
    #[default]
    Digest,
    Ignore,
}

/// Match Ubuntu Security Notices against the packages installed on this machine.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_dpkg_status")]
    pub dpkg_status: String,
    #[serde(default = "default_os_release")]
    pub os_release: String,
    /// Ubuntu codename such as "noble". Default: read from os_release.
    #[serde(default)]
    pub release: Option<String>,
    #[serde(default)]
    pub already_fixed: AlreadyFixed,
}

impl Default for InstalledConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dpkg_status: default_dpkg_status(),
            os_release: default_os_release(),
            release: None,
            already_fixed: AlreadyFixed::Digest,
        }
    }
}

fn default_dpkg_status() -> String {
    "/var/lib/dpkg/status".into()
}
fn default_os_release() -> String {
    "/etc/os-release".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watch {
    pub name: String,
    /// Words matched (case-insensitive, at word boundaries) against title, summary and products.
    /// Defaults to `[name]` when both `keywords` and `packages` are empty.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Exact package names (e.g. "com.squareup.okhttp3:okhttp", "tokio").
    #[serde(default)]
    pub packages: Vec<String>,
    /// Only apply to these source names (empty = all sources).
    #[serde(default)]
    pub sources: Vec<String>,
    /// false: matches only go to the digest (for noisy targets).
    #[serde(default = "default_true")]
    pub urgent: bool,
}

impl Watch {
    pub fn applies_to(&self, source: &str) -> bool {
        self.sources.is_empty() || self.sources.iter().any(|s| s == source)
    }

    pub fn effective_keywords(&self) -> Vec<String> {
        if self.keywords.is_empty() && self.packages.is_empty() {
            vec![self.name.to_lowercase()]
        } else {
            self.keywords.iter().map(|k| k.to_lowercase()).collect()
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    Kev,
    Ghsa,
    Cvelist,
    Feed,
    /// Ubuntu Security Notices (JSON API, with per-release package versions).
    Usn,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Kev => "kev",
            SourceKind::Ghsa => "ghsa",
            SourceKind::Cvelist => "cvelist",
            SourceKind::Feed => "feed",
            SourceKind::Usn => "usn",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SourceMode {
    /// Apply the normal rules (KEV / watch list / CVSS).
    #[default]
    Filter,
    /// Every new entry is urgent.
    Urgent,
    /// Every new entry goes to the digest.
    Digest,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    pub kind: SourceKind,
    /// Unique name. Defaults to the kind.
    pub name: Option<String>,
    /// Feed URL (required for `feed`), or an override for other kinds.
    pub url: Option<String>,
    #[serde(default)]
    pub mode: SourceMode,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Drop entries whose title starts with any of these (case-insensitive), e.g. ["Re:"].
    #[serde(default)]
    pub ignore_title_prefixes: Vec<String>,
    /// `usn` only: Ubuntu codename to query. Default: installed.release / os-release.
    #[serde(default)]
    pub release: Option<String>,
}

impl SourceConfig {
    pub fn name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| self.kind.as_str().to_string())
    }
}

fn default_true() -> bool {
    true
}
fn default_watch_urgent_cvss() -> f32 {
    7.0
}
fn default_digest_cvss() -> Option<f32> {
    Some(9.0)
}
fn default_max_urgent() -> usize {
    10
}
fn default_alert_after() -> u32 {
    5
}
fn default_timeout() -> u64 {
    30
}
fn default_cvelist_max() -> usize {
    300
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("invalid config {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut cfg: Config = toml::from_str(text)?;
        if cfg.sources.is_empty() {
            cfg.sources = default_sources();
        }
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        let mut names = HashSet::new();
        for s in &self.sources {
            let name = s.name();
            if !names.insert(name.clone()) {
                bail!("duplicate source name `{name}` (set `name` to make it unique)");
            }
            if s.kind == SourceKind::Feed && s.url.is_none() {
                bail!("source `{name}` (kind = \"feed\") needs `url`");
            }
        }
        for w in &self.watches {
            if w.name.trim().is_empty() {
                bail!("watch entry with empty name");
            }
            for s in &w.sources {
                if !names.contains(s) {
                    bail!("watch `{}` refers to unknown source `{s}`", w.name);
                }
            }
        }
        Ok(())
    }
}

pub fn default_sources() -> Vec<SourceConfig> {
    [SourceKind::Kev, SourceKind::Ghsa, SourceKind::Cvelist]
        .into_iter()
        .map(|kind| SourceConfig {
            kind,
            name: None,
            url: None,
            mode: SourceMode::Filter,
            enabled: true,
            ignore_title_prefixes: Vec::new(),
            release: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let cfg = Config::parse("").unwrap();
        assert_eq!(cfg.sources.len(), 3);
        assert!(cfg.rules.kev_urgent);
        assert_eq!(cfg.discord.mode, DeliveryMode::Dm);
    }

    #[test]
    fn parses_example_config() {
        let text = include_str!("../config.example.toml");
        let cfg = Config::parse(text).unwrap();
        assert!(!cfg.watches.is_empty());
        assert!(cfg.sources.iter().any(|s| s.kind == SourceKind::Feed));
    }

    #[test]
    fn rejects_feed_without_url() {
        let err = Config::parse("[[source]]\nkind = \"feed\"\nname = \"x\"\n").unwrap_err();
        assert!(format!("{err:#}").contains("needs `url`"));
    }

    #[test]
    fn rejects_duplicate_names() {
        let err =
            Config::parse("[[source]]\nkind = \"kev\"\n[[source]]\nkind = \"kev\"\n").unwrap_err();
        assert!(format!("{err:#}").contains("duplicate"));
    }

    #[test]
    fn watch_defaults_to_name() {
        let w = Watch {
            name: "Nginx".into(),
            keywords: vec![],
            packages: vec![],
            sources: vec![],
            urgent: true,
        };
        assert_eq!(w.effective_keywords(), vec!["nginx"]);
        assert!(w.applies_to("anything"));
    }
}
