//! `vuln-watch upgrade`: replace this installation with a newer GitHub release.
//!
//! Downloads the release archive for this architecture, checks it against the
//! release's SHA256SUMS and runs the bundled `deploy/install.sh`, which keeps
//! the existing config.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::http::Http;

const REPO: &str = "Matuyuhi/vuln-watch";

pub struct Options {
    /// Only report whether an update is available.
    pub check: bool,
    /// Install this version instead of the latest (may be a downgrade).
    pub version: Option<String>,
    /// Consider pre-releases. Implied when the running version is one.
    pub pre: bool,
    /// Reinstall even when already up to date.
    pub force: bool,
}

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

pub fn run(http: &Http, github_token: Option<&str>, opts: &Options) -> Result<()> {
    let current = Version::parse(env!("CARGO_PKG_VERSION"))?;
    let explicit = opts.version.is_some();
    let target = match &opts.version {
        Some(v) => parse_version(v)?,
        None => {
            let pre = opts.pre || !current.pre.is_empty();
            match latest(http, github_token, pre)? {
                Some(v) => v,
                None if pre => bail!("no releases of {REPO} found"),
                None => bail!("no stable release of {REPO} yet; use --pre to include pre-releases"),
            }
        }
    };

    let up_to_date = if explicit {
        target == current
    } else {
        target <= current
    };
    if opts.check {
        if up_to_date {
            println!("vuln-watch {current} is up to date (latest: {target})");
        } else {
            println!("update available: {current} -> {target}");
        }
        return Ok(());
    }
    if up_to_date && !opts.force {
        println!("vuln-watch {current} is up to date (latest: {target})");
        return Ok(());
    }

    if fs::metadata("/proc/self")?.uid() != 0 {
        bail!("upgrading writes /usr/local/bin and /etc/systemd; run as root: sudo vuln-watch upgrade");
    }

    println!("upgrading vuln-watch {current} -> {target}");
    install(http, &target)
}

pub fn parse_version(v: &str) -> Result<Version> {
    let v = v.strip_prefix('v').unwrap_or(v);
    Version::parse(v).with_context(|| format!("not a valid version: {v}"))
}

/// Newest published release, including pre-releases when `pre` is set.
pub fn latest(http: &Http, github_token: Option<&str>, pre: bool) -> Result<Option<Version>> {
    Ok(pick_latest(&fetch_releases(http, github_token)?, pre))
}

fn fetch_releases(http: &Http, github_token: Option<&str>) -> Result<Vec<Release>> {
    let mut headers = vec![("Accept", "application/vnd.github+json".to_string())];
    if let Some(t) = github_token {
        headers.push(("Authorization", format!("Bearer {t}")));
    }
    let url = format!("https://api.github.com/repos/{REPO}/releases?per_page=30");
    let resp = http.get(&url, &headers, None)?;
    serde_json::from_str(&resp.body).context("parsing the GitHub releases list")
}

/// Highest published version, optionally including pre-releases.
fn pick_latest(releases: &[Release], pre: bool) -> Option<Version> {
    releases
        .iter()
        .filter(|r| !r.draft && (pre || !r.prerelease))
        .filter_map(|r| parse_version(&r.tag_name).ok())
        .filter(|v| pre || v.pre.is_empty())
        .max()
}

fn install(http: &Http, version: &Version) -> Result<()> {
    let target = format!("{}-unknown-linux-gnu", std::env::consts::ARCH);
    let name = format!("vuln-watch-v{version}-{target}");
    let archive = format!("{name}.tar.gz");
    let base = format!("https://github.com/{REPO}/releases/download/v{version}");

    let sums = download(http, &format!("{base}/SHA256SUMS"))
        .with_context(|| format!("release v{version} not found"))?;
    let sums = String::from_utf8(sums).context("SHA256SUMS is not UTF-8")?;
    let expected = checksum_for(&sums, &archive).with_context(|| {
        format!("{archive} is not listed in SHA256SUMS (no build for {target}?)")
    })?;

    println!("downloading {archive}");
    let data = download(http, &format!("{base}/{archive}"))?;
    let actual = hex(&Sha256::digest(&data));
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("checksum mismatch for {archive}: expected {expected}, got {actual}");
    }

    let dir = TempDir::new()?;
    let archive_path = dir.path().join(&archive);
    fs::write(&archive_path, &data)
        .with_context(|| format!("writing {}", archive_path.display()))?;
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(&archive_path)
        .arg("-C")
        .arg(dir.path())
        .status()
        .context("running tar")?;
    if !status.success() {
        bail!("tar failed to extract {archive} ({status})");
    }

    let script = dir.path().join(&name).join("deploy/install.sh");
    let status = Command::new(&script)
        .status()
        .with_context(|| format!("running {}", script.display()))?;
    if !status.success() {
        bail!("{} failed ({status})", script.display());
    }
    Ok(())
}

fn download(http: &Http, url: &str) -> Result<Vec<u8>> {
    let resp = http
        .client()
        .get(url)
        .send()
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("GET {url} returned HTTP {}", status.as_u16());
    }
    Ok(resp
        .bytes()
        .with_context(|| format!("reading body of {url}"))?
        .to_vec())
}

/// Find the hash for `file` in `sha256sum` output.
fn checksum_for<'a>(sums: &'a str, file: &str) -> Option<&'a str> {
    sums.lines().find_map(|line| {
        let (hash, name) = line.split_once(char::is_whitespace)?;
        let name = name.trim_start().trim_start_matches('*');
        (name == file).then_some(hash)
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Private scratch directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!("vuln-watch-upgrade-{}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path).with_context(|| format!("removing {}", path.display()))?;
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(tag: &str, prerelease: bool) -> Release {
        Release {
            tag_name: tag.to_string(),
            draft: false,
            prerelease,
        }
    }

    #[test]
    fn picks_highest_stable_version() {
        let releases = vec![
            rel("v1.2.0-rc.1", true),
            rel("v1.10.0", false),
            rel("v1.9.3", false),
            rel("not-a-version", false),
        ];
        assert_eq!(pick_latest(&releases, false), Some(Version::new(1, 10, 0)));
    }

    #[test]
    fn pre_releases_only_when_asked() {
        let releases = vec![rel("v1.0.0-rc.2", true), rel("v1.0.0-rc.10", true)];
        assert_eq!(pick_latest(&releases, false), None);
        assert_eq!(
            pick_latest(&releases, true),
            Some(Version::parse("1.0.0-rc.10").unwrap())
        );
        let mut with_stable = releases;
        with_stable.push(rel("v1.0.0", false));
        assert_eq!(pick_latest(&with_stable, true), Some(Version::new(1, 0, 0)));
    }

    #[test]
    fn skips_drafts() {
        let mut draft = rel("v9.0.0", false);
        draft.draft = true;
        assert_eq!(
            pick_latest(&[draft, rel("v1.0.0", false)], false),
            Some(Version::new(1, 0, 0))
        );
    }

    #[test]
    fn finds_checksum_line() {
        let sums = "aaa  vuln-watch-v1.0.0-aarch64-unknown-linux-gnu.tar.gz\n\
                    bbb *vuln-watch-v1.0.0-x86_64-unknown-linux-gnu.tar.gz\n";
        assert_eq!(
            checksum_for(sums, "vuln-watch-v1.0.0-aarch64-unknown-linux-gnu.tar.gz"),
            Some("aaa")
        );
        assert_eq!(
            checksum_for(sums, "vuln-watch-v1.0.0-x86_64-unknown-linux-gnu.tar.gz"),
            Some("bbb")
        );
        assert_eq!(checksum_for(sums, "vuln-watch-v1.0.0.tar.gz"), None);
    }

    #[test]
    fn parses_versions_with_or_without_v() {
        assert_eq!(parse_version("v1.2.3").unwrap(), Version::new(1, 2, 3));
        assert_eq!(parse_version("1.2.3").unwrap(), Version::new(1, 2, 3));
        assert!(parse_version("latest").is_err());
    }
}
