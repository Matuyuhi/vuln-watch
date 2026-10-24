//! Packages installed on this machine (dpkg), used to match Ubuntu Security Notices.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

use crate::config::InstalledConfig;

#[derive(Debug, Default, Clone)]
pub struct Installed {
    /// Ubuntu release codename (e.g. "noble").
    pub release: Option<String>,
    packages: HashMap<String, String>,
}

impl Installed {
    pub fn load(cfg: &InstalledConfig) -> Result<Self> {
        let status_path = Path::new(&cfg.dpkg_status);
        let text = std::fs::read_to_string(status_path).with_context(|| {
            format!(
                "reading {} (installed.enabled = true needs a dpkg-based system)",
                status_path.display()
            )
        })?;
        let release = match &cfg.release {
            Some(r) => Some(r.clone()),
            None => std::fs::read_to_string(&cfg.os_release)
                .ok()
                .and_then(|t| codename_from_os_release(&t)),
        };
        let packages = parse_dpkg_status(&text);
        tracing::debug!(
            "installed: {} packages, release {:?}",
            packages.len(),
            release
        );
        Ok(Self { release, packages })
    }

    #[cfg(test)]
    pub fn from_pairs(release: &str, pairs: &[(&str, &str)]) -> Self {
        Self {
            release: Some(release.to_string()),
            packages: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    pub fn version(&self, package: &str) -> Option<&str> {
        self.packages.get(package).map(String::as_str)
    }

    pub fn package_count(&self) -> usize {
        self.packages.len()
    }
}

/// Installed packages from /var/lib/dpkg/status: Package -> Version.
pub fn parse_dpkg_status(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for para in text.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut installed = false;
        for line in para.lines() {
            if let Some(v) = line.strip_prefix("Package:") {
                name = Some(v.trim());
            } else if let Some(v) = line.strip_prefix("Version:") {
                version = Some(v.trim());
            } else if let Some(v) = line.strip_prefix("Status:") {
                // e.g. "install ok installed"; excludes "deinstall ok config-files".
                installed = v.split_whitespace().last() == Some("installed");
            }
        }
        if let (Some(n), Some(v), true) = (name, version, installed) {
            out.insert(n.to_string(), v.to_string());
        }
    }
    out
}

/// VERSION_CODENAME (or UBUNTU_CODENAME) from /etc/os-release.
pub fn codename_from_os_release(text: &str) -> Option<String> {
    let get = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches('"').to_string())
            .filter(|v| !v.is_empty())
    };
    get("UBUNTU_CODENAME").or_else(|| get("VERSION_CODENAME"))
}

/// Compare two Debian package versions (`[epoch:]upstream[-revision]`) like dpkg does.
pub fn cmp_deb_version(a: &str, b: &str) -> Ordering {
    let (ea, ua, ra) = split_version(a);
    let (eb, ub, rb) = split_version(b);
    ea.cmp(&eb)
        .then_with(|| verrevcmp(ua, ub))
        .then_with(|| verrevcmp(ra, rb))
}

fn split_version(v: &str) -> (u64, &str, &str) {
    let v = v.trim();
    let (epoch, rest) = match v.split_once(':') {
        Some((e, r)) if !e.is_empty() && e.bytes().all(|c| c.is_ascii_digit()) => {
            (e.parse().unwrap_or(0), r)
        }
        _ => (0, v),
    };
    match rest.rsplit_once('-') {
        Some((u, r)) => (epoch, u, r),
        None => (epoch, rest, ""),
    }
}

fn order(c: u8) -> i32 {
    match c {
        0 => 0,
        b'0'..=b'9' => 0,
        b'a'..=b'z' | b'A'..=b'Z' => c as i32,
        b'~' => -1,
        _ => c as i32 + 256,
    }
}

fn verrevcmp(a: &str, b: &str) -> Ordering {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let at = |i: usize| a.get(i).copied().unwrap_or(0);
    let bt = |i: usize| b.get(i).copied().unwrap_or(0);
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        while (i < a.len() && !at(i).is_ascii_digit()) || (j < b.len() && !bt(j).is_ascii_digit()) {
            let (ac, bc) = (order(at(i)), order(bt(j)));
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        while at(i) == b'0' {
            i += 1;
        }
        while bt(j) == b'0' {
            j += 1;
        }
        let mut first_diff = Ordering::Equal;
        while at(i).is_ascii_digit() && bt(j).is_ascii_digit() {
            if first_diff == Ordering::Equal {
                first_diff = at(i).cmp(&bt(j));
            }
            i += 1;
            j += 1;
        }
        if at(i).is_ascii_digit() {
            return Ordering::Greater;
        }
        if bt(j).is_ascii_digit() {
            return Ordering::Less;
        }
        if first_diff != Ordering::Equal {
            return first_diff;
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::*;

    #[test]
    fn debian_version_ordering() {
        let cases = [
            ("1:1.3.dfsg-3.1ubuntu2.2", "1:1.3.dfsg-3.1ubuntu2.3", Less),
            ("2.39-0ubuntu8.9", "2.39-0ubuntu8.10", Less),
            ("1:9.6p1-3ubuntu13.19", "1:9.6p1-3ubuntu13.19", Equal),
            ("1.0~rc1", "1.0", Less),
            ("1.0", "1.0+b1", Less),
            ("1:1.0", "2.0", Greater),
            ("1.0-1", "1.0", Greater),
            ("6.8.0.86.87", "6.8.0.87.88", Less),
            ("1.2.10", "1.2.9", Greater),
            ("1.01", "1.1", Equal),
            ("1.0a", "1.0", Greater),
            ("1.0~~", "1.0~", Less),
        ];
        for (a, b, want) in cases {
            assert_eq!(cmp_deb_version(a, b), want, "{a} vs {b}");
            assert_eq!(cmp_deb_version(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn parses_status() {
        let text = "Package: zlib1g\nStatus: install ok installed\nPriority: required\nSource: zlib\nVersion: 1:1.3.dfsg-3.1ubuntu2.2\nDescription: x\n continuation\n\nPackage: oldpkg\nStatus: deinstall ok config-files\nVersion: 1.0\n\nPackage: nginx\nStatus: install ok installed\nVersion: 1.24.0-2ubuntu7.5\n";
        let m = parse_dpkg_status(text);
        assert_eq!(m.len(), 2);
        assert_eq!(m["zlib1g"], "1:1.3.dfsg-3.1ubuntu2.2");
        assert_eq!(m["nginx"], "1.24.0-2ubuntu7.5");
        assert!(!m.contains_key("oldpkg"));
    }

    #[test]
    fn reads_codename() {
        let t = "NAME=\"Ubuntu\"\nVERSION_CODENAME=noble\nUBUNTU_CODENAME=noble\n";
        assert_eq!(codename_from_os_release(t).as_deref(), Some("noble"));
        assert_eq!(
            codename_from_os_release("VERSION_CODENAME=\"jammy\"").as_deref(),
            Some("jammy")
        );
        assert_eq!(codename_from_os_release("NAME=Debian"), None);
    }
}
