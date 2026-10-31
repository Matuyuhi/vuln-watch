use std::cmp::Ordering;

use crate::config::{AlreadyFixed, Rules, SourceMode, Watch};
use crate::installed::{cmp_deb_version, split_kernel_release, Installed};
use crate::model::{Confidence, Decision, Item, Level};
use crate::text::contains_word;

/// How a watch entry matched an item.
#[derive(Debug, Clone)]
pub struct WatchMatch<'a> {
    pub watch: &'a Watch,
    /// Matched on a structured / headline field (package, product, title).
    /// Weak matches (description only) are more likely to be false positives.
    pub strong: bool,
    /// Human readable evidence, e.g. "製品: nginx".
    pub evidence: String,
}

/// Find the best watch match, whatever the order of the entries: a strong match from an
/// `urgent = true` entry wins, then a strong match from a digest-only entry, then a
/// description-only match. Within the same rank the first entry in config order wins.
pub fn match_watch<'a>(item: &Item, watches: &'a [Watch]) -> Option<WatchMatch<'a>> {
    let packages: Vec<String> = item.packages.iter().map(|p| p.to_lowercase()).collect();
    let title = item.title.to_lowercase();
    let products = item
        .products
        .iter()
        .chain(item.packages.iter())
        .map(|p| p.to_lowercase())
        .collect::<Vec<_>>()
        .join("\n");
    let summary = item.summary.to_lowercase();

    let strong_evidence = |w: &Watch| -> Option<String> {
        if let Some(p) = w
            .packages
            .iter()
            .find(|p| packages.contains(&p.to_lowercase()))
        {
            return Some(format!("パッケージ: {p}"));
        }
        let keywords = w.effective_keywords();
        if let Some(k) = keywords.iter().find(|k| contains_word(&products, k)) {
            return Some(format!("製品: {k}"));
        }
        keywords
            .iter()
            .find(|k| contains_word(&title, k))
            .map(|k| format!("タイトル: {k}"))
    };

    let mut digest_only: Option<WatchMatch<'a>> = None;
    let mut weak: Option<WatchMatch<'a>> = None;
    for w in watches.iter().filter(|w| w.applies_to(&item.source)) {
        if let Some(evidence) = strong_evidence(w) {
            let m = WatchMatch {
                watch: w,
                strong: true,
                evidence,
            };
            if w.urgent {
                return Some(m);
            }
            digest_only.get_or_insert(m);
            continue;
        }
        if weak.is_none() {
            if let Some(k) = w
                .effective_keywords()
                .iter()
                .find(|k| contains_word(&summary, k))
            {
                weak = Some(WatchMatch {
                    watch: w,
                    strong: false,
                    evidence: format!("本文のみ: {k}"),
                });
            }
        }
    }
    digest_only.or(weak)
}

/// Prefix of reasons for items matched only by CVSS score (nothing ties them to you).
pub const SCORE_ONLY_PREFIX: &str = "CVSS ";

/// True when the decision was made on the CVSS score alone.
pub fn is_score_only(reason: &str) -> bool {
    reason.starts_with(SCORE_ONLY_PREFIX)
}

fn enabled(threshold: Option<f32>) -> Option<f32> {
    threshold.filter(|t| *t > 0.0)
}

fn fmt_cvss(c: f32) -> String {
    format!("{c:.1}")
}

fn contains_any(item: &Item, words: &[String]) -> bool {
    if words.is_empty() {
        return false;
    }
    let hay = format!(
        "{}\n{}\n{}",
        item.title,
        item.summary,
        item.products.join("\n")
    )
    .to_lowercase();
    words.iter().any(|k| contains_word(&hay, &k.to_lowercase()))
}

/// Packages installed on this machine and the policy for already-patched ones.
pub struct InstalledMatch<'a> {
    pub installed: &'a Installed,
    pub already_fixed: AlreadyFixed,
}

/// Whether metapackage `linux-image-<meta>` installs kernels of `flavour`:
/// `generic`, `generic-hwe-22.04`, and `virtual` / `virtual-hwe-22.04` for `generic`.
fn meta_installs_flavour(meta: &str, flavour: &str) -> bool {
    let base = meta.split_once("-hwe-").map_or(meta, |(b, _)| b);
    base == flavour || (flavour == "generic" && base == "virtual")
}

/// A USN that fixes the running kernel's flavour and series while the running kernel
/// is older than the fix. None when the running kernel is not a dpkg-installed Ubuntu
/// kernel, the item has no `linux-image-*` entry for it, or the running kernel is fixed.
fn running_kernel_decision(item: &Item, installed: &Installed) -> Option<Decision> {
    let (upstream, _, flavour) = split_kernel_release(installed.kernel.as_deref()?)?;
    let running = installed.kernel_version()?;
    let series = format!("{upstream}-");
    let fixed = item
        .fixed
        .iter()
        .filter_map(|(pkg, ver)| {
            let rest = pkg.strip_prefix("linux-image-")?;
            let rest = rest.strip_prefix("unsigned-").unwrap_or(rest);
            if let Some((u, _, f)) = split_kernel_release(rest) {
                (u == upstream && f == flavour && ver.starts_with(&series)).then(|| ver.clone())
            } else if !meta_installs_flavour(rest, flavour) {
                None
            } else if ver.starts_with(&series) {
                Some(ver.clone())
            } else {
                // Metapackage: "6.8.0.147.147" stands for kernel "6.8.0-147.147".
                let (abi, upload) = ver.strip_prefix(&format!("{upstream}."))?.split_once('.')?;
                Some(format!("{upstream}-{abi}.{upload}"))
            }
        })
        .max_by(|a, b| cmp_deb_version(a, b))?;
    if cmp_deb_version(running, &fixed) != Ordering::Less {
        return None;
    }
    // Rebooting only helps when a fixed kernel image is installed.
    let newest = installed.newest_kernel_image(upstream, flavour);
    Some(match newest {
        Some(v) if cmp_deb_version(v, &fixed) != Ordering::Less => Decision::new(
            Level::Urgent,
            format!("インストール済み・再起動待ち: 実行中 {running} → {fixed}"),
        ),
        _ => Decision::new(
            Level::Urgent,
            format!("インストール済み・未適用: カーネル {running} → {fixed}"),
        ),
    })
}

/// Decide based on installed packages for items that carry fixed versions (USN).
/// Returns None when the item has no distro package information.
fn evaluate_installed(item: &Item, im: &InstalledMatch) -> Option<Decision> {
    if item.fixed.is_empty() {
        return None;
    }
    let mut vulnerable = Vec::new();
    let mut patched = Vec::new();
    for (pkg, fixed) in &item.fixed {
        if let Some(v) = im.installed.version(pkg) {
            if cmp_deb_version(v, fixed) == Ordering::Less {
                vulnerable.push(format!("{pkg} {v} → {fixed}"));
            } else {
                patched.push(format!("{pkg} {v}"));
            }
        }
    }
    let list = |v: &[String]| {
        let mut s = v.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
        if v.len() > 3 {
            s.push_str(&format!(" 他{}件", v.len() - 3));
        }
        s
    };
    Some(if !vulnerable.is_empty() {
        Decision::new(
            Level::Urgent,
            format!("インストール済み・未適用: {}", list(&vulnerable)),
        )
    } else if !patched.is_empty() {
        // A kernel fix only takes effect after a reboot.
        if let Some(d) = running_kernel_decision(item, im.installed) {
            return Some(d);
        }
        match im.already_fixed {
            AlreadyFixed::Digest => Decision::new(
                Level::Digest,
                format!("インストール済み・適用済み: {}", list(&patched)),
            ),
            AlreadyFixed::Ignore => Decision::new(Level::Ignore, "適用済み"),
        }
    } else {
        Decision::new(Level::Ignore, "このサーバーには未インストール")
    })
}

/// Advisories from the scheduled Claude research: urgent unless their severity is low or
/// the only match is a digest-only watch entry. An unverified one is never urgent, even
/// from a source with `mode = "urgent"`.
fn evaluate_advisory(
    item: &Item,
    confidence: Confidence,
    mode: SourceMode,
    watches: &[Watch],
    installed: Option<&InstalledMatch>,
) -> Decision {
    let m = match_watch(item, watches);
    let d = advisory_decision(item, confidence, m.as_ref(), installed);
    let level = match mode {
        SourceMode::Urgent => Level::Urgent,
        SourceMode::Digest => d.level.min(Level::Digest),
        SourceMode::Filter => d.level,
    };
    let level = if confidence == Confidence::Unverified {
        level.min(Level::Digest)
    } else {
        level
    };
    Decision::new(level, d.reason)
}

fn advisory_decision(
    item: &Item,
    confidence: Confidence,
    m: Option<&WatchMatch>,
    installed: Option<&InstalledMatch>,
) -> Decision {
    let tag = format!("Claude 調査（{}）", confidence.label());
    // Distro packages count only when one of them is installed here; the advisory may
    // equally be about desktop apps that dpkg does not know. A patched package only
    // explains the reason: the advisory's other products may still need updating.
    let installed = installed
        .filter(|im| {
            item.fixed
                .iter()
                .any(|(pkg, _)| im.installed.version(pkg).is_some())
        })
        .and_then(|im| evaluate_installed(item, im));
    if let Some(d) = installed.as_ref().filter(|d| d.level == Level::Urgent) {
        return Decision::new(Level::Urgent, format!("{tag} {}", d.reason));
    }
    let reason = match (m, &installed) {
        (Some(m), _) => format!("{tag} ウォッチ: {}（{}）", m.watch.name, m.evidence),
        (None, Some(d)) => format!("{tag} {}", d.reason),
        (None, None) => format!("{tag} 横断勧告"),
    };
    // Advisories are few and every one is merged by hand, so they are urgent unless
    // they are minor or match a watch entry that only goes to the digest.
    let level = if item.severity.as_deref() == Some("low") || m.is_some_and(|m| !m.watch.urgent) {
        Level::Digest
    } else {
        Level::Urgent
    };
    Decision::new(level, reason)
}

#[cfg(test)]
pub fn evaluate(item: &Item, mode: SourceMode, rules: &Rules, watches: &[Watch]) -> Decision {
    evaluate_with(item, mode, rules, watches, None)
}

pub fn evaluate_with(
    item: &Item,
    mode: SourceMode,
    rules: &Rules,
    watches: &[Watch],
    installed: Option<&InstalledMatch>,
) -> Decision {
    if let Some(confidence) = item.confidence {
        return evaluate_advisory(item, confidence, mode, watches, installed);
    }
    let m = match_watch(item, watches);
    let watch_note = m
        .as_ref()
        .map(|m| format!(" / ウォッチ: {}（{}）", m.watch.name, m.evidence))
        .unwrap_or_default();

    match mode {
        SourceMode::Urgent => {
            return Decision::new(Level::Urgent, format!("ソース設定: 常に即時{watch_note}"))
        }
        SourceMode::Digest => {
            return Decision::new(
                Level::Digest,
                format!("ソース設定: ダイジェスト{watch_note}"),
            )
        }
        SourceMode::Filter => {}
    }

    if item.kev && rules.kev_urgent {
        return Decision::new(
            Level::Urgent,
            format!("CISA KEV（悪用確認済み）{watch_note}"),
        );
    }

    // Distro notices are about patches for this machine: decided by what is installed.
    if let Some(d) = installed.and_then(|im| evaluate_installed(item, im)) {
        return d;
    }

    if let Some(m) = &m {
        let label = format!("ウォッチ: {}（{}）", m.watch.name, m.evidence);
        if !m.strong {
            return Decision::new(Level::Digest, format!("{label} ※要確認"));
        }
        if !m.watch.urgent {
            return Decision::new(Level::Digest, label);
        }
        return match item.cvss {
            Some(c) if c < rules.watch_urgent_cvss => {
                Decision::new(Level::Digest, format!("{label} CVSS {}", fmt_cvss(c)))
            }
            _ => Decision::new(Level::Urgent, label),
        };
    }

    if contains_any(item, &rules.exclude_keywords) {
        return Decision::new(Level::Ignore, "除外キーワード");
    }

    if let (Some(t), Some(c)) = (enabled(rules.urgent_cvss), item.cvss) {
        if c >= t {
            return Decision::new(
                Level::Urgent,
                format!("{SCORE_ONLY_PREFIX}{} ≥ {}", fmt_cvss(c), fmt_cvss(t)),
            );
        }
    }
    if let (Some(t), Some(c)) = (enabled(rules.digest_cvss), item.cvss) {
        if c >= t {
            return Decision::new(
                Level::Digest,
                format!("{SCORE_ONLY_PREFIX}{} ≥ {}", fmt_cvss(c), fmt_cvss(t)),
            );
        }
    }
    Decision::new(Level::Ignore, "該当ルールなし")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watches() -> Vec<Watch> {
        vec![
            Watch {
                name: "nginx".into(),
                keywords: vec![],
                packages: vec![],
                sources: vec![],
                urgent: true,
            },
            Watch {
                name: "OkHttp".into(),
                keywords: vec!["okhttp".into()],
                packages: vec!["com.squareup.okhttp3:okhttp".into()],
                sources: vec![],
                urgent: true,
            },
        ]
    }

    fn item(title: &str, cvss: Option<f32>) -> Item {
        let mut i = Item::new("test", "X-1");
        i.title = title.into();
        i.cvss = cvss;
        i
    }

    #[test]
    fn kev_is_urgent() {
        let mut i = item("Something in Foo", Some(5.0));
        i.kev = true;
        let d = evaluate(&i, SourceMode::Filter, &Rules::default(), &watches());
        assert_eq!(d.level, Level::Urgent);
    }

    #[test]
    fn title_match_is_strong() {
        let d = evaluate(
            &item("nginx: buffer overflow in resolver", Some(8.1)),
            SourceMode::Filter,
            &Rules::default(),
            &watches(),
        );
        assert_eq!(d.level, Level::Urgent);
        assert!(d.reason.contains("タイトル: nginx"), "{}", d.reason);
    }

    #[test]
    fn product_match_is_strong() {
        let mut i = item("Heap overflow in resolver", None);
        i.products = vec!["F5 NGINX Open Source".into()];
        let d = evaluate(&i, SourceMode::Filter, &Rules::default(), &watches());
        assert_eq!(d.level, Level::Urgent);
        assert!(d.reason.contains("製品: nginx"));
    }

    #[test]
    fn description_only_match_is_weak() {
        let mut i = item("Path traversal in FooServer", Some(9.8));
        i.summary = "Similar to an issue previously found in nginx.".into();
        let d = evaluate(&i, SourceMode::Filter, &Rules::default(), &watches());
        assert_eq!(d.level, Level::Digest);
        assert!(d.reason.contains("本文のみ"));
    }

    #[test]
    fn strong_match_wins_over_earlier_weak_match() {
        let mut i = item("okhttp: header injection", Some(8.0));
        i.summary = "Reverse proxies such as nginx are not affected.".into();
        let d = evaluate(&i, SourceMode::Filter, &Rules::default(), &watches());
        assert_eq!(d.level, Level::Urgent);
        assert!(d.reason.contains("OkHttp"));
    }

    fn chrome_and_electron() -> Vec<Watch> {
        vec![
            Watch {
                name: "Chrome".into(),
                keywords: vec!["chromium".into()],
                packages: vec![],
                sources: vec![],
                urgent: false,
            },
            Watch {
                name: "Electron".into(),
                keywords: vec![],
                packages: vec!["electron".into()],
                sources: vec![],
                urgent: true,
            },
        ]
    }

    #[test]
    fn urgent_watch_wins_over_earlier_digest_only_watch() {
        let mut i = item("Heap buffer overflow in Chromium", Some(8.8));
        i.source = "ghsa".into();
        i.packages = vec!["electron".into()];
        let both = chrome_and_electron();
        for w in [both.clone(), both.into_iter().rev().collect()] {
            let d = evaluate(&i, SourceMode::Filter, &Rules::default(), &w);
            assert_eq!(d.level, Level::Urgent);
            assert_eq!(d.reason, "ウォッチ: Electron（パッケージ: electron）");
        }
    }

    #[test]
    fn digest_only_strong_match_wins_over_earlier_weak_match() {
        let mut w = chrome_and_electron();
        w[1].packages = vec![];
        w[1].keywords = vec!["electron".into()];
        let mut i = item("Heap buffer overflow in Chromium", Some(8.8));
        i.summary = "Electron apps bundle the affected code.".into();
        for w in [w.clone(), w.into_iter().rev().collect()] {
            let d = evaluate(&i, SourceMode::Filter, &Rules::default(), &w);
            assert_eq!(d.level, Level::Digest);
            assert_eq!(d.reason, "ウォッチ: Chrome（タイトル: chromium）");
        }
    }

    #[test]
    fn urgent_watch_below_watch_urgent_cvss_still_goes_to_digest() {
        let mut i = item("Heap buffer overflow in Chromium", Some(5.0));
        i.packages = vec!["electron".into()];
        let d = evaluate(
            &i,
            SourceMode::Filter,
            &Rules::default(),
            &chrome_and_electron(),
        );
        assert_eq!(d.level, Level::Digest);
        assert!(d.reason.starts_with("ウォッチ: Electron"), "{}", d.reason);
    }

    #[test]
    fn watch_match_with_unknown_cvss_is_urgent() {
        let d = evaluate(
            &item("USN-9000-1: nginx vulnerabilities", None),
            SourceMode::Filter,
            &Rules::default(),
            &watches(),
        );
        assert_eq!(d.level, Level::Urgent);
    }

    #[test]
    fn low_watch_match_goes_to_digest() {
        let d = evaluate(
            &item("nginx: minor info leak", Some(3.1)),
            SourceMode::Filter,
            &Rules::default(),
            &watches(),
        );
        assert_eq!(d.level, Level::Digest);
    }

    #[test]
    fn watch_match_by_package() {
        let mut i = item("Header injection", Some(9.0));
        i.packages = vec!["com.squareup.okhttp3:okhttp".into()];
        let d = evaluate(&i, SourceMode::Filter, &Rules::default(), &watches());
        assert_eq!(d.level, Level::Urgent);
        assert!(d.reason.contains("パッケージ"));
    }

    #[test]
    fn cvss_thresholds() {
        let rules = Rules::default();
        let w = watches();
        assert_eq!(
            evaluate(
                &item("Router RCE", Some(9.8)),
                SourceMode::Filter,
                &rules,
                &w
            )
            .level,
            Level::Digest
        );
        assert_eq!(
            evaluate(
                &item("Router RCE", Some(8.0)),
                SourceMode::Filter,
                &rules,
                &w
            )
            .level,
            Level::Ignore
        );
        let rules = Rules {
            urgent_cvss: Some(9.5),
            ..Rules::default()
        };
        assert_eq!(
            evaluate(
                &item("Router RCE", Some(9.8)),
                SourceMode::Filter,
                &rules,
                &w
            )
            .level,
            Level::Urgent
        );
        let rules = Rules {
            digest_cvss: Some(0.0),
            ..Rules::default()
        };
        assert_eq!(
            evaluate(
                &item("Router RCE", Some(9.8)),
                SourceMode::Filter,
                &rules,
                &w
            )
            .level,
            Level::Ignore
        );
    }

    #[test]
    fn exclude_keywords() {
        let rules = Rules {
            exclude_keywords: vec!["WordPress".into()],
            ..Rules::default()
        };
        let d = evaluate(
            &item("The Foo plugin for WordPress is vulnerable", Some(9.8)),
            SourceMode::Filter,
            &rules,
            &watches(),
        );
        assert_eq!(d.level, Level::Ignore);
    }

    #[test]
    fn watch_restricted_to_sources() {
        let w = vec![Watch {
            name: "Linux kernel".into(),
            keywords: vec!["linux kernel".into()],
            packages: vec![],
            sources: vec!["ubuntu-usn".into()],
            urgent: true,
        }];
        let mut i = item("USN-1-1: Linux kernel vulnerabilities", None);
        i.source = "ubuntu-usn".into();
        assert_eq!(
            evaluate(&i, SourceMode::Filter, &Rules::default(), &w).level,
            Level::Urgent
        );
        i.source = "cvelist".into();
        assert_eq!(
            evaluate(&i, SourceMode::Filter, &Rules::default(), &w).level,
            Level::Ignore
        );
    }

    fn advisory_item(severity: &str, confidence: Confidence) -> Item {
        let mut i = item("Electron apps must be updated", None);
        i.source = "claude-advisories".into();
        i.severity = Some(severity.into());
        i.confidence = Some(confidence);
        i.products = vec!["Electron".into(), "ca-certificates".into()];
        i.fixed = vec![("ca-certificates".into(), "20260101".into())];
        i
    }

    fn electron_watch() -> Vec<Watch> {
        vec![Watch {
            name: "Electron".into(),
            keywords: vec![],
            packages: vec![],
            sources: vec![],
            urgent: true,
        }]
    }

    #[test]
    fn advisory_is_urgent_by_default() {
        let r = Rules::default();
        let d = evaluate(
            &advisory_item("medium", Confidence::Confirmed),
            SourceMode::Filter,
            &r,
            &[],
        );
        assert_eq!(d.level, Level::Urgent);
        assert_eq!(d.reason, "Claude 調査（一次情報で確認済み） 横断勧告");
        let d = evaluate(
            &advisory_item("high", Confidence::Likely),
            SourceMode::Filter,
            &r,
            &electron_watch(),
        );
        assert_eq!(d.level, Level::Urgent);
        assert!(d.reason.contains("ウォッチ: Electron"));
    }

    #[test]
    fn advisory_goes_to_digest_when_minor_unverified_or_digest_watch() {
        let r = Rules::default();
        let mut digest_watch = electron_watch();
        digest_watch[0].urgent = false;
        for (i, w) in [
            (advisory_item("low", Confidence::Confirmed), vec![]),
            (advisory_item("critical", Confidence::Unverified), vec![]),
            (
                advisory_item("critical", Confidence::Confirmed),
                digest_watch,
            ),
        ] {
            assert_eq!(
                evaluate(&i, SourceMode::Filter, &r, &w).level,
                Level::Digest
            );
        }
    }

    #[test]
    fn advisory_urgent_watch_wins_over_digest_only_watch() {
        let mut both = electron_watch();
        both.push(Watch {
            name: "CA bundles".into(),
            keywords: vec!["ca-certificates".into()],
            packages: vec![],
            sources: vec![],
            urgent: false,
        });
        let i = advisory_item("high", Confidence::Confirmed);
        let r = Rules::default();
        for w in [both.clone(), both.into_iter().rev().collect()] {
            let d = evaluate(&i, SourceMode::Filter, &r, &w);
            assert_eq!(d.level, Level::Urgent);
            assert!(d.reason.contains("ウォッチ: Electron"));
        }
    }

    #[test]
    fn advisory_with_outdated_installed_package() {
        let inst = Installed::from_pairs("noble", &[("ca-certificates", "20240203")]);
        let im = InstalledMatch {
            installed: &inst,
            already_fixed: AlreadyFixed::Digest,
        };
        let r = Rules::default();
        let d = evaluate_with(
            &advisory_item("low", Confidence::Confirmed),
            SourceMode::Filter,
            &r,
            &[],
            Some(&im),
        );
        assert_eq!(d.level, Level::Urgent);
        assert!(d.reason.contains("ca-certificates 20240203 → 20260101"));
        let d = evaluate_with(
            &advisory_item("low", Confidence::Unverified),
            SourceMode::Filter,
            &r,
            &[],
            Some(&im),
        );
        assert_eq!(d.level, Level::Digest);
        // Not installed here: the dpkg entry does not make it "not applicable".
        let none = Installed::from_pairs("noble", &[]);
        let im = InstalledMatch {
            installed: &none,
            already_fixed: AlreadyFixed::Digest,
        };
        let d = evaluate_with(
            &advisory_item("low", Confidence::Confirmed),
            SourceMode::Filter,
            &r,
            &[],
            Some(&im),
        );
        assert_eq!(d.level, Level::Digest);
    }

    #[test]
    fn advisory_with_patched_package_stays_urgent() {
        let inst = Installed::from_pairs("noble", &[("ca-certificates", "20260101")]);
        let im = InstalledMatch {
            installed: &inst,
            already_fixed: AlreadyFixed::Ignore,
        };
        let i = advisory_item("high", Confidence::Confirmed);
        let r = Rules::default();
        let d = evaluate_with(&i, SourceMode::Filter, &r, &electron_watch(), Some(&im));
        assert_eq!(d.level, Level::Urgent);
        let d = evaluate_with(&i, SourceMode::Filter, &r, &[], Some(&im));
        assert_eq!(d.level, Level::Urgent);
        assert!(d.reason.contains("適用済み"));
    }

    #[test]
    fn advisory_source_mode_keeps_safeguard() {
        let r = Rules::default();
        let unverified = advisory_item("critical", Confidence::Unverified);
        let d = evaluate(&unverified, SourceMode::Urgent, &r, &[]);
        assert_eq!(d.level, Level::Digest);
        assert!(d.reason.starts_with("Claude 調査（未検証）"));
        let confirmed = advisory_item("low", Confidence::Confirmed);
        assert_eq!(
            evaluate(&confirmed, SourceMode::Urgent, &r, &[]).level,
            Level::Urgent
        );
        let severe = advisory_item("critical", Confidence::Confirmed);
        assert_eq!(
            evaluate(&severe, SourceMode::Digest, &r, &electron_watch()).level,
            Level::Digest
        );
    }

    fn usn_item() -> Item {
        let mut i = item("USN-8954-1: zlib vulnerability", None);
        i.source = "ubuntu-usn".into();
        i.fixed = vec![
            ("zlib1g".into(), "1:1.3.dfsg-3.1ubuntu2.3".into()),
            ("zlib1g-dev".into(), "1:1.3.dfsg-3.1ubuntu2.3".into()),
        ];
        i
    }

    #[test]
    fn installed_and_outdated_is_urgent() {
        let inst = Installed::from_pairs("noble", &[("zlib1g", "1:1.3.dfsg-3.1ubuntu2.2")]);
        let im = InstalledMatch {
            installed: &inst,
            already_fixed: AlreadyFixed::Digest,
        };
        let d = evaluate_with(
            &usn_item(),
            SourceMode::Filter,
            &Rules::default(),
            &[],
            Some(&im),
        );
        assert_eq!(d.level, Level::Urgent);
        assert!(d
            .reason
            .contains("zlib1g 1:1.3.dfsg-3.1ubuntu2.2 → 1:1.3.dfsg-3.1ubuntu2.3"));
    }

    #[test]
    fn installed_and_patched_follows_policy() {
        let inst = Installed::from_pairs("noble", &[("zlib1g", "1:1.3.dfsg-3.1ubuntu2.3")]);
        let mut im = InstalledMatch {
            installed: &inst,
            already_fixed: AlreadyFixed::Digest,
        };
        let r = Rules::default();
        assert_eq!(
            evaluate_with(&usn_item(), SourceMode::Filter, &r, &[], Some(&im)).level,
            Level::Digest
        );
        im.already_fixed = AlreadyFixed::Ignore;
        assert_eq!(
            evaluate_with(&usn_item(), SourceMode::Filter, &r, &[], Some(&im)).level,
            Level::Ignore
        );
    }

    #[test]
    fn not_installed_is_ignored_even_if_watched() {
        let inst = Installed::from_pairs("noble", &[("nginx", "1.24.0-2ubuntu7.5")]);
        let im = InstalledMatch {
            installed: &inst,
            already_fixed: AlreadyFixed::Digest,
        };
        let w = vec![Watch {
            name: "zlib".into(),
            keywords: vec![],
            packages: vec![],
            sources: vec![],
            urgent: true,
        }];
        let d = evaluate_with(
            &usn_item(),
            SourceMode::Filter,
            &Rules::default(),
            &w,
            Some(&im),
        );
        assert_eq!(d.level, Level::Ignore);
        // Without installed matching the watch list decides.
        assert_eq!(
            evaluate(&usn_item(), SourceMode::Filter, &Rules::default(), &w).level,
            Level::Urgent
        );
    }

    fn kernel_usn(flavour: &str, abi: &str, meta: &str, image: &str) -> Item {
        let mut i = item("USN-8917-1: Linux kernel vulnerabilities", None);
        i.source = "ubuntu-usn".into();
        i.fixed = vec![
            (format!("linux-image-{flavour}"), meta.into()),
            (format!("linux-image-6.8.0-{abi}-{flavour}"), image.into()),
        ];
        i
    }

    fn generic_kernel_usn() -> Item {
        kernel_usn("generic", "147", "6.8.0.147.147", "6.8.0-147.147")
    }

    fn kernel_host(running: &str, meta: &str) -> Installed {
        Installed::from_pairs(
            "noble",
            &[
                ("linux-image-generic", meta),
                ("linux-image-6.8.0-145-generic", "6.8.0-145.145"),
                ("linux-image-6.8.0-147-generic", "6.8.0-147.147"),
            ],
        )
        .with_kernel(running)
    }

    fn decide(i: &Item, inst: &Installed, already_fixed: AlreadyFixed) -> Decision {
        let im = InstalledMatch {
            installed: inst,
            already_fixed,
        };
        evaluate_with(i, SourceMode::Filter, &Rules::default(), &[], Some(&im))
    }

    #[test]
    fn kernel_installed_but_not_running_is_urgent() {
        let inst = kernel_host("6.8.0-145-generic", "6.8.0.147.147");
        for af in [AlreadyFixed::Digest, AlreadyFixed::Ignore] {
            let d = decide(&generic_kernel_usn(), &inst, af);
            assert_eq!(d.level, Level::Urgent);
            assert!(d.reason.contains("再起動待ち"), "{}", d.reason);
            assert!(
                d.reason.contains("6.8.0-145.145 → 6.8.0-147.147"),
                "{}",
                d.reason
            );
        }
        // Only the metapackage listed: its version is mapped to the kernel's format.
        let mut i = generic_kernel_usn();
        i.fixed.truncate(1);
        let d = decide(&i, &inst, AlreadyFixed::Digest);
        assert_eq!(d.level, Level::Urgent);
        assert!(d.reason.contains("6.8.0-145.145 → 6.8.0-147.147"));
        // Metapackage listed in the kernel's own version format.
        i.fixed[0].1 = "6.8.0-147.147".into();
        let d = decide(&i, &inst, AlreadyFixed::Digest);
        assert_eq!(d.level, Level::Urgent);
        assert!(d.reason.contains("6.8.0-145.145 → 6.8.0-147.147"));
    }

    #[test]
    fn kernel_fix_without_new_image_is_not_reboot_pending() {
        // Only a non-image package of the USN is patched; the fixed image is missing.
        let inst = Installed::from_pairs(
            "noble",
            &[
                ("linux-libc-dev", "6.8.0-147.147"),
                ("linux-image-6.8.0-145-generic", "6.8.0-145.145"),
            ],
        )
        .with_kernel("6.8.0-145-generic");
        let mut i = generic_kernel_usn();
        i.fixed
            .push(("linux-libc-dev".into(), "6.8.0-147.147".into()));
        let d = decide(&i, &inst, AlreadyFixed::Ignore);
        assert_eq!(d.level, Level::Urgent);
        assert!(!d.reason.contains("再起動待ち"), "{}", d.reason);
        assert!(d.reason.contains("未適用"), "{}", d.reason);
        assert!(d.reason.contains("6.8.0-145.145 → 6.8.0-147.147"));
    }

    #[test]
    fn kernel_hwe_and_virtual_metapackages() {
        let host = |meta: &str| {
            Installed::from_pairs(
                "jammy",
                &[
                    (meta, "6.8.0.147.147~22.04.1"),
                    ("linux-image-6.8.0-145-generic", "6.8.0-145.145~22.04.1"),
                    ("linux-image-6.8.0-147-generic", "6.8.0-147.147~22.04.1"),
                ],
            )
            .with_kernel("6.8.0-145-generic")
        };
        for meta in [
            "linux-image-generic-hwe-22.04",
            "linux-image-virtual-hwe-22.04",
            "linux-image-virtual",
        ] {
            let mut i = generic_kernel_usn();
            i.fixed = vec![(meta.into(), "6.8.0.147.147~22.04.1".into())];
            let d = decide(&i, &host(meta), AlreadyFixed::Digest);
            assert_eq!(d.level, Level::Urgent, "{meta}: {}", d.reason);
            assert!(d.reason.contains("再起動待ち"), "{meta}: {}", d.reason);
            assert!(d.reason.contains("→ 6.8.0-147.147~22.04.1"), "{}", d.reason);
        }
        // A different flavour's HWE metapackage is not the running kernel's.
        let mut i = generic_kernel_usn();
        i.fixed = vec![(
            "linux-image-lowlatency-hwe-22.04".into(),
            "6.8.0.147.147~22.04.1".into(),
        )];
        let d = decide(
            &i,
            &host("linux-image-lowlatency-hwe-22.04"),
            AlreadyFixed::Digest,
        );
        assert_eq!(d.level, Level::Digest, "{}", d.reason);
    }

    #[test]
    fn kernel_running_fixed_follows_policy() {
        for running in ["6.8.0-147-generic", "6.8.0-150-generic"] {
            let inst = Installed::from_pairs(
                "noble",
                &[
                    ("linux-image-generic", "6.8.0.150.150"),
                    ("linux-image-6.8.0-147-generic", "6.8.0-147.147"),
                    ("linux-image-6.8.0-150-generic", "6.8.0-150.150"),
                ],
            )
            .with_kernel(running);
            let d = decide(&generic_kernel_usn(), &inst, AlreadyFixed::Digest);
            assert_eq!(d.level, Level::Digest, "{running}: {}", d.reason);
            assert!(d.reason.contains("適用済み"));
            let d = decide(&generic_kernel_usn(), &inst, AlreadyFixed::Ignore);
            assert_eq!(d.level, Level::Ignore, "{running}");
        }
    }

    #[test]
    fn kernel_not_patched_is_urgent_as_before() {
        let inst = Installed::from_pairs(
            "noble",
            &[
                ("linux-image-generic", "6.8.0.145.145"),
                ("linux-image-6.8.0-145-generic", "6.8.0-145.145"),
            ],
        )
        .with_kernel("6.8.0-145-generic");
        let d = decide(&generic_kernel_usn(), &inst, AlreadyFixed::Digest);
        assert_eq!(d.level, Level::Urgent);
        assert!(d.reason.contains("未適用"), "{}", d.reason);
    }

    #[test]
    fn kernel_usn_for_other_flavour_is_unchanged() {
        let inst = kernel_host("6.8.0-145-generic", "6.8.0.147.147");
        let azure = kernel_usn("azure", "1030", "6.8.0.1030.31", "6.8.0-1030.31");
        let d = decide(&azure, &inst, AlreadyFixed::Digest);
        assert_eq!(d.level, Level::Ignore);
        assert!(d.reason.contains("未インストール"), "{}", d.reason);
    }

    #[test]
    fn kernel_unknown_to_dpkg_keeps_patched_result() {
        // Custom kernel or container: the running kernel has no dpkg package.
        for running in ["6.9.3-custom", "6.8.0-140-generic"] {
            let inst = Installed::from_pairs("noble", &[("linux-image-generic", "6.8.0.147.147")])
                .with_kernel(running);
            let d = decide(&generic_kernel_usn(), &inst, AlreadyFixed::Digest);
            assert_eq!(d.level, Level::Digest, "{running}: {}", d.reason);
        }
        let inst = Installed::from_pairs("noble", &[("linux-image-generic", "6.8.0.147.147")]);
        let d = decide(&generic_kernel_usn(), &inst, AlreadyFixed::Digest);
        assert_eq!(d.level, Level::Digest);
    }

    #[test]
    fn source_modes() {
        let i = item("anything", None);
        let r = Rules::default();
        assert_eq!(
            evaluate(&i, SourceMode::Urgent, &r, &[]).level,
            Level::Urgent
        );
        assert_eq!(
            evaluate(&i, SourceMode::Digest, &r, &[]).level,
            Level::Digest
        );
        assert_eq!(
            evaluate(&i, SourceMode::Filter, &r, &[]).level,
            Level::Ignore
        );
    }
}
