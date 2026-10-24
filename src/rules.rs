use std::cmp::Ordering;

use crate::config::{AlreadyFixed, Rules, SourceMode, Watch};
use crate::installed::{cmp_deb_version, Installed};
use crate::model::{Decision, Item, Level};
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

/// Find the best watch match: strong matches win over description-only matches.
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

    let mut weak: Option<WatchMatch<'a>> = None;
    for w in watches.iter().filter(|w| w.applies_to(&item.source)) {
        if let Some(p) = w
            .packages
            .iter()
            .find(|p| packages.contains(&p.to_lowercase()))
        {
            return Some(WatchMatch {
                watch: w,
                strong: true,
                evidence: format!("パッケージ: {p}"),
            });
        }
        let keywords = w.effective_keywords();
        if let Some(k) = keywords.iter().find(|k| contains_word(&products, k)) {
            return Some(WatchMatch {
                watch: w,
                strong: true,
                evidence: format!("製品: {k}"),
            });
        }
        if let Some(k) = keywords.iter().find(|k| contains_word(&title, k)) {
            return Some(WatchMatch {
                watch: w,
                strong: true,
                evidence: format!("タイトル: {k}"),
            });
        }
        if weak.is_none() {
            if let Some(k) = keywords.iter().find(|k| contains_word(&summary, k)) {
                weak = Some(WatchMatch {
                    watch: w,
                    strong: false,
                    evidence: format!("本文のみ: {k}"),
                });
            }
        }
    }
    weak
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
                format!("CVSS {} ≥ {}", fmt_cvss(c), fmt_cvss(t)),
            );
        }
    }
    if let (Some(t), Some(c)) = (enabled(rules.digest_cvss), item.cvss) {
        if c >= t {
            return Decision::new(
                Level::Digest,
                format!("CVSS {} ≥ {}", fmt_cvss(c), fmt_cvss(t)),
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
