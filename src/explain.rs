//! `vuln-watch explain <CVE-ID|GHSA-ID>`: what the state database knows about one id, the
//! item as the sources serve it now, and what the current rules decide for it.
//!
//! Read-only: the database is opened with `Db::open_read_only` (never created or migrated,
//! so running as root leaves no root-owned files behind), nothing is sent and no cursor or
//! ETag is stored.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use serde_json::Value;

use crate::app::Secrets;
use crate::config::{Config, SourceConfig, SourceKind};
use crate::db::{Db, KeyRow, PendingRow, Queue, SeenRow};
use crate::http::{Http, StatusError};
use crate::installed::Installed;
use crate::model::Item;
use crate::rules::{self, InstalledMatch, SourcePolicy};
use crate::sources::{cvelist, ghsa, ignored_title_prefix, GithubAuth};
use crate::text::truncate;

pub struct Options {
    pub id: String,
    pub state_db: PathBuf,
    /// Skip the live fetch: show only the state.
    pub offline: bool,
}

/// An id `explain` accepts, normalized (`CVE-2026-1234`, `GHSA-abcd-2345-wxyz`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Id {
    Cve(String),
    Ghsa(String),
}

impl Id {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let upper = s.to_ascii_uppercase();
        if let Some(rest) = upper.strip_prefix("CVE-") {
            if let Some((year, num)) = rest.split_once('-') {
                let digits = |p: &str| p.bytes().all(|b| b.is_ascii_digit());
                if year.len() == 4 && num.len() >= 4 && digits(year) && digits(num) {
                    return Ok(Id::Cve(upper));
                }
            }
        } else if let Some(rest) = upper.strip_prefix("GHSA-") {
            let parts: Vec<&str> = rest.split('-').collect();
            if parts.len() == 3
                && parts
                    .iter()
                    .all(|p| p.len() == 4 && p.bytes().all(|b| b.is_ascii_alphanumeric()))
            {
                return Ok(Id::Ghsa(format!("GHSA-{}", rest.to_ascii_lowercase())));
            }
        }
        bail!(
            "not a CVE or GHSA id: {:?} (expected CVE-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx)",
            truncate(s, 60)
        )
    }

    pub fn as_str(&self) -> &str {
        match self {
            Id::Cve(s) | Id::Ghsa(s) => s,
        }
    }
}

/// What `state.db` holds for a set of ids (the requested one and the related ones found
/// in the live data, e.g. the GHSA ids of a CVE).
#[derive(Default)]
pub struct StateSummary {
    pub seen: Vec<SeenRow>,
    pub alerted: Vec<KeyRow>,
    pub outbox: Vec<KeyRow>,
    pub digest: Vec<KeyRow>,
    pub pending: Vec<(String, PendingRow)>,
}

pub fn state_summary(db: &Db, ids: &[String]) -> Result<StateSummary> {
    let mut s = StateSummary::default();
    for id in ids {
        s.seen.extend(db.seen_rows(id)?);
        s.alerted.extend(db.alerted_rows(id)?);
        s.outbox.extend(db.queue_rows(Queue::Outbox, id)?);
        s.digest.extend(db.queue_rows(Queue::Digest, id)?);
        s.pending.extend(db.pending_rows(id)?);
    }
    // No duplicates, whatever the ids.
    s.seen
        .sort_by(|a, b| (&a.source, &a.id).cmp(&(&b.source, &b.id)));
    s.seen.dedup_by(|a, b| a.source == b.source && a.id == b.id);
    for rows in [&mut s.alerted, &mut s.outbox, &mut s.digest] {
        rows.sort_by(|a, b| a.key.cmp(&b.key));
        rows.dedup_by(|a, b| a.key == b.key);
    }
    s.pending
        .sort_by(|a, b| (&a.0, &a.1.id).cmp(&(&b.0, &b.1.id)));
    s.pending.dedup_by(|a, b| a.0 == b.0 && a.1.id == b.1.id);
    Ok(s)
}

/// The state as text. `sources`: the configured source names, to list the ones that have
/// not seen the id.
pub fn state_lines(s: &StateSummary, sources: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for row in &s.seen {
        // The marker stays in `seen` after the item is decided with a fix.
        let note = match row.id.strip_suffix("#awaiting-remedy") {
            Some(base)
                if s.seen
                    .iter()
                    .any(|r| r.source == row.source && r.id.eq_ignore_ascii_case(base)) =>
            {
                " (was held back for lack of a fix; decided since)"
            }
            Some(_) => " (held back: no fix published yet)",
            None => "",
        };
        out.push(format!(
            "seen       {}: {} at {}{note}",
            row.source, row.id, row.first_seen
        ));
    }
    let unseen: Vec<&str> = sources
        .iter()
        .filter(|name| !s.seen.iter().any(|r| &r.source == *name))
        .map(String::as_str)
        .collect();
    if !unseen.is_empty() {
        out.push(format!("not seen   {}", unseen.join(", ")));
    }
    let keyed = |label: &str, rows: &[KeyRow], none: &str, out: &mut Vec<String>| {
        if rows.is_empty() {
            out.push(format!("{label:<10} {none}"));
        }
        for r in rows {
            out.push(format!("{label:<10} {} {} at {}", r.key, r.detail, r.at));
        }
    };
    keyed("alerted", &s.alerted, "none recorded", &mut out);
    keyed("outbox", &s.outbox, "not waiting", &mut out);
    keyed("digest", &s.digest, "not queued", &mut out);
    if s.pending.is_empty() {
        out.push(format!("{:<10} not waiting", "pending"));
    }
    for (source, row) in &s.pending {
        out.push(format!(
            "pending    {source}: {} waiting for its record, {} failed attempt(s), queued at {}",
            row.id, row.attempts, row.queued_at
        ));
    }
    out
}

/// The fields of an item that the rules use.
pub fn item_lines(item: &Item) -> Vec<String> {
    let list = |v: &[String]| {
        if v.is_empty() {
            "-".to_string()
        } else {
            truncate(&v.join(", "), 300)
        }
    };
    let mut out = vec![
        format!("title      {}", truncate(&item.title, 200)),
        format!("url        {}", item.url),
    ];
    if let Some(cve) = &item.cve {
        out.push(format!("cve        {cve}"));
    }
    out.push(format!("products   {}", list(&item.products)));
    out.push(format!("packages   {}", list(&item.packages)));
    out.push(format!(
        "cvss       {}{}",
        item.cvss
            .map(|c| format!("{c:.1}"))
            .unwrap_or_else(|| "-".into()),
        item.severity
            .as_deref()
            .map(|s| format!(" ({s})"))
            .unwrap_or_default()
    ));
    out.push(format!(
        "kev        {}",
        if item.kev { "yes" } else { "no" }
    ));
    out.push(format!(
        "remedy     {}",
        if item.remedy {
            "yes (a fix or mitigation is published)"
        } else {
            "no"
        }
    ));
    if let Some(p) = &item.published {
        out.push(format!("published  {p}"));
    }
    out
}

/// What the current rules decide for `item` as served by a source of `kind`: one line per
/// enabled source of that kind (`only`: of these names; none: the default policy, said so), with the level,
/// the reason as a message would show it, and the best watch match.
pub fn decision_lines(
    item: &Item,
    kind: SourceKind,
    only: Option<&[String]>,
    cfg: &Config,
    installed: Option<&Installed>,
) -> Vec<String> {
    let im = installed.map(|i| InstalledMatch {
        installed: i,
        already_fixed: cfg.installed.already_fixed,
    });
    let sources: Vec<&SourceConfig> = cfg
        .sources
        .iter()
        .filter(|s| s.enabled && s.kind == kind)
        .filter(|s| only.is_none_or(|names| names.contains(&s.name())))
        .collect();
    let mut out = Vec::new();
    if sources.is_empty() && only.is_some() {
        out.push(format!("no enabled `{}` source reads it", kind.as_str()));
        return out;
    }
    let sources: Vec<(String, SourcePolicy, Option<&str>)> = if sources.is_empty() {
        out.push(format!(
            "(no enabled `{}` source: decided with the default mode \"filter\")",
            kind.as_str()
        ));
        vec![(kind.as_str().to_string(), SourcePolicy::default(), None)]
    } else {
        sources
            .into_iter()
            .map(|s| {
                let policy = SourcePolicy {
                    mode: s.mode,
                    require_watch: s.require_watch,
                };
                (s.name(), policy, ignored_title_prefix(s, &item.title))
            })
            .collect()
    };
    for (name, policy, ignored_prefix) in sources {
        // Dropped by the source before the rules see it.
        if let Some(p) = ignored_prefix {
            out.push(format!(
                "[{name}] dropped by ignore_title_prefixes ({p:?}): never reaches the rules"
            ));
            continue;
        }
        // Watch entries can be limited to source names.
        let mut item = item.clone();
        item.source = name.clone();
        let d = rules::evaluate_with(&item, policy, &cfg.rules, &cfg.watches, im.as_ref());
        out.push(format!(
            "[{name}] {:<7} {}",
            format!("{:?}", d.level),
            d.reason
        ));
        if d.awaiting_remedy {
            out.push(
                "          decided again when a source brings it with a fix (require_remedy)"
                    .into(),
            );
        }
        out.push(match rules::match_watch(&item, &cfg.watches) {
            Some(m) => format!(
                "          watch: {} ({}, {}{})",
                m.watch.name,
                m.evidence,
                if m.strong {
                    "strong"
                } else {
                    "weak: description only"
                },
                if m.watch.urgent {
                    ""
                } else {
                    ", urgent = false"
                }
            ),
            None => "          no watch match".into(),
        });
    }
    out
}

/// Items fetched live, with the kind of source that serves them.
struct Found {
    label: String,
    /// Ids of the record (GHSA id, CVE), also when it yields no item (withdrawn).
    ids: Vec<String>,
    kind: SourceKind,
    /// The sources that read this record; None: every enabled source of `kind`.
    sources: Option<Vec<String>>,
    note: Option<String>,
    item: Option<Item>,
}

/// The enabled ghsa sources whose list can contain the advisory (None: no ghsa source is
/// enabled), and a line for each that cannot or whose filters were not all checked.
fn ghsa_sources(cfg: &Config, l: &ghsa::Lookup) -> (Option<Vec<String>>, Vec<String>) {
    let mut names = Vec::new();
    let mut notes = Vec::new();
    let mut any = false;
    for src in cfg
        .sources
        .iter()
        .filter(|s| s.enabled && s.kind == SourceKind::Ghsa)
    {
        any = true;
        let url = src.url.as_deref().unwrap_or(ghsa::DEFAULT_URL);
        let name = src.name();
        match ghsa::list_eligibility(url, l.kind.as_deref(), &l.ecosystems) {
            ghsa::Eligibility::Yes => names.push(name),
            ghsa::Eligibility::No(why) => {
                notes.push(format!("not read by source `{name}` ({why})"));
            }
            ghsa::Eligibility::Unchecked(params) => {
                notes.push(format!(
                    "source `{name}`: filter {} not checked; its decision assumes it reads this advisory",
                    params.join(", ")
                ));
                names.push(name);
            }
        }
    }
    (any.then_some(names), notes)
}

fn is_not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<StatusError>()
        .is_some_and(|s| s.status == 404)
}

const GITHUB_HEADERS: [(&str, &str); 2] = [
    ("Accept", "application/vnd.github+json"),
    ("X-GitHub-Api-Version", "2022-11-28"),
];

fn github_get(http: &Http, token: Option<&str>, url: &str) -> Result<String> {
    let base: Vec<(&'static str, String)> = GITHUB_HEADERS
        .iter()
        .map(|(k, v)| (*k, v.to_string()))
        .collect();
    let headers = GithubAuth::new("explain", token).headers(url, &base);
    Ok(http.get(url, &headers, None)?.body)
}

/// Fetch the item(s) for `id`. Lines describing failures go to `out`; nothing fails the
/// command, so the state is still shown.
fn fetch_live(
    id: &Id,
    cfg: &Config,
    http: &Http,
    token: Option<&str>,
    ghsa_api: &str,
    out: &mut Vec<String>,
) -> Vec<Found> {
    let mut found = Vec::new();
    let ghsa_from =
        |out: &mut Vec<String>, label: &str, url: &str, found: &mut Vec<Found>| match github_get(
            http, token, url,
        )
        .and_then(|b| ghsa::parse_lookup("ghsa", &b))
        {
            Ok(list) if list.is_empty() => {
                out.push(format!("{label}: no GitHub advisory"));
            }
            Ok(list) => {
                for l in list {
                    let (sources, mut notes) = ghsa_sources(cfg, &l);
                    if l.item.is_none() {
                        notes.insert(0, "withdrawn: no source reports it".to_string());
                    }
                    let note = (!notes.is_empty()).then(|| notes.join("\n"));
                    found.push(Found {
                        label: format!("GitHub advisory {}", l.ghsa_id),
                        ids: [Some(l.ghsa_id.clone()), l.cve_id.clone()]
                            .into_iter()
                            .flatten()
                            .collect(),
                        kind: SourceKind::Ghsa,
                        sources,
                        note,
                        item: l.item,
                    });
                }
            }
            Err(e) if is_not_found(&e) => out.push(format!("{label}: not found at the source")),
            Err(e) => out.push(format!("{label}: fetch failed: {e:#}")),
        };
    match id {
        Id::Cve(cve) => {
            // One fetch per record URL: sources with different `url`s may serve different
            // versions, and each is decided with the record it reads.
            let mut by_url: Vec<(String, Option<Vec<String>>)> = Vec::new();
            for src in cfg
                .sources
                .iter()
                .filter(|s| s.enabled && s.kind == SourceKind::Cvelist)
            {
                let url = cvelist::lookup_url(src.url.as_deref(), cve);
                match by_url.iter_mut().find(|(u, _)| *u == url) {
                    Some((_, Some(names))) => names.push(src.name()),
                    _ => by_url.push((url, Some(vec![src.name()]))),
                }
            }
            if by_url.is_empty() {
                by_url.push((cvelist::lookup_url(None, cve), None));
            }
            for (url, sources) in by_url {
                let label = match &sources {
                    Some(names) => format!("CVE record {url} ({})", names.join(", ")),
                    None => format!("CVE record {url}"),
                };
                let record = http
                    .get(&url, &[], None)
                    .and_then(|r| Ok(serde_json::from_str::<Value>(&r.body)?));
                match record {
                    Ok(v) => {
                        let item = cvelist::parse_record("cvelist", &v);
                        found.push(Found {
                            label,
                            ids: vec![cve.clone()],
                            kind: SourceKind::Cvelist,
                            sources,
                            note: item.is_none().then(|| {
                                "rejected (or no cveId): no source reports it".to_string()
                            }),
                            item,
                        });
                    }
                    Err(e) if is_not_found(&e) => {
                        out.push(format!("{label}: not found at the source"))
                    }
                    Err(e) => out.push(format!("{label}: fetch failed: {e:#}")),
                }
            }
            // The API returns reviewed advisories unless `type` says otherwise: ask for each
            // type the enabled ghsa sources read.
            let mut types: Vec<String> = Vec::new();
            for src in cfg
                .sources
                .iter()
                .filter(|s| s.enabled && s.kind == SourceKind::Ghsa)
            {
                let t = ghsa::list_type(src.url.as_deref().unwrap_or(ghsa::DEFAULT_URL));
                if !types.contains(&t) {
                    types.push(t);
                }
            }
            if types.is_empty() {
                types.push("reviewed".to_string());
            }
            for t in types {
                // One page of 100 (the API maximum): far more than one CVE has.
                let url = reqwest::Url::parse_with_params(
                    ghsa_api,
                    [("cve_id", cve.as_str()), ("per_page", "100"), ("type", &t)],
                )
                .map(String::from)
                .unwrap_or_else(|_| format!("{ghsa_api}?cve_id={cve}&per_page=100&type={t}"));
                ghsa_from(
                    out,
                    &format!("GitHub {t} advisories for {cve}"),
                    &url,
                    &mut found,
                );
            }
        }
        Id::Ghsa(g) => {
            let url = format!("{ghsa_api}/{g}");
            ghsa_from(out, &format!("GitHub advisory {g}"), &url, &mut found);
        }
    }
    found
}

pub fn run(cfg: &Config, http: &Http, secrets: &Secrets, opts: &Options) -> Result<()> {
    let id = Id::parse(&opts.id)?;
    println!("explain {}\n", id.as_str());

    let mut fetch_notes = Vec::new();
    let found = if opts.offline {
        Vec::new()
    } else {
        fetch_live(
            &id,
            cfg,
            http,
            secrets.github_token.as_deref(),
            ghsa::API_URL,
            &mut fetch_notes,
        )
    };

    // Related ids: the GHSA ids of a CVE, the CVE of a GHSA id.
    let mut ids = vec![id.as_str().to_string()];
    for related in found.iter().flat_map(|f| &f.ids) {
        if !ids.iter().any(|i| i.eq_ignore_ascii_case(related)) {
            ids.push(related.clone());
        }
    }

    println!("== State ({})", opts.state_db.display());
    if ids.len() > 1 {
        println!("(also looked up: {})", ids[1..].join(", "));
    }
    for line in state_part(&opts.state_db, &ids, cfg) {
        println!("{line}");
    }

    if opts.offline {
        println!("\n(--offline: current data and decision skipped)");
        return Ok(());
    }

    println!("\n== Current data");
    for line in &fetch_notes {
        println!("{line}");
    }
    for f in &found {
        println!("-- {}", f.label);
        if let Some(note) = &f.note {
            println!("{note}");
        }
        if let Some(item) = &f.item {
            for line in item_lines(item) {
                println!("{line}");
            }
        }
    }

    println!("\n== Decision with the current config");
    let installed = if cfg.installed.enabled {
        match Installed::load(&cfg.installed) {
            Ok(i) => Some(i),
            Err(e) => {
                println!("([installed] not applied: {e:#})");
                None
            }
        }
    } else {
        None
    };
    let mut any = false;
    for f in &found {
        let Some(item) = &f.item else { continue };
        any = true;
        println!("-- {}", f.label);
        for line in decision_lines(item, f.kind, f.sources.as_deref(), cfg, installed.as_ref()) {
            println!("{line}");
        }
    }
    if !any {
        println!("nothing to decide: no current data for this id");
    }
    Ok(())
}

fn state_part(path: &Path, ids: &[String], cfg: &Config) -> Vec<String> {
    match std::fs::metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return vec![format!(
                "{} not found (no successful run yet, or a different --state-dir)",
                path.display()
            )];
        }
        Err(e) => {
            let hint = if crate::doctor::is_root() {
                ""
            } else {
                " (the state needs root: sudo vuln-watch explain ...)"
            };
            return vec![format!("{}: {e}{hint}", path.display())];
        }
    }
    let summary = Db::open_read_only(path).and_then(|db| state_summary(&db, ids));
    match summary {
        Ok(s) => {
            let names: Vec<String> = cfg.sources.iter().map(|s| s.name()).collect();
            state_lines(&s, &names)
        }
        Err(e) => {
            let hint = if crate::doctor::is_root() {
                ""
            } else {
                " (the state needs root: sudo vuln-watch explain ...)"
            };
            vec![format!("reading {} failed: {e:#}{hint}", path.display())]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Watch;
    use crate::model::Level;

    #[test]
    fn parses_ids() {
        assert_eq!(
            Id::parse(" cve-2026-12345 ").unwrap(),
            Id::Cve("CVE-2026-12345".into())
        );
        assert_eq!(
            Id::parse("ghsa-ABCD-2345-wxyz").unwrap(),
            Id::Ghsa("GHSA-abcd-2345-wxyz".into())
        );
        for bad in [
            "",
            "CVE-2026-123",
            "CVE-26-12345",
            "CVE-2026-1234a",
            "CVE-2026-é1234",
            "GHSA-abcd-2345",
            "GHSA-abcd-2345-wxyz-1",
            "GHSA-abc!-2345-wxyz",
            "USN-1234-1",
            "../etc/passwd",
        ] {
            assert!(Id::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn state_summary_finds_every_table() {
        let db = Db::open_in_memory().unwrap();
        let cve = "CVE-2026-1111";
        db.mark_seen("cvelist", cve).unwrap();
        db.mark_seen("ghsa", "GHSA-aaaa-bbbb-cccc#awaiting-remedy")
            .unwrap();
        db.mark_seen("kev", "CVE-2026-11112").unwrap();
        db.set_alerted(cve, Level::Urgent).unwrap();
        db.set_alerted(&format!("{cve}#kev"), Level::Urgent)
            .unwrap();
        db.set_alerted("CVE-2026-11110", Level::Digest).unwrap();
        let mut item = Item::new("kev", cve);
        item.cve = Some(cve.into());
        db.enqueue(Queue::Outbox, &format!("{cve}#kev"), &item, "CISA KEV")
            .unwrap();
        db.enqueue(Queue::Digest, &format!("cvelist:{cve}"), &item, "r")
            .unwrap();
        db.add_pending("cvelist", cve, "https://example/x.json")
            .unwrap();
        db.bump_pending_attempt("cvelist", cve).unwrap();

        let ids = vec![cve.to_string(), "GHSA-aaaa-bbbb-cccc".to_string()];
        let s = state_summary(&db, &ids).unwrap();
        let seen: Vec<_> = s.seen.iter().map(|r| (&*r.source, &*r.id)).collect();
        assert_eq!(
            seen,
            vec![
                ("cvelist", cve),
                ("ghsa", "GHSA-aaaa-bbbb-cccc#awaiting-remedy")
            ]
        );
        let alerted: Vec<_> = s.alerted.iter().map(|r| (&*r.key, &*r.detail)).collect();
        assert_eq!(
            alerted,
            vec![(cve, "Urgent"), ("CVE-2026-1111#kev", "Urgent")]
        );
        assert_eq!(s.outbox.len(), 1);
        assert_eq!(s.outbox[0].detail, "CISA KEV");
        assert_eq!(s.digest.len(), 1);
        assert_eq!(s.digest[0].key, "cvelist:CVE-2026-1111");
        assert_eq!(s.pending.len(), 1);
        assert_eq!(s.pending[0].0, "cvelist");
        assert_eq!(s.pending[0].1.attempts, 1);

        let text = state_lines(&s, &["kev".into(), "cvelist".into(), "ghsa".into()]).join("\n");
        assert!(text.contains("not seen   kev"), "{text}");
        assert!(text.contains("held back"), "{text}");
        assert!(text.contains("1 failed attempt(s)"), "{text}");

        // Lower-case input finds the same rows.
        let s = state_summary(&db, &["cve-2026-1111".to_string()]).unwrap();
        assert_eq!(s.seen.len(), 1);
        assert_eq!(s.alerted.len(), 2);
    }

    #[test]
    fn awaiting_remedy_marker_of_a_decided_item_is_past() {
        let db = Db::open_in_memory().unwrap();
        let g = "GHSA-aaaa-bbbb-cccc";
        db.mark_seen("ghsa", &format!("{g}#awaiting-remedy"))
            .unwrap();
        let s = state_summary(&db, &[g.to_string()]).unwrap();
        let text = state_lines(&s, &[]).join("\n");
        assert!(text.contains("held back: no fix published yet"), "{text}");
        db.mark_seen("ghsa", g).unwrap();
        let s = state_summary(&db, &[g.to_string()]).unwrap();
        let text = state_lines(&s, &[]).join("\n");
        assert!(!text.contains("no fix published yet"), "{text}");
        assert!(text.contains("decided since"), "{text}");
    }

    #[test]
    fn empty_state_says_so() {
        let db = Db::open_in_memory().unwrap();
        let s = state_summary(&db, &["CVE-2026-1".to_string()]).unwrap();
        let text = state_lines(&s, &["cvelist".into()]).join("\n");
        assert!(text.contains("not seen   cvelist"));
        assert!(text.contains("alerted    none recorded"), "{text}");
        assert!(text.contains("pending    not waiting"), "{text}");
    }

    /// Serve `routes` (path suffix, status, body) over plain HTTP on localhost.
    fn serve(routes: Vec<(&'static str, u16, &'static str)>) -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap() > 2 {
                    line.clear();
                }
                let path = request_line.split(' ').nth(1).unwrap_or("");
                let (status, body) = routes
                    .iter()
                    .find(|(suffix, _, _)| path.ends_with(suffix))
                    .map(|(_, s, b)| (*s, *b))
                    .unwrap_or((404, "{\"message\": \"Not Found\"}"));
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn not_found_at_the_source() {
        let base = serve(vec![]);
        let cfg = mirror_config(&base);
        let http = Http::new(5).unwrap();
        let mut out = Vec::new();
        let id = Id::parse("CVE-2026-12345").unwrap();
        let api = format!("{base}/advisories");
        let found = fetch_live(&id, &cfg, &http, Some("t"), &api, &mut out);
        assert!(found.is_empty());
        assert_eq!(out.len(), 2, "{out:?}");
        assert!(
            out[0].contains("/cves/2026/12xxx/CVE-2026-12345.json"),
            "{out:?}"
        );
        assert!(
            out.iter().all(|l| l.ends_with("not found at the source")),
            "{out:?}"
        );

        let mut out = Vec::new();
        let id = Id::parse("GHSA-aaaa-bbbb-cccc").unwrap();
        assert!(fetch_live(&id, &cfg, &http, None, &api, &mut out).is_empty());
        assert_eq!(
            out,
            vec!["GitHub advisory GHSA-aaaa-bbbb-cccc: not found at the source"]
        );
    }

    #[test]
    fn each_cvelist_url_is_fetched_for_its_own_sources() {
        let record = r#"{"cveMetadata": {"cveId": "CVE-2026-8888", "state": "PUBLISHED"},
            "containers": {"cna": {"title": "nginx: overflow", "descriptions": []}}}"#;
        let good = serve(vec![("/CVE-2026-8888.json", 200, record)]);
        let empty = serve(vec![]);
        let mut cfg = mirror_config(&empty);
        let mut other = cfg
            .sources
            .iter()
            .find(|s| s.kind == SourceKind::Cvelist)
            .unwrap()
            .clone();
        other.name = Some("good".into());
        other.url = Some(format!("{good}/cves"));
        cfg.sources.push(other);
        let http = Http::new(5).unwrap();
        let mut out = Vec::new();
        let id = Id::parse("CVE-2026-8888").unwrap();
        let api = format!("{empty}/advisories");
        let found = fetch_live(&id, &cfg, &http, None, &api, &mut out);
        assert_eq!(found.len(), 1, "{out:?}");
        assert_eq!(found[0].sources.as_deref(), Some(&["good".to_string()][..]));
        assert!(
            out.iter()
                .any(|l| l.contains("(cvelist)") && l.ends_with("not found at the source")),
            "{out:?}"
        );
        let item = found[0].item.as_ref().unwrap();
        let lines = decision_lines(
            item,
            SourceKind::Cvelist,
            found[0].sources.as_deref(),
            &cfg,
            None,
        );
        assert!(lines[0].starts_with("[good] "), "{lines:?}");
        assert!(
            !lines.iter().any(|l| l.starts_with("[cvelist]")),
            "{lines:?}"
        );
    }

    #[test]
    fn cve_lookup_asks_for_each_advisory_type_the_sources_read() {
        let malware = r#"[{"ghsa_id": "GHSA-mmmm-mmmm-mmmm", "cve_id": "CVE-2026-9999",
            "summary": "m", "type": "malware", "vulnerabilities": []}]"#;
        let base = serve(vec![
            (
                "/advisories?cve_id=CVE-2026-9999&per_page=100&type=reviewed",
                200,
                "[]",
            ),
            (
                "/advisories?cve_id=CVE-2026-9999&per_page=100&type=malware",
                200,
                malware,
            ),
        ]);
        let mut cfg = mirror_config(&base);
        let mut m = cfg
            .sources
            .iter()
            .find(|s| s.kind == SourceKind::Ghsa)
            .unwrap()
            .clone();
        m.name = Some("ghsa-malware".into());
        m.url = Some("https://api.github.com/advisories?type=malware&per_page=100".into());
        cfg.sources.push(m);
        let http = Http::new(5).unwrap();
        let mut out = Vec::new();
        let id = Id::parse("CVE-2026-9999").unwrap();
        let api = format!("{base}/advisories");
        let found = fetch_live(&id, &cfg, &http, None, &api, &mut out);
        assert!(
            out.iter()
                .any(|l| l == "GitHub reviewed advisories for CVE-2026-9999: no GitHub advisory"),
            "{out:?}"
        );
        let g: Vec<_> = found
            .iter()
            .filter(|f| f.kind == SourceKind::Ghsa)
            .collect();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].sources, Some(vec!["ghsa-malware".to_string()]));
        assert!(g[0].ids.contains(&"GHSA-mmmm-mmmm-mmmm".to_string()));
    }

    #[test]
    fn finds_cve_record_and_its_advisories() {
        let record = r#"{"cveMetadata": {"cveId": "CVE-2026-7777", "state": "PUBLISHED"},
            "containers": {"cna": {"title": "nginx: overflow", "descriptions": []}}}"#;
        let advisories = r#"[{"ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": "CVE-2026-7777",
            "summary": "s", "type": "unreviewed", "vulnerabilities": []},
            {"ghsa_id": "GHSA-dddd-eeee-ffff", "cve_id": "CVE-2026-7777", "summary": "w",
            "type": "reviewed", "withdrawn_at": "2026-11-01T00:00:00Z"}]"#;
        let base = serve(vec![
            ("/CVE-2026-7777.json", 200, record),
            (
                "/advisories?cve_id=CVE-2026-7777&per_page=100&type=reviewed",
                200,
                advisories,
            ),
        ]);
        let cfg = mirror_config(&base);
        let http = Http::new(5).unwrap();
        let mut out = Vec::new();
        let id = Id::parse("CVE-2026-7777").unwrap();
        let api = format!("{base}/advisories");
        let found = fetch_live(&id, &cfg, &http, None, &api, &mut out);
        assert!(out.is_empty(), "{out:?}");
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].kind, SourceKind::Cvelist);
        assert_eq!(found[0].item.as_ref().unwrap().title, "nginx: overflow");
        // The configured ghsa source reads reviewed advisories only.
        assert!(
            found[1]
                .note
                .as_deref()
                .unwrap()
                .contains("not read by source `ghsa` (type=reviewed)"),
            "{:?}",
            found[1].note
        );
        assert_eq!(found[1].sources, Some(vec![]));
        let lines = decision_lines(
            found[1].item.as_ref().unwrap(),
            SourceKind::Ghsa,
            found[1].sources.as_deref(),
            &cfg,
            None,
        );
        assert_eq!(lines, vec!["no enabled `ghsa` source reads it"]);
        assert_eq!(found[1].item.as_ref().unwrap().id, "GHSA-aaaa-bbbb-cccc");
        assert!(found[2].item.is_none());
        assert!(found[2].note.as_deref().unwrap().contains("withdrawn"));
        // A withdrawn advisory still names its ids for the state lookup.
        assert_eq!(found[2].ids, vec!["GHSA-dddd-eeee-ffff", "CVE-2026-7777"]);
    }

    /// The cvelist source reads `base` (plain http is only allowed in tests).
    fn mirror_config(base: &str) -> Config {
        let mut cfg = config("");
        let src = cfg
            .sources
            .iter_mut()
            .find(|s| s.kind == SourceKind::Cvelist)
            .unwrap();
        src.url = Some(format!("{base}/cves"));
        cfg
    }

    fn config(extra: &str) -> Config {
        Config::parse(&format!(
            "[installed]\nenabled = false\n{extra}\n\
             [[source]]\nkind = \"cvelist\"\n\
             [[source]]\nkind = \"ghsa\"\n\
             [[watch]]\nname = \"nginx\"\n"
        ))
        .unwrap()
    }

    fn item(title: &str, cvss: Option<f32>) -> Item {
        let mut i = Item::new("cvelist", "CVE-2026-1");
        i.cve = Some("CVE-2026-1".into());
        i.title = title.into();
        i.cvss = cvss;
        i
    }

    #[test]
    fn decision_watch_strong_match_is_urgent() {
        let cfg = config("");
        let lines = decision_lines(
            &item("nginx: overflow in resolver", Some(8.0)),
            SourceKind::Cvelist,
            None,
            &cfg,
            None,
        );
        assert!(lines[0].starts_with("[cvelist] Urgent"), "{lines:?}");
        assert!(
            lines[0].contains("ウォッチ: nginx（タイトル: nginx）"),
            "{lines:?}"
        );
        assert!(
            lines[1].contains("watch: nginx (タイトル: nginx, strong)"),
            "{lines:?}"
        );
    }

    #[test]
    fn decision_no_match_below_digest_cvss_is_ignored() {
        let cfg = config("");
        let lines = decision_lines(
            &item("Overflow in FooServer", Some(3.0)),
            SourceKind::Cvelist,
            None,
            &cfg,
            None,
        );
        assert!(lines[0].starts_with("[cvelist] Ignore"), "{lines:?}");
        assert!(lines[0].contains("該当ルールなし"), "{lines:?}");
        assert_eq!(lines[1].trim(), "no watch match");
    }

    #[test]
    fn decision_require_remedy_holds_back() {
        let cfg = config("[rules]\nrequire_remedy = true\n");
        let lines = decision_lines(
            &item("nginx: overflow", Some(9.0)),
            SourceKind::Cvelist,
            None,
            &cfg,
            None,
        );
        assert!(lines[0].starts_with("[cvelist] Ignore"), "{lines:?}");
        assert!(lines[0].contains("対処未公開"), "{lines:?}");
        assert!(lines[1].contains("require_remedy"), "{lines:?}");
    }

    #[test]
    fn decision_without_enabled_source_uses_default_policy() {
        let cfg = config("");
        let lines = decision_lines(
            &item("nginx: overflow", None),
            SourceKind::Usn,
            None,
            &cfg,
            None,
        );
        assert!(lines[0].contains("no enabled `usn` source"), "{lines:?}");
        assert!(lines[1].starts_with("[usn] Urgent"), "{lines:?}");
    }

    #[test]
    fn decision_reports_ignored_title_prefix() {
        let mut cfg = config("");
        let src = cfg
            .sources
            .iter_mut()
            .find(|s| s.kind == SourceKind::Cvelist)
            .unwrap();
        src.ignore_title_prefixes = vec!["NGINX:".into()];
        let lines = decision_lines(
            &item("  nginx: overflow", Some(9.8)),
            SourceKind::Cvelist,
            None,
            &cfg,
            None,
        );
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("dropped by ignore_title_prefixes"),
            "{lines:?}"
        );
    }

    #[test]
    fn decision_respects_watch_sources() {
        let mut cfg = config("");
        cfg.watches = vec![Watch {
            name: "nginx".into(),
            keywords: vec![],
            packages: vec![],
            sources: vec!["ghsa".into()],
            urgent: true,
            exclude: vec![],
        }];
        let lines = decision_lines(
            &item("nginx: overflow", Some(3.0)),
            SourceKind::Cvelist,
            None,
            &cfg,
            None,
        );
        assert!(
            lines.iter().any(|l| l.trim() == "no watch match"),
            "{lines:?}"
        );
    }
}
