use anyhow::{Context, Result};

use crate::config::{Config, DeliveryMode, SourceConfig};
use crate::db::{Db, Queue};
use crate::discord::{self, Message, Notifier, Target};
use crate::http::Http;
use crate::installed::Installed;
use crate::model::{Decision, Item, Level};
use crate::rules::{self, InstalledMatch};
use crate::sources::{self, Ctx, Fetched};
use crate::text::truncate;

pub struct Secrets {
    pub bot_token: Option<String>,
    pub webhook_url: Option<String>,
    pub user_id: Option<String>,
    pub github_token: Option<String>,
    pub heartbeat_url: Option<String>,
}

impl Secrets {
    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Self {
            bot_token: get("DISCORD_BOT_TOKEN"),
            webhook_url: get("DISCORD_WEBHOOK_URL"),
            user_id: get("DISCORD_USER_ID"),
            github_token: get("GITHUB_TOKEN"),
            heartbeat_url: get("HEARTBEAT_URL"),
        }
    }
}

pub fn build_target(cfg: &Config, secrets: &Secrets, dry_run: bool) -> Result<Target> {
    if dry_run {
        return Ok(Target::Stdout);
    }
    Ok(match cfg.discord.mode {
        DeliveryMode::Dm => Target::Dm {
            token: secrets
                .bot_token
                .clone()
                .context("DISCORD_BOT_TOKEN is not set (required for discord.mode = \"dm\")")?,
            user_id: secrets
                .user_id
                .clone()
                .or_else(|| cfg.discord.user_id.clone())
                .context("Discord user id is not set (discord.user_id or DISCORD_USER_ID)")?,
        },
        DeliveryMode::Webhook => Target::Webhook {
            url: secrets.webhook_url.clone().context(
                "DISCORD_WEBHOOK_URL is not set (required for discord.mode = \"webhook\")",
            )?,
            username: cfg.discord.username.clone(),
        },
    })
}

pub struct RunOptions {
    pub dry_run: bool,
    pub limit: Option<usize>,
    /// Exit with an error if any source failed.
    pub strict: bool,
}

#[derive(Default, Debug)]
pub struct RunSummary {
    pub urgent: usize,
    pub digested: usize,
    pub ignored: usize,
    pub bootstrapped: usize,
    pub failed_sources: Vec<String>,
    /// Another run held the run lock, so this one did nothing.
    pub skipped: bool,
}

/// Held while a (non dry-run) `run` is in progress. `sudo vuln-watch run` runs in its own
/// transient unit, so systemd does not keep it from overlapping the timer's run; without
/// this both could send the same outbox entries.
const RUN_LOCK_KEY: &str = "run:lock";
/// Longer than the unit's TimeoutStartSec (300 s) and than one source or one send between
/// renewals. Each renewal restarts it, so a run killed by the timeout blocks the next
/// runs for at most this long.
const RUN_LOCK_MINUTES: i64 = 6;

pub fn run(
    cfg: &Config,
    db: &mut Db,
    http: &Http,
    notifier: &Notifier,
    secrets: &Secrets,
    opts: &RunOptions,
) -> Result<RunSummary> {
    if opts.dry_run {
        return locked_run(cfg, db, http, notifier, secrets, opts, None);
    }
    let Some(mut lock) = db.try_lease(RUN_LOCK_KEY, run_lock_ttl())? else {
        tracing::info!("run: another run is in progress, skipping");
        return Ok(RunSummary {
            skipped: true,
            ..RunSummary::default()
        });
    };
    let result = locked_run(cfg, db, http, notifier, secrets, opts, Some(&mut lock));
    if let Err(e) = db.release_lease(RUN_LOCK_KEY, &lock) {
        tracing::warn!("could not release {RUN_LOCK_KEY}: {e:#}");
    }
    result
}

fn run_lock_ttl() -> chrono::Duration {
    chrono::Duration::minutes(RUN_LOCK_MINUTES)
}

/// Renew the run lock after each source and before each send, so a run that outlives
/// the TTL (e.g. started with `--state-dir`, outside the unit's timeout) keeps it. If it
/// expired and another run took it meanwhile, stop before sending anything that run may
/// send too.
fn renew_run_lock(db: &Db, lock: &mut Option<&mut String>) -> Result<()> {
    let Some(held) = lock.as_deref_mut() else {
        return Ok(());
    };
    match db.renew_lease(RUN_LOCK_KEY, held, run_lock_ttl())? {
        Some(v) => {
            *held = v;
            Ok(())
        }
        None => anyhow::bail!("run lock expired and was taken by another run; stopping"),
    }
}

fn locked_run(
    cfg: &Config,
    db: &mut Db,
    http: &Http,
    notifier: &Notifier,
    secrets: &Secrets,
    opts: &RunOptions,
    mut lock: Option<&mut String>,
) -> Result<RunSummary> {
    let mut summary = RunSummary::default();

    // Read on every run so upgrades done by apt / unattended-upgrades are reflected.
    let installed = if cfg.installed.enabled {
        Some(Installed::load(&cfg.installed)?)
    } else {
        None
    };
    let installed_match = installed.as_ref().map(|i| InstalledMatch {
        installed: i,
        already_fixed: cfg.installed.already_fixed,
    });

    for src in cfg.sources.iter().filter(|s| s.enabled) {
        let name = src.name();
        let result = process_source(
            cfg,
            db,
            http,
            secrets,
            opts,
            src,
            installed_match.as_ref(),
            &mut summary,
        );
        renew_run_lock(db, &mut lock)?;
        match result {
            Ok(got_new) => {
                source_succeeded(db, notifier, &name, opts.dry_run)?;
                check_stale(db, notifier, src, got_new, opts.dry_run, chrono::Utc::now())?;
            }
            Err(e) => {
                tracing::warn!("source {name} failed: {e:#}");
                summary.failed_sources.push(name.clone());
                source_failed(cfg, db, notifier, &name, &e, opts.dry_run)?;
            }
        }
    }

    flush_outbox(cfg, db, notifier, &mut summary, &mut lock)?;

    if !opts.dry_run {
        retry_digest(cfg, db, notifier);
    }

    if !opts.dry_run {
        let hb = secrets
            .heartbeat_url
            .clone()
            .or_else(|| cfg.runtime.heartbeat_url.clone());
        if let Some(url) = hb {
            if let Err(e) = http.ping(&url) {
                tracing::warn!("heartbeat ping failed: {e:#}");
            }
        }
    }

    tracing::info!(
        "run finished: urgent={} digest={} ignored={} bootstrapped={} failed={:?}",
        summary.urgent,
        summary.digested,
        summary.ignored,
        summary.bootstrapped,
        summary.failed_sources
    );
    if opts.strict && !summary.failed_sources.is_empty() {
        anyhow::bail!("sources failed: {}", summary.failed_sources.join(", "));
    }
    Ok(summary)
}

/// Send queued urgent notifications (oldest first). Anything that fails to send stays
/// in the outbox and is retried on the next run; the overflow beyond the per-run cap
/// goes to the digest so a burst can't flood the DM.
fn flush_outbox(
    cfg: &Config,
    db: &Db,
    notifier: &Notifier,
    summary: &mut RunSummary,
    lock: &mut Option<&mut String>,
) -> Result<()> {
    let entries = db.queue_entries(Queue::Outbox)?;
    let max = cfg.runtime.max_urgent_per_run;
    let overflow = entries.len().saturating_sub(max);
    for (i, e) in entries.into_iter().enumerate() {
        if i < max {
            if i > 0 {
                notifier.pace();
            }
            renew_run_lock(db, lock)?;
            let decision = Decision::new(Level::Urgent, e.reason.clone());
            let id = e.item.display_id();
            match notifier.send(db, &discord::urgent_message(&e.item, &decision)) {
                Ok(()) => {}
                // Resending a message Discord refused would fail on every run and hold up
                // everything queued behind it.
                Err(err) if discord::is_rejected(&err) => {
                    tracing::warn!(
                        "Discord rejected the message for {id} ({err:#}), sending plain text"
                    );
                    renew_run_lock(db, lock)?;
                    notifier
                        .send(db, &discord::urgent_fallback_message(&e.item, &decision))
                        .with_context(|| format!("sending plain-text notification for {id}"))?;
                }
                Err(err) => {
                    return Err(err.context(format!("sending notification for {id}")));
                }
            }
            db.set_alerted(&e.key, Level::Urgent)?;
            // It may have been queued for the digest earlier at a lower level.
            db.dequeue(Queue::Digest, &e.key)?;
            db.dequeue(Queue::Digest, &e.item.dedupe_key())?;
            summary.urgent += 1;
        } else {
            db.enqueue(
                Queue::Digest,
                &e.key,
                &e.item,
                &format!("{}（即時通知の上限超過）", e.reason),
            )?;
            db.set_alerted(&e.key, Level::Digest)?;
            summary.digested += 1;
        }
        db.dequeue(Queue::Outbox, &e.key)?;
    }
    if overflow > 0 {
        renew_run_lock(db, lock)?;
        notifier.send(
            db,
            &Message::text(format!(
                "⚠️ 即時通知が上限（{max}件/回）を超えたため、残り{overflow}件はダイジェストに回しました。"
            )),
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn process_source(
    cfg: &Config,
    db: &mut Db,
    http: &Http,
    secrets: &Secrets,
    opts: &RunOptions,
    src: &SourceConfig,
    installed: Option<&InstalledMatch>,
    summary: &mut RunSummary,
) -> Result<bool> {
    let bootstrap = !opts.dry_run && db.get_kv(&format!("init:{}", src.name()))?.is_none();

    let fetched = {
        let ctx = Ctx {
            http,
            db,
            cfg,
            github_token: secrets.github_token.clone(),
            bootstrap,
            limit: opts.limit,
            release: installed.and_then(|i| i.installed.release.clone()),
        };
        sources::fetch(src, &ctx)?
    };

    handle_fetched(cfg, db, src, fetched, bootstrap, opts, installed, summary)
}

/// Decide and enqueue the items of one fetch, then persist its commit pairs.
/// Returns whether anything new arrived (always true on bootstrap).
#[allow(clippy::too_many_arguments)]
fn handle_fetched(
    cfg: &Config,
    db: &mut Db,
    src: &SourceConfig,
    fetched: Fetched,
    bootstrap: bool,
    opts: &RunOptions,
    installed: Option<&InstalledMatch>,
    summary: &mut RunSummary,
) -> Result<bool> {
    let name = src.name();
    let last_new_key = format!("lastnew:{name}");

    if bootstrap {
        let n = db.mark_seen_many(&name, fetched.items.iter().map(|i| i.id.as_str()))?;
        for (k, v) in &fetched.commit {
            db.set_kv(k, v)?;
        }
        let now = chrono::Utc::now().to_rfc3339();
        db.set_kv(&format!("init:{name}"), &now)?;
        db.set_kv(&last_new_key, &now)?;
        tracing::info!("{name}: first run, recorded {n} existing items without notifying");
        summary.bootstrapped += n;
        return Ok(true);
    }

    let total = fetched.items.len();
    let mut new = 0;
    for item in fetched.items {
        if db.is_seen(&name, &item.id)? {
            continue;
        }
        new += 1;
        let decision = rules::evaluate_with(&item, src.mode, &cfg.rules, &cfg.watches, installed);
        if opts.dry_run {
            println!(
                "[{name}] {:<7} {} — {} ({})",
                format!("{:?}", decision.level),
                item.display_id(),
                truncate(&item.title, 80),
                decision.reason
            );
        }
        let key = item.alert_key();
        let already = db.alerted_level(&key)?;
        match decision.level {
            Level::Ignore => {
                summary.ignored += 1;
                db.mark_seen(&name, &item.id)?;
            }
            level if already.is_some_and(|a| a >= level) => {
                tracing::debug!("{name}: {key} already notified at {already:?}");
                db.mark_seen(&name, &item.id)?;
            }
            Level::Digest => {
                db.enqueue(Queue::Digest, &key, &item, &decision.reason)?;
                db.set_alerted(&key, Level::Digest)?;
                db.mark_seen(&name, &item.id)?;
                summary.digested += 1;
            }
            Level::Urgent => {
                // Persist before cursors/ETags are committed; sent by flush_outbox.
                db.enqueue(Queue::Outbox, &key, &item, &decision.reason)?;
                db.mark_seen(&name, &item.id)?;
            }
        }
    }
    for (k, v) in &fetched.commit {
        db.set_kv(k, v)?;
    }
    if new > 0 {
        db.set_kv(&last_new_key, &chrono::Utc::now().to_rfc3339())?;
    }
    tracing::info!("{name}: {total} fetched, {new} new");
    Ok(new > 0)
}

fn source_succeeded(db: &Db, notifier: &Notifier, name: &str, dry_run: bool) -> Result<()> {
    let fail_key = format!("fail:{name}");
    let alert_key = format!("failalert:{name}");
    if db.get_kv(&alert_key)?.is_some() && !dry_run {
        notifier.send(
            db,
            &Message::text(format!("✅ ソース `{name}` の取得が復旧しました。")),
        )?;
    }
    db.del_kv(&fail_key)?;
    db.del_kv(&alert_key)?;
    Ok(())
}

/// After a successful fetch: warn once when a source has returned nothing new for longer
/// than its `stale_after_hours` (e.g. an API field was renamed, a feed moved), and say so
/// when new items arrive again. `lastnew:<name>` is written by `handle_fetched`.
fn check_stale(
    db: &Db,
    notifier: &Notifier,
    src: &SourceConfig,
    got_new: bool,
    dry_run: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    if dry_run {
        return Ok(());
    }
    let name = src.name();
    let last_new_key = format!("lastnew:{name}");
    let alert_key = format!("stalealert:{name}");
    let hours = src.stale_after_hours();
    if hours == 0 {
        // Turned off: drop an earlier alert without a recovery message.
        db.del_kv(&alert_key)?;
        return Ok(());
    }
    let parse = |v: &str| chrono::DateTime::parse_from_rfc3339(v).ok();
    let last = db.get_kv(&last_new_key)?.as_deref().and_then(parse);
    let Some(last) = last else {
        // Installs from before this check have no time yet: start counting now.
        db.set_kv(&last_new_key, &now.to_rfc3339())?;
        return Ok(());
    };
    if let Some(alerted) = db.get_kv(&alert_key)? {
        // A new item since the alert, in this run or in one whose recovery message
        // failed to send (its items are seen by now, so `got_new` alone would miss it).
        if got_new || parse(&alerted).is_some_and(|at| last > at) {
            notifier.send(
                db,
                &Message::text(format!("✅ ソース `{name}` に新しい項目が届きました。")),
            )?;
            db.del_kv(&alert_key)?;
        }
        return Ok(());
    }
    if got_new {
        return Ok(());
    }
    let elapsed = now.signed_duration_since(last).num_hours();
    if elapsed >= 0 && elapsed as u64 >= hours && db.get_kv(&alert_key)?.is_none() {
        notifier.send(
            db,
            &Message::text(format!(
                "⚠️ ソース `{name}` から{elapsed}時間、新しい項目がありません（取得は成功）。URL や形式の変更を確認してください。"
            )),
        )?;
        db.set_kv(&alert_key, &now.to_rfc3339())?;
    }
    Ok(())
}

fn source_failed(
    cfg: &Config,
    db: &Db,
    notifier: &Notifier,
    name: &str,
    err: &anyhow::Error,
    dry_run: bool,
) -> Result<()> {
    let fail_key = format!("fail:{name}");
    let alert_key = format!("failalert:{name}");
    let count: u32 = db
        .get_kv(&fail_key)?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        + 1;
    db.set_kv(&fail_key, &count.to_string())?;
    if !dry_run && count >= cfg.runtime.alert_after_failures && db.get_kv(&alert_key)?.is_none() {
        notifier.send(
            db,
            &Message::text(truncate(
                &format!(
                    "⚠️ ソース `{name}` の取得が{count}回連続で失敗しています。\n```\n{err:#}\n```"
                ),
                1900,
            )),
        )?;
        db.set_kv(&alert_key, "1")?;
    }
    Ok(())
}

/// Set when a digest fails to send (value: time of the failed attempt); `run` then retries it.
const DIGEST_RETRY_KEY: &str = "digest:retry";
const DIGEST_RETRY_INTERVAL_MINUTES: i64 = 5;
/// Held while a digest is being sent, so the scheduled digest and a retry from `run`
/// (separate service instances) never send the same queue entries twice.
const DIGEST_LOCK_KEY: &str = "digest:lock";
/// Longer than the unit's TimeoutStartSec, so a killed process does not block digests for long.
const DIGEST_LOCK_MINUTES: i64 = 10;

/// Send the queued digest. Each message's entries are dequeued once it is sent, so a
/// failure part way leaves only the unsent entries queued, and `run` resends them.
pub fn digest(cfg: &Config, db: &Db, notifier: &Notifier) -> Result<usize> {
    let Some(lock) = db.try_lease(
        DIGEST_LOCK_KEY,
        chrono::Duration::minutes(DIGEST_LOCK_MINUTES),
    )?
    else {
        tracing::info!("digest: another digest is being sent, skipping");
        return Ok(0);
    };
    let result = locked_digest(cfg, db, notifier);
    if let Err(e) = db.release_lease(DIGEST_LOCK_KEY, &lock) {
        tracing::warn!("could not release {DIGEST_LOCK_KEY}: {e:#}");
    }
    result
}

fn locked_digest(cfg: &Config, db: &Db, notifier: &Notifier) -> Result<usize> {
    let resumed = db.get_kv(DIGEST_RETRY_KEY)?.is_some();
    let result = send_digest(cfg, db, notifier, resumed);
    match &result {
        Ok(_) => db.del_kv(DIGEST_RETRY_KEY)?,
        Err(_) => {
            if let Err(e) = db.set_kv(DIGEST_RETRY_KEY, &chrono::Utc::now().to_rfc3339()) {
                tracing::warn!("could not record the failed digest for retry: {e:#}");
            }
        }
    }
    result
}

fn send_digest(cfg: &Config, db: &Db, notifier: &Notifier, resumed: bool) -> Result<usize> {
    let entries = db.queue_entries(Queue::Digest)?;
    if entries.is_empty() {
        if cfg.runtime.digest_send_empty {
            notifier.send(
                db,
                &Message::text("📋 脆弱性ダイジェスト: 新着はありません"),
            )?;
        }
        tracing::info!("digest: nothing to send");
        return Ok(0);
    }
    let msgs = discord::digest_messages(&entries, resumed);
    for (i, (msg, keys)) in msgs.iter().enumerate() {
        if i > 0 {
            notifier.pace();
        }
        notifier
            .send(db, msg)
            .with_context(|| format!("sending digest message {}/{}", i + 1, msgs.len()))?;
        for key in keys {
            db.dequeue(Queue::Digest, key)?;
        }
    }
    tracing::info!(
        "digest: sent {} items in {} messages",
        entries.len(),
        msgs.len()
    );
    Ok(entries.len())
}

/// Resend a digest that failed, at most every few minutes. Failures are only logged so
/// they never hold up urgent delivery or change the exit code of `run`.
fn retry_digest(cfg: &Config, db: &Db, notifier: &Notifier) {
    let last = match db.get_kv(DIGEST_RETRY_KEY) {
        Ok(Some(v)) => v,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!("reading {DIGEST_RETRY_KEY} failed: {e:#}");
            return;
        }
    };
    let due = chrono::DateTime::parse_from_rfc3339(&last).map_or(true, |t| {
        chrono::Utc::now().signed_duration_since(t)
            >= chrono::Duration::minutes(DIGEST_RETRY_INTERVAL_MINUTES)
    });
    if !due {
        return;
    }
    tracing::info!("retrying the digest that failed at {last}");
    if let Err(e) = digest(cfg, db, notifier) {
        tracing::warn!("digest retry failed: {e:#}");
    }
}

pub fn test_message() -> Message {
    let mut item = Item::new("test", "VULN-WATCH-TEST");
    item.title = "vuln-watch のテスト通知です".into();
    item.summary = "この通知が届いていれば、Discordへの送信設定は正しく動作しています。".into();
    item.url = "https://github.com/Matuyuhi/vuln-watch".into();
    item.cvss = Some(9.8);
    item.severity = Some("critical".into());
    item.products = vec!["example product".into()];
    discord::urgent_message(&item, &Decision::new(Level::Urgent, "テスト"))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::discord::{Fail, Recorder};

    const CONFIG: &str = r#"
[runtime]
max_urgent_per_run = 2
alert_after_failures = 2

[[source]]
kind = "kev"

[[source]]
kind = "ghsa"
"#;

    fn cfg() -> Config {
        Config::parse(CONFIG).unwrap()
    }

    fn src<'a>(cfg: &'a Config, name: &str) -> &'a SourceConfig {
        cfg.sources.iter().find(|s| s.name() == name).unwrap()
    }

    fn opts() -> RunOptions {
        RunOptions {
            dry_run: false,
            limit: None,
            strict: false,
        }
    }

    fn recorder(http: &Http, fail: Vec<(usize, Fail)>) -> Notifier<'_> {
        Notifier::new(
            http,
            Target::Recorder(RefCell::new(Recorder::failing(fail))),
        )
    }

    /// Urgent by the default rules (CISA KEV).
    fn kev_item(source: &str, cve: &str) -> Item {
        let mut item = Item::new(source, cve);
        item.cve = Some(cve.into());
        item.title = format!("{cve} title");
        item.kev = true;
        item
    }

    /// Digest by the default rules (unmatched, CVSS >= 9.0).
    fn digest_item(source: &str, cve: &str) -> Item {
        let mut item = Item::new(source, cve);
        item.cve = Some(cve.into());
        item.title = format!("{cve} title");
        item.cvss = Some(9.5);
        item
    }

    fn fetched(items: Vec<Item>, cursor: &str) -> Fetched {
        Fetched {
            items,
            commit: vec![("cursor:test".into(), cursor.into())],
        }
    }

    fn handle(cfg: &Config, db: &mut Db, name: &str, f: Fetched, s: &mut RunSummary) {
        handle_fetched(cfg, db, src(cfg, name), f, false, &opts(), None, s).unwrap();
    }

    fn keys(db: &Db, q: Queue) -> Vec<String> {
        db.queue_entries(q)
            .unwrap()
            .into_iter()
            .map(|e| e.key)
            .collect()
    }

    #[test]
    fn bootstrap_marks_seen_and_commits_without_queueing() {
        let cfg = cfg();
        let mut db = Db::open_in_memory().unwrap();
        let mut s = RunSummary::default();
        let f = fetched(
            vec![
                kev_item("kev", "CVE-2026-0001"),
                digest_item("kev", "CVE-2026-0002"),
            ],
            "c1",
        );
        handle_fetched(
            &cfg,
            &mut db,
            src(&cfg, "kev"),
            f,
            true,
            &opts(),
            None,
            &mut s,
        )
        .unwrap();

        assert!(db.is_seen("kev", "CVE-2026-0001").unwrap());
        assert!(db.is_seen("kev", "CVE-2026-0002").unwrap());
        assert_eq!(db.get_kv("cursor:test").unwrap().as_deref(), Some("c1"));
        assert!(db.get_kv("init:kev").unwrap().is_some());
        assert_eq!(db.queue_len(Queue::Outbox).unwrap(), 0);
        assert_eq!(db.queue_len(Queue::Digest).unwrap(), 0);
        assert_eq!(s.bootstrapped, 2);
    }

    #[test]
    fn urgent_item_is_in_outbox_before_commit() {
        let cfg = cfg();
        let mut db = Db::open_in_memory().unwrap();
        // Fail the commit write if nothing has been enqueued yet.
        db.execute_batch(
            "CREATE TRIGGER commit_after_enqueue BEFORE INSERT ON kv
             WHEN NEW.key = 'cursor:test' AND (SELECT COUNT(*) FROM outbox) = 0
             BEGIN SELECT RAISE(ABORT, 'commit before enqueue'); END;",
        )
        .unwrap();
        let mut s = RunSummary::default();
        handle(
            &cfg,
            &mut db,
            "kev",
            fetched(vec![kev_item("kev", "CVE-2026-0001")], "c1"),
            &mut s,
        );
        assert_eq!(keys(&db, Queue::Outbox), ["CVE-2026-0001#kev"]);
        assert_eq!(db.get_kv("cursor:test").unwrap().as_deref(), Some("c1"));

        // The trigger itself works: a commit with an empty outbox is refused.
        db.dequeue(Queue::Outbox, "CVE-2026-0001#kev").unwrap();
        db.del_kv("cursor:test").unwrap();
        assert!(db.set_kv("cursor:test", "c2").is_err());
    }

    #[test]
    fn same_cve_from_two_sources_is_sent_once() {
        let cfg = cfg();
        let http = Http::new(5).unwrap();
        let notifier = recorder(&http, vec![]);
        let mut db = Db::open_in_memory().unwrap();
        let mut s = RunSummary::default();
        handle(
            &cfg,
            &mut db,
            "kev",
            fetched(vec![kev_item("kev", "CVE-2026-0001")], "c1"),
            &mut s,
        );
        handle(
            &cfg,
            &mut db,
            "ghsa",
            fetched(vec![kev_item("ghsa", "CVE-2026-0001")], "c2"),
            &mut s,
        );
        flush_outbox(&cfg, &db, &notifier, &mut s, &mut None).unwrap();

        assert_eq!(notifier.sent().len(), 1);
        assert_eq!(s.urgent, 1);
        assert_eq!(db.queue_len(Queue::Outbox).unwrap(), 0);

        // Seen again on a later run from a third copy: not sent again.
        let mut again = kev_item("ghsa", "CVE-2026-0001");
        again.id = "GHSA-xxxx".into();
        handle(&cfg, &mut db, "ghsa", fetched(vec![again], "c3"), &mut s);
        assert_eq!(db.queue_len(Queue::Outbox).unwrap(), 0);
    }

    #[test]
    fn digest_cve_later_in_kev_is_sent_urgent_and_leaves_digest() {
        let cfg = cfg();
        let http = Http::new(5).unwrap();
        let notifier = recorder(&http, vec![]);
        let mut db = Db::open_in_memory().unwrap();
        let mut s = RunSummary::default();
        handle(
            &cfg,
            &mut db,
            "ghsa",
            fetched(vec![digest_item("ghsa", "CVE-2026-0001")], "c1"),
            &mut s,
        );
        assert_eq!(keys(&db, Queue::Digest), ["CVE-2026-0001"]);
        assert_eq!(
            db.alerted_level("CVE-2026-0001").unwrap(),
            Some(Level::Digest)
        );

        handle(
            &cfg,
            &mut db,
            "kev",
            fetched(vec![kev_item("kev", "CVE-2026-0001")], "c2"),
            &mut s,
        );
        flush_outbox(&cfg, &db, &notifier, &mut s, &mut None).unwrap();

        let sent = notifier.sent();
        assert_eq!(sent.len(), 1);
        assert!(
            sent[0].content.contains("CVE-2026-0001"),
            "{}",
            sent[0].content
        );
        assert_eq!(
            db.alerted_level("CVE-2026-0001#kev").unwrap(),
            Some(Level::Urgent)
        );
        assert!(keys(&db, Queue::Digest).is_empty());
    }

    #[test]
    fn overflow_beyond_cap_goes_to_digest_with_one_notice() {
        let cfg = cfg();
        let http = Http::new(5).unwrap();
        let notifier = recorder(&http, vec![]);
        let mut db = Db::open_in_memory().unwrap();
        let mut s = RunSummary::default();
        let items = (1..=5)
            .map(|i| kev_item("kev", &format!("CVE-2026-000{i}")))
            .collect();
        handle(&cfg, &mut db, "kev", fetched(items, "c1"), &mut s);
        flush_outbox(&cfg, &db, &notifier, &mut s, &mut None).unwrap();

        let sent = notifier.sent();
        assert_eq!(sent.len(), 3, "2 urgent + 1 overflow notice");
        assert!(sent[0].content.contains("CVE-2026-0001"));
        assert!(sent[1].content.contains("CVE-2026-0002"));
        assert!(sent[2].content.contains("残り3件"), "{}", sent[2].content);
        assert_eq!(s.urgent, 2);
        assert_eq!(s.digested, 3);
        assert_eq!(db.queue_len(Queue::Outbox).unwrap(), 0);
        assert_eq!(
            keys(&db, Queue::Digest),
            [
                "CVE-2026-0003#kev",
                "CVE-2026-0004#kev",
                "CVE-2026-0005#kev"
            ]
        );
        let reason = &db.queue_entries(Queue::Digest).unwrap()[0].reason;
        assert!(reason.contains("即時通知の上限超過"), "{reason}");
    }

    #[test]
    fn rejected_message_is_resent_as_plain_text_and_next_item_still_sent() {
        let cfg = cfg();
        let http = Http::new(5).unwrap();
        // Attempt 0 (first item, embed) is rejected; 1 is its fallback; 2 is the next item.
        let notifier = recorder(&http, vec![(0, Fail::Rejected)]);
        let mut db = Db::open_in_memory().unwrap();
        let mut s = RunSummary::default();
        handle(
            &cfg,
            &mut db,
            "kev",
            fetched(
                vec![
                    kev_item("kev", "CVE-2026-0001"),
                    kev_item("kev", "CVE-2026-0002"),
                ],
                "c1",
            ),
            &mut s,
        );
        flush_outbox(&cfg, &db, &notifier, &mut s, &mut None).unwrap();

        let sent = notifier.sent();
        assert_eq!(sent.len(), 2);
        assert!(sent[0].embeds.is_empty(), "fallback is plain text");
        assert!(sent[0].content.contains("CVE-2026-0001"));
        assert!(!sent[1].embeds.is_empty());
        assert!(sent[1].content.contains("CVE-2026-0002"));
        assert_eq!(s.urgent, 2);
        assert_eq!(db.queue_len(Queue::Outbox).unwrap(), 0);
    }

    #[test]
    fn transient_error_keeps_item_and_later_items_in_outbox() {
        let cfg = cfg();
        let http = Http::new(5).unwrap();
        let mut db = Db::open_in_memory().unwrap();
        let mut s = RunSummary::default();
        handle(
            &cfg,
            &mut db,
            "kev",
            fetched(
                vec![
                    kev_item("kev", "CVE-2026-0001"),
                    kev_item("kev", "CVE-2026-0002"),
                ],
                "c1",
            ),
            &mut s,
        );

        let failing = recorder(&http, vec![(0, Fail::Transient)]);
        assert!(flush_outbox(&cfg, &db, &failing, &mut s, &mut None).is_err());
        assert!(failing.sent().is_empty());
        assert_eq!(
            keys(&db, Queue::Outbox),
            ["CVE-2026-0001#kev", "CVE-2026-0002#kev"]
        );
        assert_eq!(db.alerted_level("CVE-2026-0001#kev").unwrap(), None);

        // Next run: both are sent, in order.
        let ok = recorder(&http, vec![]);
        flush_outbox(&cfg, &db, &ok, &mut s, &mut None).unwrap();
        let sent = ok.sent();
        assert_eq!(sent.len(), 2);
        assert!(sent[0].content.contains("CVE-2026-0001"));
        assert!(sent[1].content.contains("CVE-2026-0002"));
        assert_eq!(db.queue_len(Queue::Outbox).unwrap(), 0);
    }

    #[test]
    fn source_failure_alerts_once_and_recovery_clears_counters() {
        let cfg = cfg();
        let http = Http::new(5).unwrap();
        let notifier = recorder(&http, vec![]);
        let db = Db::open_in_memory().unwrap();
        let err = anyhow::anyhow!("HTTP 503");

        source_failed(&cfg, &db, &notifier, "kev", &err, false).unwrap();
        assert!(notifier.sent().is_empty(), "below alert_after_failures");
        source_failed(&cfg, &db, &notifier, "kev", &err, false).unwrap();
        source_failed(&cfg, &db, &notifier, "kev", &err, false).unwrap();
        let sent = notifier.sent();
        assert_eq!(sent.len(), 1, "one failing message");
        assert!(
            sent[0].content.contains("2回連続で失敗"),
            "{}",
            sent[0].content
        );
        assert_eq!(db.get_kv("fail:kev").unwrap().as_deref(), Some("3"));

        source_succeeded(&db, &notifier, "kev", false).unwrap();
        source_succeeded(&db, &notifier, "kev", false).unwrap();
        let sent = notifier.sent();
        assert_eq!(sent.len(), 2, "one recovered message");
        assert!(sent[1].content.contains("復旧"), "{}", sent[1].content);
        assert_eq!(db.get_kv("fail:kev").unwrap(), None);
        assert_eq!(db.get_kv("failalert:kev").unwrap(), None);
    }

    fn hours_before(now: chrono::DateTime<chrono::Utc>, h: i64) -> String {
        (now - chrono::Duration::hours(h)).to_rfc3339()
    }

    fn hours_ago(h: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::hours(h)).to_rfc3339()
    }

    #[test]
    fn new_items_and_bootstrap_record_lastnew() {
        let cfg = cfg();
        let mut db = Db::open_in_memory().unwrap();
        let mut s = RunSummary::default();
        let got = handle_fetched(
            &cfg,
            &mut db,
            src(&cfg, "kev"),
            fetched(vec![], "c0"),
            true,
            &opts(),
            None,
            &mut s,
        )
        .unwrap();
        assert!(got, "bootstrap counts as new");
        assert!(db.get_kv("lastnew:kev").unwrap().is_some());

        let old = hours_ago(100);
        db.set_kv("lastnew:kev", &old).unwrap();
        let got = handle_fetched(
            &cfg,
            &mut db,
            src(&cfg, "kev"),
            fetched(vec![], "c1"),
            false,
            &opts(),
            None,
            &mut s,
        )
        .unwrap();
        assert!(!got);
        assert_eq!(db.get_kv("lastnew:kev").unwrap(), Some(old.clone()));

        let got = handle_fetched(
            &cfg,
            &mut db,
            src(&cfg, "kev"),
            fetched(vec![digest_item("kev", "CVE-2026-0001")], "c2"),
            false,
            &opts(),
            None,
            &mut s,
        )
        .unwrap();
        assert!(got);
        assert_ne!(db.get_kv("lastnew:kev").unwrap(), Some(old.clone()));

        // Already seen: not new, lastnew unchanged.
        db.set_kv("lastnew:kev", &old).unwrap();
        let got = handle_fetched(
            &cfg,
            &mut db,
            src(&cfg, "kev"),
            fetched(vec![digest_item("kev", "CVE-2026-0001")], "c3"),
            false,
            &opts(),
            None,
            &mut s,
        )
        .unwrap();
        assert!(!got);
        assert_eq!(db.get_kv("lastnew:kev").unwrap(), Some(old));
    }

    const STALE_CONFIG: &str = r#"
[[source]]
kind = "ghsa"
stale_after_hours = 10

[[source]]
kind = "kev"
stale_after_hours = 0
"#;

    #[test]
    fn stale_source_alerts_once_and_recovers() {
        let cfg = Config::parse(STALE_CONFIG).unwrap();
        let http = Http::new(5).unwrap();
        let notifier = recorder(&http, vec![]);
        let db = Db::open_in_memory().unwrap();
        let ghsa = src(&cfg, "ghsa");
        let now = chrono::Utc::now();

        db.set_kv("lastnew:ghsa", &hours_before(now, 9)).unwrap();
        check_stale(&db, &notifier, ghsa, false, false, now).unwrap();
        assert!(notifier.sent().is_empty(), "not stale yet");

        db.set_kv("lastnew:ghsa", &hours_before(now, 11)).unwrap();
        check_stale(&db, &notifier, ghsa, false, false, now).unwrap();
        let sent = notifier.sent();
        assert_eq!(sent.len(), 1);
        assert!(
            sent[0]
                .content
                .contains("`ghsa` から11時間、新しい項目がありません"),
            "{}",
            sent[0].content
        );
        assert!(db.get_kv("stalealert:ghsa").unwrap().is_some());

        // Still stale on the next run: no second message.
        check_stale(&db, &notifier, ghsa, false, false, now).unwrap();
        assert_eq!(notifier.sent().len(), 1);

        // A new item: one recovery message, alert cleared.
        check_stale(&db, &notifier, ghsa, true, false, now).unwrap();
        check_stale(&db, &notifier, ghsa, true, false, now).unwrap();
        let sent = notifier.sent();
        assert_eq!(sent.len(), 2);
        assert!(
            sent[1].content.contains("新しい項目が届きました"),
            "{}",
            sent[1].content
        );
        assert!(db.get_kv("stalealert:ghsa").unwrap().is_none());
    }

    #[test]
    fn failed_recovery_message_is_retried_on_a_quiet_run() {
        let cfg = Config::parse(STALE_CONFIG).unwrap();
        let http = Http::new(5).unwrap();
        let db = Db::open_in_memory().unwrap();
        let ghsa = src(&cfg, "ghsa");
        let now = chrono::Utc::now();
        db.set_kv("lastnew:ghsa", &hours_before(now, 11)).unwrap();
        let ok = recorder(&http, vec![]);
        check_stale(&db, &ok, ghsa, false, false, now).unwrap();
        assert_eq!(ok.sent().len(), 1);

        // New items arrive an hour later, but the recovery message fails to send.
        let later = now + chrono::Duration::hours(1);
        db.set_kv("lastnew:ghsa", &later.to_rfc3339()).unwrap();
        let failing = recorder(&http, vec![(0, Fail::Transient)]);
        assert!(check_stale(&db, &failing, ghsa, true, false, later).is_err());
        assert!(db.get_kv("stalealert:ghsa").unwrap().is_some());

        // The next run has nothing new, but still sends the recovery message.
        let ok = recorder(&http, vec![]);
        check_stale(&db, &ok, ghsa, false, false, later).unwrap();
        let sent = ok.sent();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].content.contains("新しい項目が届きました"));
        assert!(db.get_kv("stalealert:ghsa").unwrap().is_none());
    }

    #[test]
    fn turning_the_check_off_clears_the_alert_without_a_message() {
        let cfg = Config::parse(STALE_CONFIG).unwrap();
        let http = Http::new(5).unwrap();
        let notifier = recorder(&http, vec![]);
        let db = Db::open_in_memory().unwrap();
        let now = chrono::Utc::now();
        db.set_kv("lastnew:kev", &now.to_rfc3339()).unwrap();
        db.set_kv("stalealert:kev", &hours_before(now, 1)).unwrap();
        check_stale(&db, &notifier, src(&cfg, "kev"), true, false, now).unwrap();
        assert!(notifier.sent().is_empty());
        assert!(db.get_kv("stalealert:kev").unwrap().is_none());
    }

    #[test]
    fn stale_check_off_missing_key_or_dry_run_never_alerts() {
        let cfg = Config::parse(STALE_CONFIG).unwrap();
        let http = Http::new(5).unwrap();
        let notifier = recorder(&http, vec![]);
        let db = Db::open_in_memory().unwrap();
        let now = chrono::Utc::now();

        // stale_after_hours = 0
        db.set_kv("lastnew:kev", &hours_ago(10_000)).unwrap();
        check_stale(&db, &notifier, src(&cfg, "kev"), false, false, now).unwrap();
        assert!(db.get_kv("stalealert:kev").unwrap().is_none());

        // Dry run
        db.set_kv("lastnew:ghsa", &hours_ago(100)).unwrap();
        check_stale(&db, &notifier, src(&cfg, "ghsa"), false, true, now).unwrap();
        assert!(db.get_kv("stalealert:ghsa").unwrap().is_none());

        // First run after an upgrade: no key yet, so start counting instead of alerting.
        db.del_kv("lastnew:ghsa").unwrap();
        check_stale(&db, &notifier, src(&cfg, "ghsa"), false, false, now).unwrap();
        assert_eq!(db.get_kv("lastnew:ghsa").unwrap(), Some(now.to_rfc3339()));
        assert!(notifier.sent().is_empty());
    }

    fn config() -> Config {
        let mut cfg = Config::parse("").unwrap();
        cfg.sources.clear();
        cfg.installed.enabled = false;
        cfg
    }

    fn secrets() -> Secrets {
        Secrets {
            bot_token: None,
            webhook_url: None,
            user_id: None,
            github_token: None,
            heartbeat_url: None,
        }
    }

    /// Queue enough entries for three digest messages; returns the keys per message.
    fn fill_digest(db: &Db) -> Vec<Vec<String>> {
        for i in 0..60 {
            let mut item = Item::new("ghsa", format!("GHSA-{i:04}"));
            item.title = "x".repeat(90);
            item.url = format!("https://example.com/{i}");
            db.enqueue(Queue::Digest, &format!("k{i:03}"), &item, "CVSS 9.1 ≥ 9.0")
                .unwrap();
        }
        let msgs = discord::digest_messages(&db.queue_entries(Queue::Digest).unwrap(), false);
        assert_eq!(msgs.len(), 3);
        msgs.into_iter().map(|(_, keys)| keys).collect()
    }

    fn queued(db: &Db) -> Vec<String> {
        let entries = db.queue_entries(Queue::Digest).unwrap();
        entries.into_iter().map(|e| e.key).collect()
    }

    fn make_retry_due(db: &Db) {
        let t = chrono::Utc::now() - chrono::Duration::minutes(DIGEST_RETRY_INTERVAL_MINUTES);
        db.set_kv(DIGEST_RETRY_KEY, &t.to_rfc3339()).unwrap();
    }

    #[test]
    fn partial_digest_failure_keeps_only_unsent_entries() {
        let (cfg, http) = (config(), Http::new(5).unwrap());
        let mut db = Db::open_in_memory().unwrap();
        let keys = fill_digest(&db);

        let notifier = recorder(&http, vec![(1, Fail::Transient)]);
        assert!(digest(&cfg, &db, &notifier).is_err());
        assert_eq!(notifier.sent().len(), 1);
        let rest: Vec<String> = keys[1..].concat();
        assert_eq!(queued(&db), rest);
        assert!(db.get_kv(DIGEST_RETRY_KEY).unwrap().is_some());

        // Not retried right after the failure.
        let notifier = recorder(&http, vec![]);
        retry_digest(&cfg, &db, &notifier);
        assert!(notifier.sent().is_empty());

        make_retry_due(&db);
        let opts = RunOptions {
            dry_run: false,
            limit: None,
            strict: true,
        };
        run(&cfg, &mut db, &http, &notifier, &secrets(), &opts).unwrap();
        let sent = notifier.sent();
        assert_eq!(sent.len(), 2);
        assert!(sent[0]
            .content
            .starts_with(&format!("📋 脆弱性ダイジェスト（再送）: {}件", rest.len())));
        assert!(queued(&db).is_empty());
        assert!(db.get_kv(DIGEST_RETRY_KEY).unwrap().is_none());
    }

    #[test]
    fn successful_digest_leaves_no_retry_key() {
        let (cfg, db, http) = (
            config(),
            Db::open_in_memory().unwrap(),
            Http::new(5).unwrap(),
        );
        fill_digest(&db);
        let notifier = recorder(&http, vec![]);
        assert_eq!(digest(&cfg, &db, &notifier).unwrap(), 60);
        assert_eq!(notifier.sent().len(), 3);
        assert!(notifier.sent()[0]
            .content
            .starts_with("📋 脆弱性ダイジェスト: 60件"));
        assert!(queued(&db).is_empty());
        assert!(db.get_kv(DIGEST_RETRY_KEY).unwrap().is_none());
    }

    #[test]
    fn digest_skips_while_another_is_sending() {
        let (cfg, db, http) = (
            config(),
            Db::open_in_memory().unwrap(),
            Http::new(5).unwrap(),
        );
        fill_digest(&db);
        assert!(db
            .try_lease(DIGEST_LOCK_KEY, chrono::Duration::minutes(1))
            .unwrap()
            .is_some());
        let notifier = recorder(&http, vec![]);
        assert_eq!(digest(&cfg, &db, &notifier).unwrap(), 0);
        assert!(notifier.sent().is_empty());
        assert_eq!(queued(&db).len(), 60);
    }

    #[test]
    fn digest_retry_failure_does_not_fail_run() {
        let (cfg, http) = (config(), Http::new(5).unwrap());
        let mut db = Db::open_in_memory().unwrap();
        fill_digest(&db);
        make_retry_due(&db);
        let mut item = Item::new("kev", "CVE-2026-0001");
        item.cve = Some("CVE-2026-0001".into());
        db.enqueue(Queue::Outbox, &item.alert_key(), &item, "CISA KEV")
            .unwrap();

        // The urgent message goes out first; the digest retry then fails.
        let notifier = recorder(&http, vec![(1, Fail::Transient)]);
        let opts = RunOptions {
            dry_run: false,
            limit: None,
            strict: true,
        };
        let summary = run(&cfg, &mut db, &http, &notifier, &secrets(), &opts).unwrap();
        assert_eq!(summary.urgent, 1);
        assert_eq!(db.queue_len(Queue::Outbox).unwrap(), 0);
        assert_eq!(queued(&db).len(), 60);
        assert!(db.get_kv(DIGEST_RETRY_KEY).unwrap().is_some());
    }

    fn outbox_with_one_urgent(db: &Db) {
        let mut item = Item::new("kev", "CVE-2026-0002");
        item.cve = Some("CVE-2026-0002".into());
        db.enqueue(Queue::Outbox, &item.alert_key(), &item, "CISA KEV")
            .unwrap();
    }

    fn run_opts() -> RunOptions {
        RunOptions {
            dry_run: false,
            limit: None,
            strict: true,
        }
    }

    #[test]
    fn run_skips_while_another_run_holds_the_lock() {
        let (cfg, http) = (config(), Http::new(5).unwrap());
        let mut db = Db::open_in_memory().unwrap();
        outbox_with_one_urgent(&db);
        assert!(db
            .try_lease(RUN_LOCK_KEY, run_lock_ttl())
            .unwrap()
            .is_some());
        let notifier = recorder(&http, vec![]);
        let summary = run(&cfg, &mut db, &http, &notifier, &secrets(), &run_opts()).unwrap();
        assert!(summary.skipped);
        assert!(notifier.sent().is_empty());
        assert_eq!(db.queue_len(Queue::Outbox).unwrap(), 1);
        // The other run's lease is left alone.
        assert!(db.get_kv(RUN_LOCK_KEY).unwrap().is_some());
    }

    #[test]
    fn run_releases_the_lock_when_done() {
        let (cfg, http) = (config(), Http::new(5).unwrap());
        let mut db = Db::open_in_memory().unwrap();
        outbox_with_one_urgent(&db);
        let notifier = recorder(&http, vec![]);
        let summary = run(&cfg, &mut db, &http, &notifier, &secrets(), &run_opts()).unwrap();
        assert!(!summary.skipped);
        assert_eq!(summary.urgent, 1);
        assert!(db.get_kv(RUN_LOCK_KEY).unwrap().is_none());
    }

    #[test]
    fn run_releases_the_lock_on_error() {
        let (mut cfg, http) = (config(), Http::new(5).unwrap());
        cfg.installed.enabled = true;
        cfg.installed.dpkg_status = "/nonexistent/dpkg/status".into();
        let mut db = Db::open_in_memory().unwrap();
        let notifier = recorder(&http, vec![]);
        assert!(run(&cfg, &mut db, &http, &notifier, &secrets(), &run_opts()).is_err());
        assert!(db.get_kv(RUN_LOCK_KEY).unwrap().is_none());
    }

    #[test]
    fn expired_run_lock_does_not_block() {
        let (cfg, http) = (config(), Http::new(5).unwrap());
        let mut db = Db::open_in_memory().unwrap();
        outbox_with_one_urgent(&db);
        db.set_kv(RUN_LOCK_KEY, "2000-01-01T00:00:00Z").unwrap();
        let notifier = recorder(&http, vec![]);
        let summary = run(&cfg, &mut db, &http, &notifier, &secrets(), &run_opts()).unwrap();
        assert!(!summary.skipped);
        assert_eq!(notifier.sent().len(), 1);
        assert_eq!(db.queue_len(Queue::Outbox).unwrap(), 0);
        assert!(db.get_kv(RUN_LOCK_KEY).unwrap().is_none());
    }

    #[test]
    fn dry_run_takes_no_lock() {
        let (cfg, http) = (config(), Http::new(5).unwrap());
        let mut db = Db::open_in_memory().unwrap();
        db.set_kv(RUN_LOCK_KEY, "2999-01-01T00:00:00Z").unwrap();
        let notifier = recorder(&http, vec![]);
        let opts = RunOptions {
            dry_run: true,
            limit: None,
            strict: true,
        };
        let summary = run(&cfg, &mut db, &http, &notifier, &secrets(), &opts).unwrap();
        assert!(!summary.skipped);
        assert_eq!(
            db.get_kv(RUN_LOCK_KEY).unwrap().as_deref(),
            Some("2999-01-01T00:00:00Z")
        );
    }

    #[test]
    fn run_that_lost_its_lock_stops_and_leaves_the_new_lock() {
        let db = Db::open_in_memory().unwrap();
        // This run's lease expired and another run took it.
        let mut held = "2000-01-01T00:00:00Z 1-1".to_string();
        let other = db.try_lease(RUN_LOCK_KEY, run_lock_ttl()).unwrap().unwrap();
        assert!(renew_run_lock(&db, &mut Some(&mut held)).is_err());
        db.release_lease(RUN_LOCK_KEY, &held).unwrap();
        assert_eq!(db.get_kv(RUN_LOCK_KEY).unwrap(), Some(other));
    }

    #[test]
    fn flush_stops_without_sending_when_the_lock_was_taken() {
        let (cfg, http) = (config(), Http::new(5).unwrap());
        let db = Db::open_in_memory().unwrap();
        outbox_with_one_urgent(&db);
        let mut held = "2000-01-01T00:00:00Z 1-1".to_string();
        db.try_lease(RUN_LOCK_KEY, run_lock_ttl()).unwrap().unwrap();
        let notifier = recorder(&http, vec![]);
        let mut s = RunSummary::default();
        assert!(flush_outbox(&cfg, &db, &notifier, &mut s, &mut Some(&mut held)).is_err());
        assert!(notifier.sent().is_empty());
        assert_eq!(db.queue_len(Queue::Outbox).unwrap(), 1);
    }
}
