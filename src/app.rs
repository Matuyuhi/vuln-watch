use anyhow::{Context, Result};

use crate::config::{Config, DeliveryMode, SourceConfig};
use crate::db::{Db, Queue};
use crate::discord::{self, Message, Notifier, Target};
use crate::http::Http;
use crate::installed::Installed;
use crate::model::{Decision, Item, Level};
use crate::rules::{self, InstalledMatch};
use crate::sources::{self, Ctx};
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
}

pub fn run(
    cfg: &Config,
    db: &mut Db,
    http: &Http,
    notifier: &Notifier,
    secrets: &Secrets,
    opts: &RunOptions,
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
        match process_source(
            cfg,
            db,
            http,
            secrets,
            opts,
            src,
            installed_match.as_ref(),
            &mut summary,
        ) {
            Ok(()) => source_succeeded(db, notifier, &name, opts.dry_run)?,
            Err(e) => {
                tracing::warn!("source {name} failed: {e:#}");
                summary.failed_sources.push(name.clone());
                source_failed(cfg, db, notifier, &name, &e, opts.dry_run)?;
            }
        }
    }

    flush_outbox(cfg, db, notifier, opts, &mut summary)?;

    if !opts.dry_run {
        let hb = secrets
            .heartbeat_url
            .clone()
            .or_else(|| cfg.runtime.heartbeat_url.clone());
        if let Some(url) = hb {
            if let Err(e) = http.get(&url, &[], None) {
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
    opts: &RunOptions,
    summary: &mut RunSummary,
) -> Result<()> {
    let entries = db.queue_entries(Queue::Outbox)?;
    let max = cfg.runtime.max_urgent_per_run;
    let overflow = entries.len().saturating_sub(max);
    for (i, e) in entries.into_iter().enumerate() {
        if i < max {
            if i > 0 && !opts.dry_run {
                std::thread::sleep(std::time::Duration::from_millis(600));
            }
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
) -> Result<()> {
    let name = src.name();
    let init_key = format!("init:{name}");
    let bootstrap = !opts.dry_run && db.get_kv(&init_key)?.is_none();

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

    if bootstrap {
        let n = db.mark_seen_many(&name, fetched.items.iter().map(|i| i.id.as_str()))?;
        for (k, v) in &fetched.commit {
            db.set_kv(k, v)?;
        }
        db.set_kv(&init_key, &chrono::Utc::now().to_rfc3339())?;
        tracing::info!("{name}: first run, recorded {n} existing items without notifying");
        summary.bootstrapped += n;
        return Ok(());
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
    tracing::info!("{name}: {total} fetched, {new} new");
    Ok(())
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

pub fn digest(cfg: &Config, db: &Db, notifier: &Notifier) -> Result<usize> {
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
    let msgs = discord::digest_messages(&entries);
    notifier.send_all(db, &msgs)?;
    for e in &entries {
        db.dequeue(Queue::Digest, &e.key)?;
    }
    tracing::info!(
        "digest: sent {} items in {} messages",
        entries.len(),
        msgs.len()
    );
    Ok(entries.len())
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
