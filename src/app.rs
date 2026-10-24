use anyhow::{Context, Result};

use crate::config::{Config, DeliveryMode, SourceConfig};
use crate::db::Db;
use crate::discord::{self, Message, Notifier, Target};
use crate::http::Http;
use crate::model::{Decision, Item, Level};
use crate::rules;
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

struct Candidate {
    item: Item,
    decision: Decision,
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
    let mut urgent: Vec<Candidate> = Vec::new();

    for src in cfg.sources.iter().filter(|s| s.enabled) {
        let name = src.name();
        match process_source(cfg, db, http, secrets, opts, src, &mut summary, &mut urgent) {
            Ok(()) => source_succeeded(db, notifier, &name, opts.dry_run)?,
            Err(e) => {
                tracing::warn!("source {name} failed: {e:#}");
                summary.failed_sources.push(name.clone());
                source_failed(cfg, db, notifier, &name, &e, opts.dry_run)?;
            }
        }
    }

    // Send urgent notifications (bounded), overflow goes to the digest.
    let max = cfg.runtime.max_urgent_per_run;
    let overflow = urgent.len().saturating_sub(max);
    for (i, c) in urgent.into_iter().enumerate() {
        let key = c.item.dedupe_key();
        if i < max {
            notifier
                .send(db, &discord::urgent_message(&c.item, &c.decision))
                .with_context(|| format!("sending notification for {}", c.item.display_id()))?;
            if i + 1 < max {
                std::thread::sleep(std::time::Duration::from_millis(if opts.dry_run {
                    0
                } else {
                    600
                }));
            }
            db.set_alerted(&key, Level::Urgent)?;
            db.remove_digest(&key)?;
            summary.urgent += 1;
        } else {
            db.enqueue_digest(
                &key,
                &c.item,
                &format!("{}（即時通知の上限超過）", c.decision.reason),
            )?;
            db.set_alerted(&key, Level::Digest)?;
            summary.digested += 1;
        }
        db.mark_seen(&c.item.source, &c.item.id)?;
    }
    if overflow > 0 {
        notifier.send(
            db,
            &Message::text(format!(
                "⚠️ 即時通知が上限（{max}件/回）を超えたため、残り{overflow}件はダイジェストに回しました。"
            )),
        )?;
    }

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

#[allow(clippy::too_many_arguments)]
fn process_source(
    cfg: &Config,
    db: &mut Db,
    http: &Http,
    secrets: &Secrets,
    opts: &RunOptions,
    src: &SourceConfig,
    summary: &mut RunSummary,
    urgent: &mut Vec<Candidate>,
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
        let decision = rules::evaluate(&item, src.mode, &cfg.rules, &cfg.watches);
        if opts.dry_run {
            println!(
                "[{name}] {:<7} {} — {} ({})",
                format!("{:?}", decision.level),
                item.display_id(),
                truncate(&item.title, 80),
                decision.reason
            );
        }
        let key = item.dedupe_key();
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
                db.enqueue_digest(&key, &item, &decision.reason)?;
                db.set_alerted(&key, Level::Digest)?;
                db.mark_seen(&name, &item.id)?;
                summary.digested += 1;
            }
            Level::Urgent => {
                // Marked seen after it has actually been sent.
                if !urgent.iter().any(|c| c.item.dedupe_key() == key) {
                    urgent.push(Candidate { item, decision });
                } else {
                    db.mark_seen(&name, &item.id)?;
                }
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
    let entries = db.digest_entries()?;
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
        db.remove_digest(&e.key)?;
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
