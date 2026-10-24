mod app;
mod config;
mod db;
mod discord;
mod http;
mod installed;
mod model;
mod rules;
mod sources;
mod text;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::app::{RunOptions, Secrets};
use crate::config::Config;
use crate::db::Db;
use crate::discord::Notifier;
use crate::http::Http;

#[derive(Parser)]
#[command(
    version,
    about = "Watch vulnerability feeds and notify Discord as fast as possible"
)]
struct Cli {
    /// Path to config.toml
    #[arg(
        short,
        long,
        env = "VULN_WATCH_CONFIG",
        default_value = "/etc/vuln-watch/config.toml"
    )]
    config: PathBuf,

    /// Directory for state.db (systemd's StateDirectory sets $STATE_DIRECTORY)
    #[arg(long, env = "STATE_DIRECTORY", default_value = "./state")]
    state_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Poll all sources once, send urgent notifications and queue digest items
    Run {
        /// Print what would be sent without sending or saving state
        #[arg(long)]
        dry_run: bool,
        /// With --dry-run: max items evaluated per source
        #[arg(long, default_value_t = 5)]
        limit: usize,
        /// Exit with an error when any source fails
        #[arg(long)]
        strict: bool,
    },
    /// Send the queued digest
    Digest {
        /// Print the digest without sending or clearing it
        #[arg(long)]
        dry_run: bool,
    },
    /// Send a test notification to verify the Discord setup
    TestNotify,
    /// Validate the configuration and print a summary
    CheckConfig,
}

fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // Under systemd, journald adds its own timestamps.
    let journald = std::env::var_os("JOURNAL_STREAM").is_some();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(!journald)
        .with_target(false);
    if journald {
        builder.without_time().init();
    } else {
        builder.init();
    }
}

fn main() -> ExitCode {
    init_logging();
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)?;
    let secrets = Secrets::from_env();
    let http = Http::new(cfg.runtime.http_timeout_secs)?;
    let db_path = cli.state_dir.join("state.db");

    match cli.command {
        Command::Run {
            dry_run,
            limit,
            strict,
        } => {
            let mut db = if dry_run {
                Db::open_in_memory()?
            } else {
                Db::open(&db_path)?
            };
            let notifier = Notifier::new(&http, app::build_target(&cfg, &secrets, dry_run)?);
            let opts = RunOptions {
                dry_run,
                limit: dry_run.then_some(limit),
                strict,
            };
            app::run(&cfg, &mut db, &http, &notifier, &secrets, &opts)?;
        }
        Command::Digest { dry_run } => {
            let db = Db::open(&db_path)?;
            let notifier = Notifier::new(&http, app::build_target(&cfg, &secrets, dry_run)?);
            if dry_run {
                let entries = db.queue_entries(db::Queue::Digest)?;
                for m in discord::digest_messages(&entries) {
                    notifier.send(&db, &m)?;
                }
                println!("{} items queued (not cleared)", entries.len());
            } else {
                app::digest(&cfg, &db, &notifier)?;
            }
        }
        Command::TestNotify => {
            let db = Db::open(&db_path)?;
            let notifier = Notifier::new(&http, app::build_target(&cfg, &secrets, false)?);
            notifier
                .send(&db, &app::test_message())
                .context("test notification failed")?;
            println!("test notification sent");
        }
        Command::CheckConfig => {
            println!("config: {}", cli.config.display());
            println!("delivery: {:?}", cfg.discord.mode);
            for s in &cfg.sources {
                println!(
                    "source: {:<16} kind={:<8} mode={:?} enabled={}{}",
                    s.name(),
                    s.kind.as_str(),
                    s.mode,
                    s.enabled,
                    s.url
                        .as_deref()
                        .map(|u| format!(" url={u}"))
                        .unwrap_or_default()
                );
            }
            for w in &cfg.watches {
                println!(
                    "watch: {:<20} keywords={:?} packages={:?}",
                    w.name,
                    w.effective_keywords(),
                    w.packages
                );
            }
            if cfg.installed.enabled {
                match installed::Installed::load(&cfg.installed) {
                    Ok(i) => println!(
                        "installed packages: {} (release: {})",
                        i.package_count(),
                        i.release.as_deref().unwrap_or("unknown")
                    ),
                    Err(e) => println!("installed packages: error ({e:#})"),
                }
            } else {
                println!("installed packages: disabled");
            }
            let target = app::build_target(&cfg, &secrets, false);
            println!(
                "discord credentials: {}",
                match &target {
                    Ok(_) => "ok".to_string(),
                    Err(e) => format!("missing ({e})"),
                }
            );
            println!(
                "github token: {}",
                if secrets.github_token.is_some() {
                    "set"
                } else {
                    "not set (rate limited, CVE List via CDN)"
                }
            );
            target?;
        }
    }
    Ok(())
}
