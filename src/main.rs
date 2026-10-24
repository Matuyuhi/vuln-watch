mod app;
mod config;
mod db;
mod delegate;
mod discord;
mod doctor;
mod http;
mod installed;
mod model;
mod rules;
mod sources;
mod text;
mod upgrade;
mod watch;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::app::{RunOptions, Secrets};
use crate::config::Config;
use crate::db::Db;
use crate::discord::Notifier;
use crate::http::Http;

const DEFAULT_STATE_DIR: &str = "./state";
/// Present on hosts installed with deploy/install.sh; loaded only by the systemd unit,
/// so shell invocations there are re-run under systemd (see `delegate`).
const INSTALLED_ENV_FILE: &str = "/etc/vuln-watch/env";

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
    #[arg(long, env = "STATE_DIRECTORY", default_value = DEFAULT_STATE_DIR)]
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
    /// Diagnose this installation: binary, PATH, config, credentials, systemd and state
    Doctor {
        /// Skip the check for a newer release
        #[arg(long)]
        offline: bool,
    },
    /// Update this installation to the latest GitHub release (run as root)
    Upgrade {
        /// Only report whether an update is available
        #[arg(long)]
        check: bool,
        /// Install this version instead of the latest (e.g. 1.2.0; may downgrade)
        #[arg(long, value_name = "VERSION")]
        version: Option<String>,
        /// Include pre-releases (implied when running a pre-release)
        #[arg(long)]
        pre: bool,
        /// Reinstall even if already up to date
        #[arg(long)]
        force: bool,
    },
    /// List or edit the watch list in config.toml (editing needs write access, i.e. sudo)
    Watch {
        #[command(subcommand)]
        command: watch::WatchCommand,
    },
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
        Ok(code) => code,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

impl Command {
    /// The subcommand and flags, to re-run it under systemd. None: runs here.
    fn delegated_args(&self) -> Option<Vec<String>> {
        let flag = |on: bool, name: &str| on.then(|| name.to_string());
        Some(match self {
            Command::Run {
                dry_run,
                limit,
                strict,
            } => {
                let mut a = vec!["run".to_string()];
                if *dry_run {
                    a.extend(["--dry-run".to_string(), format!("--limit={limit}")]);
                }
                a.extend(flag(*strict, "--strict"));
                a
            }
            Command::Digest { dry_run } => ["digest".to_string()]
                .into_iter()
                .chain(flag(*dry_run, "--dry-run"))
                .collect(),
            Command::TestNotify => vec!["test-notify".to_string()],
            Command::CheckConfig => vec!["check-config".to_string()],
            Command::Doctor { .. } | Command::Upgrade { .. } | Command::Watch { .. } => {
                return None
            }
        })
    }
}

fn real_main() -> Result<ExitCode> {
    let cli = Cli::parse();
    // Needs no config, so it also works when the config is broken.
    if let Command::Upgrade {
        check,
        version,
        pre,
        force,
    } = cli.command
    {
        let http = Http::new(300)?;
        let token = std::env::var("GITHUB_TOKEN")
            .ok()
            .filter(|t| !t.trim().is_empty());
        let opts = upgrade::Options {
            check,
            version,
            pre,
            force,
        };
        upgrade::run(&http, token.as_deref(), &opts)?;
        return Ok(ExitCode::SUCCESS);
    }
    // Also needs no config: a broken config is one of the things it reports.
    if let Command::Doctor { offline } = cli.command {
        let http = Http::new(30)?;
        // Outside systemd the default ./state is rarely what was meant.
        let state_dir = (cli.state_dir != Path::new(DEFAULT_STATE_DIR)).then_some(cli.state_dir);
        let opts = doctor::Options {
            config: cli.config,
            state_dir,
            offline,
        };
        doctor::run(&http, &opts)?;
        return Ok(ExitCode::SUCCESS);
    }

    // Edits config.toml only: no credentials or state, so it runs here (as root to write).
    if let Command::Watch { command } = cli.command {
        watch::run(&cli.config, command)?;
        return Ok(ExitCode::SUCCESS);
    }

    // On an installed host the credentials and state belong to the systemd unit:
    // run there, with the output on this terminal. Inside the unit
    // $STATE_DIRECTORY is set, so this does not recurse.
    if cli.state_dir == Path::new(DEFAULT_STATE_DIR)
        && Path::new(INSTALLED_ENV_FILE).exists()
        && Path::new("/run/systemd/system").is_dir()
    {
        // A dry run needs no credentials or state, so it still works without sudo.
        let local_dry_run =
            matches!(cli.command, Command::Run { dry_run: true, .. }) && !doctor::is_root();
        if let Some(args) = cli.command.delegated_args().filter(|_| !local_dry_run) {
            return delegate::run(&cli.config, &args);
        }
    }

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
                for (m, _) in discord::digest_messages(&entries, false) {
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
        Command::Upgrade { .. } | Command::Doctor { .. } | Command::Watch { .. } => {
            unreachable!("handled above")
        }
    }
    Ok(ExitCode::SUCCESS)
}
