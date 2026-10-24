//! `vuln-watch doctor`: diagnose an installation.
//!
//! Looks for the problems that tend to show up after installing or upgrading:
//! a stale binary earlier on PATH, a config that no longer parses, missing
//! credentials in /etc/vuln-watch/env, timers that are not running, and
//! sources that keep failing. Sends nothing; the only network access is the
//! release check, skipped with `--offline`.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::app::{self, Secrets};
use crate::config::{Config, DeliveryMode};
use crate::db::{Db, Queue};
use crate::http::Http;
use crate::installed::Installed;
use crate::upgrade;

const INSTALLED_BIN: &str = "/usr/local/bin/vuln-watch";
const ENV_FILE: &str = "/etc/vuln-watch/env";
/// Where systemd's StateDirectory puts state.db (a link into /var/lib/private).
const SYSTEMD_STATE_DIR: &str = "/var/lib/vuln-watch";
const UNIT_DIR: &str = "/etc/systemd/system";
const SERVICE_UNIT: &str = "vuln-watch@.service";
const TIMERS: [&str; 2] = ["vuln-watch-run.timer", "vuln-watch-digest.timer"];
const BUNDLED_SERVICE: &str = include_str!("../deploy/systemd/vuln-watch@.service");

pub struct Options {
    pub config: PathBuf,
    /// None: the systemd state directory.
    pub state_dir: Option<PathBuf>,
    /// Skip the release check.
    pub offline: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Ok,
    Warn,
    Fail,
    Skip,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Status::Ok => "ok",
            Status::Warn => "warn",
            Status::Fail => "FAIL",
            Status::Skip => "skip",
        })
    }
}

#[derive(Default)]
struct Report {
    fails: usize,
    warns: usize,
}

impl Report {
    fn add(&mut self, status: Status, name: &str, detail: impl fmt::Display, hint: Option<&str>) {
        match status {
            Status::Fail => self.fails += 1,
            Status::Warn => self.warns += 1,
            Status::Ok | Status::Skip => {}
        }
        println!("{status:<5} {name:<10} {detail}");
        if let Some(h) = hint {
            println!("{:<17}-> {h}", "");
        }
    }

    fn ok(&mut self, name: &str, detail: impl fmt::Display) {
        self.add(Status::Ok, name, detail, None);
    }
    fn warn(&mut self, name: &str, detail: impl fmt::Display, hint: Option<&str>) {
        self.add(Status::Warn, name, detail, hint);
    }
    fn fail(&mut self, name: &str, detail: impl fmt::Display, hint: Option<&str>) {
        self.add(Status::Fail, name, detail, hint);
    }
    fn skip(&mut self, name: &str, detail: impl fmt::Display) {
        self.add(Status::Skip, name, detail, None);
    }
}

pub fn run(http: &Http, opts: &Options) -> Result<()> {
    let root = is_root();
    if !root {
        println!("note: not running as root; some files cannot be read (sudo vuln-watch doctor)\n");
    }
    let mut r = Report::default();

    check_binary(&mut r);
    let file_env = check_env_file(&mut r);
    let secrets = file_env
        .as_ref()
        .map(secrets_from)
        .unwrap_or_else(Secrets::from_env);
    if !opts.offline {
        check_latest(&mut r, http, secrets.github_token.as_deref());
    }
    let cfg = check_config(&mut r, &opts.config);
    if let Some(cfg) = &cfg {
        check_credentials(&mut r, cfg, &secrets, file_env.is_some());
        check_installed(&mut r, cfg);
    }
    check_systemd(&mut r);
    let state_dir = opts
        .state_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(SYSTEMD_STATE_DIR));
    check_state(&mut r, &state_dir.join("state.db"), cfg.as_ref(), root);
    check_upgrade_leftovers(&mut r);

    println!();
    if r.fails > 0 {
        bail!("{} problem(s), {} warning(s)", r.fails, r.warns);
    }
    println!("no problems found ({} warning(s))", r.warns);
    Ok(())
}

fn is_root() -> bool {
    fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

fn version_of(bin: &Path) -> Option<String> {
    let out = Command::new(bin).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    Some(
        text.trim()
            .trim_start_matches("vuln-watch")
            .trim()
            .to_string(),
    )
}

fn check_binary(r: &mut Report) {
    let installed = Path::new(INSTALLED_BIN);
    let current = std::env::current_exe().ok();
    let this = env!("CARGO_PKG_VERSION");

    if !installed.exists() {
        r.fail(
            "binary",
            format!("{INSTALLED_BIN} not found (running {this})"),
            Some("install with install.sh or deploy/install.sh; the systemd units run this path"),
        );
    } else if current.as_deref().and_then(|p| p.canonicalize().ok())
        == installed.canonicalize().ok()
    {
        r.ok("binary", format!("{INSTALLED_BIN} ({this})"));
    } else {
        let v = version_of(installed).unwrap_or_else(|| "unknown version".into());
        let status = if v == this { Status::Ok } else { Status::Warn };
        let shown = current
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "?".into());
        r.add(
            status,
            "binary",
            format!("running {shown} ({this}); systemd uses {INSTALLED_BIN} ({v})"),
            (status == Status::Warn).then_some("run doctor from the installed binary"),
        );
    }

    let path = std::env::var_os("PATH").unwrap_or_default();
    let found = find_in_path(&path, "vuln-watch");
    let shadowed: Vec<_> = found
        .iter()
        .take_while(|p| !same_file(p, installed))
        .collect();
    if found.is_empty() {
        r.warn(
            "path",
            "vuln-watch is not on PATH",
            Some("add /usr/local/bin to PATH"),
        );
    } else if shadowed.is_empty() {
        r.ok(
            "path",
            format!("{} comes first on PATH", found[0].display()),
        );
    } else {
        let list = shadowed
            .iter()
            .map(|p| {
                let v = version_of(p).unwrap_or_else(|| "?".into());
                format!("{} ({v})", p.display())
            })
            .collect::<Vec<_>>()
            .join(", ");
        r.warn(
            "path",
            format!("found before {INSTALLED_BIN}: {list}"),
            Some("remove the old binary so `vuln-watch` runs the installed version"),
        );
    }
}

/// Executables called `name` in the directories of `path`, in PATH order.
fn find_in_path(path: &OsStr, name: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for dir in std::env::split_paths(path) {
        let p = dir.join(name);
        let executable = fs::metadata(&p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false);
        if executable && !out.iter().any(|q| same_file(q, &p)) {
            out.push(p);
        }
    }
    out
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

fn check_latest(r: &mut Report, http: &Http, token: Option<&str>) {
    let current = match upgrade::parse_version(env!("CARGO_PKG_VERSION")) {
        Ok(v) => v,
        Err(e) => return r.warn("version", format!("{e:#}"), None),
    };
    match upgrade::latest(http, token, !current.pre.is_empty()) {
        Ok(Some(latest)) if latest > current => r.warn(
            "version",
            format!("{current} installed, {latest} available"),
            Some("sudo vuln-watch upgrade"),
        ),
        Ok(Some(latest)) => r.ok("version", format!("{current} (latest: {latest})")),
        Ok(None) => r.ok("version", format!("{current} (no newer release)")),
        Err(e) => r.warn(
            "version",
            format!("could not check for releases: {e:#}"),
            Some("use --offline to skip this check"),
        ),
    }
}

/// Parse a systemd EnvironmentFile. Empty values count as unset, as in `Secrets::from_env`.
fn parse_env_file(text: &str) -> HashMap<String, String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';'))
        .filter_map(|l| {
            let (k, v) = l.split_once('=')?;
            let k = k.trim().trim_start_matches("export ").trim();
            let v = v.trim();
            (!v.is_empty()).then(|| (k.to_string(), v.to_string()))
        })
        .collect()
}

fn secrets_from(env: &HashMap<String, String>) -> Secrets {
    let get = |k: &str| env.get(k).cloned();
    Secrets {
        bot_token: get("DISCORD_BOT_TOKEN"),
        webhook_url: get("DISCORD_WEBHOOK_URL"),
        user_id: get("DISCORD_USER_ID"),
        github_token: get("GITHUB_TOKEN"),
        heartbeat_url: get("HEARTBEAT_URL"),
    }
}

/// Checks /etc/vuln-watch/env and returns its variables when readable.
fn check_env_file(r: &mut Report) -> Option<HashMap<String, String>> {
    let path = Path::new(ENV_FILE);
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            r.fail(
                "env",
                format!("{ENV_FILE} not found"),
                Some("copy deploy/env.example there (mode 600) or re-run install.sh"),
            );
            return None;
        }
        Err(e) => {
            r.warn("env", format!("{ENV_FILE}: {e}"), None);
            return None;
        }
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 || meta.uid() != 0 {
        r.warn(
            "env",
            format!("{ENV_FILE} is mode {mode:o}, owner uid {}", meta.uid()),
            Some(&format!(
                "it holds tokens: sudo chown root:root {ENV_FILE} && sudo chmod 600 {ENV_FILE}"
            )),
        );
    }
    match fs::read_to_string(path) {
        Ok(text) => {
            if mode & 0o077 == 0 && meta.uid() == 0 {
                r.ok("env", format!("{ENV_FILE} (mode 600)"));
            }
            Some(parse_env_file(&text))
        }
        Err(e) => {
            r.warn(
                "env",
                format!("cannot read {ENV_FILE}: {e}"),
                Some("run as root to check the credentials in it"),
            );
            None
        }
    }
}

fn check_config(r: &mut Report, path: &Path) -> Option<Config> {
    if !path.exists() {
        r.fail(
            "config",
            format!("{} not found", path.display()),
            Some("copy config.example.toml there, re-run install.sh, or pass --config"),
        );
        return None;
    }
    match Config::load(path) {
        Ok(cfg) => {
            let enabled = cfg.sources.iter().filter(|s| s.enabled).count();
            r.ok(
                "config",
                format!(
                    "{} ({enabled} sources enabled, {} watches)",
                    path.display(),
                    cfg.watches.len()
                ),
            );
            Some(cfg)
        }
        Err(e) => {
            r.fail(
                "config",
                format!("{e:#}"),
                Some(
                    "compare with config.example.toml and CHANGELOG.md for renamed or removed keys",
                ),
            );
            None
        }
    }
}

fn check_credentials(r: &mut Report, cfg: &Config, secrets: &Secrets, from_file: bool) {
    let source = if from_file {
        ENV_FILE
    } else {
        "the environment"
    };
    let user_id = secrets.user_id.as_ref().or(cfg.discord.user_id.as_ref());
    let placeholder = user_id.is_some_and(|id| id.chars().all(|c| c == '0'));
    match app::build_target(cfg, secrets, false) {
        Ok(_) if placeholder && cfg.discord.mode == DeliveryMode::Dm => r.fail(
            "discord",
            "the Discord user id is still the example value",
            Some("set discord.user_id in config.toml or DISCORD_USER_ID in /etc/vuln-watch/env"),
        ),
        Ok(_) => r.ok(
            "discord",
            format!("{:?} delivery configured", cfg.discord.mode).to_lowercase(),
        ),
        Err(e) if from_file => r.fail(
            "discord",
            format!("{e:#}"),
            Some("set it in /etc/vuln-watch/env (or discord.user_id in config.toml)"),
        ),
        // Without the env file we only see the shell's environment, which systemd does not use.
        Err(e) => r.warn("discord", format!("{e:#} (checked {source})"), None),
    }
    if secrets.github_token.is_some() {
        r.ok("github", "GITHUB_TOKEN set");
    } else {
        r.warn(
            "github",
            format!("GITHUB_TOKEN not set in {source}"),
            Some("recommended: raises the API limit and reads the CVE List via the API"),
        );
    }
}

fn check_installed(r: &mut Report, cfg: &Config) {
    if !cfg.installed.enabled {
        return r.skip("installed", "installed.enabled = false");
    }
    match Installed::load(&cfg.installed) {
        Ok(i) => r.ok(
            "installed",
            format!(
                "{} packages (release: {})",
                i.package_count(),
                i.release.as_deref().unwrap_or("unknown")
            ),
        ),
        Err(e) => r.fail(
            "installed",
            format!("{e:#}"),
            Some("set installed.enabled = false on machines without dpkg"),
        ),
    }
}

/// `systemctl show` output as key/value pairs.
fn parse_show(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn systemctl_show(unit: &str, props: &str) -> Result<HashMap<String, String>> {
    let out = Command::new("systemctl")
        .args(["show", unit, "-p", props])
        .output()
        .context("running systemctl")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!(
            "systemctl show {unit}: {}",
            err.lines().next().unwrap_or("").trim()
        );
    }
    Ok(parse_show(&String::from_utf8_lossy(&out.stdout)))
}

fn check_systemd(r: &mut Report) {
    let service = Path::new(UNIT_DIR).join(SERVICE_UNIT);
    let missing: Vec<_> = std::iter::once(SERVICE_UNIT)
        .chain(TIMERS)
        .filter(|u| !Path::new(UNIT_DIR).join(u).exists())
        .collect();
    if !missing.is_empty() {
        r.fail(
            "systemd",
            format!("missing in {UNIT_DIR}: {}", missing.join(", ")),
            Some("re-run install.sh or deploy/install.sh"),
        );
    } else {
        match fs::read_to_string(&service) {
            Ok(text) if text == BUNDLED_SERVICE => r.ok("systemd", "unit files installed"),
            Ok(_) => r.warn(
                "systemd",
                format!("{} differs from this version's", service.display()),
                Some("expected if you edited it; otherwise re-run deploy/install.sh"),
            ),
            Err(e) => r.warn("systemd", format!("{}: {e}", service.display()), None),
        }
    }

    // Same test as sd_booted(3).
    if !Path::new("/run/systemd/system").is_dir() {
        return r.skip("systemd", "systemd is not running; timers not checked");
    }

    for timer in TIMERS {
        let props = match systemctl_show(
            timer,
            "LoadState,UnitFileState,ActiveState,NeedDaemonReload",
        ) {
            Ok(p) => p,
            Err(e) => {
                r.warn("timer", format!("{e:#}"), None);
                continue;
            }
        };
        let get = |k: &str| props.get(k).map(String::as_str).unwrap_or("");
        if get("LoadState") != "loaded" {
            continue; // already reported as a missing unit
        }
        if get("NeedDaemonReload") == "yes" {
            r.warn(
                "timer",
                format!("{timer} changed on disk"),
                Some("sudo systemctl daemon-reload"),
            );
        }
        if get("UnitFileState") == "enabled" && get("ActiveState") == "active" {
            r.ok("timer", format!("{timer} enabled and active"));
        } else {
            r.fail(
                "timer",
                format!(
                    "{timer} is {} / {}",
                    get("UnitFileState"),
                    get("ActiveState")
                ),
                Some(&format!("sudo systemctl enable --now {timer}")),
            );
        }
    }

    for unit in ["vuln-watch@run.service", "vuln-watch@digest.service"] {
        let props = match systemctl_show(unit, "Result,ExecMainStatus,ExecMainExitTimestamp") {
            Ok(p) => p,
            Err(e) => {
                r.warn("last run", format!("{e:#}"), None);
                continue;
            }
        };
        let get = |k: &str| props.get(k).map(String::as_str).unwrap_or("");
        let at = get("ExecMainExitTimestamp");
        if at.is_empty() {
            r.skip("last run", format!("{unit} has not run since boot"));
        } else if get("Result") == "success" {
            r.ok("last run", format!("{unit} succeeded ({at})"));
        } else {
            r.fail(
                "last run",
                format!(
                    "{unit} failed ({}, exit status {}, {at})",
                    get("Result"),
                    get("ExecMainStatus")
                ),
                Some(&format!("journalctl -u {unit} -n 50")),
            );
        }
    }
}

fn check_state(r: &mut Report, db_path: &Path, cfg: Option<&Config>, root: bool) {
    match fs::metadata(db_path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return r.warn(
                "state",
                format!("{} not found (no successful run yet?)", db_path.display()),
                Some("sudo systemctl start vuln-watch@run.service"),
            );
        }
        Err(e) if !root => {
            return r.skip("state", format!("{}: {e} (run as root)", db_path.display()));
        }
        Err(e) => return r.warn("state", format!("{}: {e}", db_path.display()), None),
    }
    let summary = Db::open_read_only(db_path).and_then(|db| {
        let failing = db.kv_with_prefix("fail:")?;
        let outbox = db.queue_len(Queue::Outbox)?;
        let digest = db.queue_len(Queue::Digest)?;
        Ok((failing, outbox, digest))
    });
    let (failing, outbox, digest) = match summary {
        Ok(s) => s,
        Err(e) => return r.fail("state", format!("{e:#}"), None),
    };
    r.ok(
        "state",
        format!("{} ({digest} queued for the digest)", db_path.display()),
    );
    let threshold = cfg.map(|c| c.runtime.alert_after_failures).unwrap_or(1);
    for (key, count) in failing {
        let name = key.trim_start_matches("fail:");
        let count: u32 = count.parse().unwrap_or(0);
        let detail = format!("source `{name}` failed {count} time(s) in a row");
        let hint = Some("journalctl -u vuln-watch@run -n 100");
        if count >= threshold {
            r.fail("source", detail, hint);
        } else {
            r.warn("source", detail, hint);
        }
    }
    if outbox > 0 {
        r.warn(
            "outbox",
            format!("{outbox} urgent message(s) not delivered yet"),
            Some("check the Discord credentials, then sudo vuln-watch test-notify"),
        );
    }
}

fn check_upgrade_leftovers(r: &mut Report) {
    let tmp = std::env::temp_dir();
    let leftovers: Vec<_> = fs::read_dir(&tmp)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with("vuln-watch-upgrade-")
                })
                .map(|e| e.path().display().to_string())
                .collect()
        })
        .unwrap_or_default();
    if leftovers.is_empty() {
        r.ok("upgrade", "no leftovers from an interrupted upgrade");
    } else {
        r.warn(
            "upgrade",
            format!("leftover directories: {}", leftovers.join(", ")),
            Some("an upgrade was interrupted; remove them and run sudo vuln-watch upgrade --force"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn parses_env_file() {
        let env = parse_env_file(
            "# comment\n\
             DISCORD_BOT_TOKEN=abc=def\n\
             DISCORD_USER_ID=\n\
             ; other comment\n\
             export GITHUB_TOKEN = ghp_x \n\
             garbage\n",
        );
        assert_eq!(
            env.get("DISCORD_BOT_TOKEN").map(String::as_str),
            Some("abc=def")
        );
        assert_eq!(env.get("GITHUB_TOKEN").map(String::as_str), Some("ghp_x"));
        assert!(!env.contains_key("DISCORD_USER_ID"));
        assert_eq!(env.len(), 2);
    }

    #[test]
    fn parses_systemctl_show() {
        let p = parse_show("Result=success\nExecMainExitTimestamp=\nExecMainStatus=0\n");
        assert_eq!(p["Result"], "success");
        assert_eq!(p["ExecMainExitTimestamp"], "");
    }

    #[test]
    fn finds_executables_in_path_order() {
        let base =
            std::env::temp_dir().join(format!("vuln-watch-doctor-test-{}", std::process::id()));
        let (a, b, c) = (base.join("a"), base.join("b"), base.join("c"));
        for d in [&a, &b, &c] {
            fs::create_dir_all(d).unwrap();
        }
        for (d, mode) in [(&a, 0o755), (&b, 0o644), (&c, 0o755)] {
            let p = d.join("vuln-watch");
            fs::write(&p, "").unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        }
        let path: OsString = std::env::join_paths([&c, &b, &a, &c]).unwrap();
        let found = find_in_path(&path, "vuln-watch");
        fs::remove_dir_all(&base).unwrap();
        assert_eq!(found, vec![c.join("vuln-watch"), a.join("vuln-watch")]);
    }
}
