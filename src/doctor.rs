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
pub(crate) const SYSTEMD_STATE_DIR: &str = "/var/lib/vuln-watch";
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
        check_heartbeat(&mut r, cfg, &secrets, file_env.is_some());
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

pub(crate) fn is_root() -> bool {
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
            let k = k.trim();
            let v = unquote_env_value(v.trim());
            // Like `Secrets::from_env`, a blank value (also `"  "`) is unset.
            (!v.trim().is_empty()).then(|| (k.to_string(), v))
        })
        .collect()
}

/// systemd removes quotes around a whole EnvironmentFile value (`KEY="v"` / `KEY='v'`) and,
/// inside double quotes, the backslash before `"` and `\`; do the same so doctor sees the value
/// the service gets.
fn unquote_env_value(v: &str) -> String {
    let quoted = |q: char| v.len() >= 2 && v.starts_with(q) && v.ends_with(q);
    if quoted('\'') {
        v[1..v.len() - 1].to_string()
    } else if quoted('"') {
        let mut out = String::new();
        let mut chars = v[1..v.len() - 1].chars();
        while let Some(c) = chars.next() {
            match (c, chars.clone().next()) {
                ('\\', Some(n @ ('"' | '\\'))) => {
                    out.push(n);
                    chars.next();
                }
                _ => out.push(c),
            }
        }
        out
    } else {
        v.to_string()
    }
}

/// Variables vuln-watch (or its HTTP client) reads from the environment.
const KNOWN_ENV: &[&str] = &[
    "DISCORD_BOT_TOKEN",
    "DISCORD_USER_ID",
    "DISCORD_WEBHOOK_URL",
    "GITHUB_TOKEN",
    "HEARTBEAT_URL",
    "RUST_LOG",
    "VULN_WATCH_CONFIG",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
];

#[derive(Debug, PartialEq, Eq)]
enum EnvIssue {
    /// Not `KEY=value`; systemd skips the line. `head` is the text before `=`,
    /// or, for a line without `=`, a known variable name it starts with
    /// (`GITHUB_TOKEN: x`); otherwise nothing from the line is kept.
    Invalid { line: usize, head: Option<String> },
    /// A config.toml setting written into the env file: the text before `=`,
    /// or a `[section]` header.
    ConfigKey { line: usize, head: String },
    /// Well-formed but not a variable vuln-watch reads (often a typo).
    Unknown { line: usize, key: String },
}

/// Lines of an EnvironmentFile that do not do what was probably meant.
///
/// Values (tokens) are never printed: for a `KEY=value` line only the part
/// before `=` is kept. A line without `=` is often a secret pasted on its own
/// line, so text from it is kept only when it is a `[section]` header or
/// starts with a variable name vuln-watch reads followed by `:` or a space.
fn lint_env_file(text: &str) -> Vec<EnvIssue> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        let Some((key, _)) = l.split_once('=') else {
            out.push(lint_line_without_eq(line, l));
            continue;
        };
        let key = key.trim();
        let valid = !key.is_empty()
            && key
                .chars()
                .enumerate()
                .all(|(i, c)| c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()));
        if valid {
            if !is_known_env(key) {
                out.push(EnvIssue::Unknown {
                    line,
                    key: key.to_string(),
                });
            }
            continue;
        }
        let head: String = key.chars().take(40).collect();
        let config_like = head.starts_with('[')
            || head.contains('.')
            || (!head.is_empty() && head.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        if config_like {
            out.push(EnvIssue::ConfigKey { line, head });
        } else {
            out.push(EnvIssue::Invalid {
                line,
                head: Some(head),
            });
        }
    }
    out
}

fn is_known_env(name: &str) -> bool {
    KNOWN_ENV
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
}

/// A line without `=`. Only text that cannot be a secret is kept.
fn lint_line_without_eq(line: usize, l: &str) -> EnvIssue {
    let section = l
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .filter(|name| {
            !name.is_empty()
                && name.len() <= 38
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        });
    if section.is_some() {
        return EnvIssue::ConfigKey {
            line,
            head: l.to_string(),
        };
    }
    let first = l.split([':', ' ', '\t']).next().unwrap_or("");
    let head = (first.len() < l.len() && is_known_env(first)).then(|| first.to_string());
    EnvIssue::Invalid { line, head }
}

fn report_env_issues(r: &mut Report, issues: &[EnvIssue]) {
    for issue in issues {
        let (detail, hint) = env_issue_text(issue);
        r.warn("env", detail, Some(&hint));
    }
}

/// The warning and hint printed for an issue.
fn env_issue_text(issue: &EnvIssue) -> (String, String) {
    match issue {
        EnvIssue::Invalid {
            line,
            head: Some(head),
        } => (
            format!("{ENV_FILE} line {line}: `{head}` is not KEY=value; systemd ignores it"),
            "write it as KEY=value without quotes or `export`, or comment it out with #".into(),
        ),
        EnvIssue::Invalid { line, head: None } => (
            format!(
                "{ENV_FILE} line {line}: not KEY=value; systemd ignores it \
                 (a token pasted on its own line?)"
            ),
            "write it as KEY=value on one line (e.g. GITHUB_TOKEN=...), or comment it out with #"
                .into(),
        ),
        EnvIssue::ConfigKey { line, head } => (
            format!("{ENV_FILE} line {line}: `{head}` looks like a config.toml setting; systemd ignores it"),
            "move it to /etc/vuln-watch/config.toml (e.g. `mode` under [discord])".into(),
        ),
        EnvIssue::Unknown { line, key } => (
            format!("{ENV_FILE} line {line}: `{key}` is not used by vuln-watch (typo?)"),
            format!("known variables: {}", KNOWN_ENV[..5].join(", ")),
        ),
    }
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
            report_env_issues(r, &lint_env_file(&text));
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

/// Heartbeat findings as (status, detail, hint). The URL embeds a token and is never printed.
fn heartbeat_findings(
    cfg: &Config,
    secrets: &Secrets,
    from_file: bool,
) -> Vec<(Status, String, Option<String>)> {
    let source = if from_file {
        ENV_FILE
    } else {
        "the environment"
    };
    let mut out = Vec::new();
    if cfg.runtime.heartbeat_url.is_some() {
        out.push((
            Status::Warn,
            "runtime.heartbeat_url is set in config.toml, which every local user can read \
             (anyone who knows it can keep the heartbeat green)"
                .to_string(),
            Some(format!(
                "move it to HEARTBEAT_URL in {ENV_FILE} (mode 600) and remove it from config.toml"
            )),
        ));
    }
    match app::heartbeat(
        secrets.heartbeat_url.as_deref(),
        cfg.runtime.heartbeat_url.as_deref(),
    ) {
        app::Heartbeat::Env(_) => {
            out.push((Status::Ok, format!("HEARTBEAT_URL set in {source}"), None))
        }
        app::Heartbeat::Insecure => out.push((
            // Without the env file we only see the shell's environment, which systemd does not use.
            if from_file {
                Status::Fail
            } else {
                Status::Warn
            },
            format!(
                "HEARTBEAT_URL in {source} does not start with https:// ({}); it is not pinged",
                crate::config::url_scheme(secrets.heartbeat_url.as_deref().unwrap_or(""))
            ),
            Some("use the https:// check-in URL; over http the token is sent in clear text".into()),
        )),
        app::Heartbeat::Config(_) | app::Heartbeat::None => {}
    }
    out
}

fn check_heartbeat(r: &mut Report, cfg: &Config, secrets: &Secrets, from_file: bool) {
    for (status, detail, hint) in heartbeat_findings(cfg, secrets, from_file) {
        r.add(status, "heartbeat", detail, hint.as_deref());
    }
}

fn check_installed(r: &mut Report, cfg: &Config) {
    if !cfg.installed.enabled {
        return r.skip("installed", "installed.enabled = false");
    }
    match Installed::load(&cfg.installed) {
        Ok(i) => {
            let kernel = match (i.kernel.as_deref(), i.kernel_version()) {
                (Some(k), Some(v)) => format!("{k} {v}"),
                (Some(k), None) => format!("{k}, not installed by dpkg"),
                (None, _) => "unknown".into(),
            };
            r.ok(
                "installed",
                format!(
                    "{} packages (release: {}, running kernel: {kernel})",
                    i.package_count(),
                    i.release.as_deref().unwrap_or("unknown")
                ),
            )
        }
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
                Some(&format!("sudo journalctl -u {unit} -n 50")),
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
        let last_new = db.kv_with_prefix("lastnew:")?;
        let outbox = db.queue_len(Queue::Outbox)?;
        let digest = db.queue_len(Queue::Digest)?;
        let backfill = db.kv_with_prefix("ghsa:")?;
        Ok((failing, last_new, outbox, digest, backfill))
    });
    let (failing, last_new, outbox, digest, backfill) = match summary {
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
        let hint = Some("sudo journalctl -u vuln-watch@run -n 100");
        if count >= threshold {
            r.fail("source", detail, hint);
        } else {
            r.warn("source", detail, hint);
        }
    }
    let now = chrono::Utc::now();
    for (key, value) in last_new {
        let name = key.trim_start_matches("lastnew:");
        // Without a config every recorded source is listed, without a staleness limit.
        let limit = match cfg {
            Some(c) => match c.sources.iter().find(|s| s.enabled && s.name() == name) {
                Some(s) => s.stale_after_hours(),
                None => continue,
            },
            None => 0,
        };
        let (stale, detail) = freshness(name, &value, limit, now);
        if stale {
            r.warn(
                "freshness",
                detail,
                Some("fetches succeed but return nothing new; check the source URL and sudo journalctl -u vuln-watch@run -n 100"),
            );
        } else {
            r.ok("freshness", detail);
        }
    }
    for (key, window) in backfill {
        let Some(name) = key
            .strip_prefix("ghsa:")
            .and_then(|k| k.strip_suffix(":backfill"))
        else {
            continue;
        };
        // The value may carry the next page URL after the range.
        let range = window.split(' ').next().unwrap_or_default();
        r.warn(
            "source",
            format!("source `{name}` has not read advisories updated in {range} yet (backfill in progress)"),
            Some("filled a few pages per run; GITHUB_TOKEN makes it faster"),
        );
    }
    if outbox > 0 {
        r.warn(
            "outbox",
            format!("{outbox} urgent message(s) not delivered yet"),
            Some("check the Discord credentials, then sudo vuln-watch test-notify"),
        );
    }
}

/// Describe when a source last returned something new; true when it is over `limit`
/// hours (0 = no limit).
fn freshness(
    name: &str,
    last_new: &str,
    limit: u64,
    now: chrono::DateTime<chrono::Utc>,
) -> (bool, String) {
    let Ok(t) = chrono::DateTime::parse_from_rfc3339(last_new) else {
        return (
            false,
            format!("source `{name}`: unreadable last-new time {last_new:?}"),
        );
    };
    let hours = now.signed_duration_since(t).num_hours();
    let mut detail = format!(
        "source `{name}`: last new item {} ({hours} h ago)",
        t.with_timezone(&chrono::Utc).format("%Y-%m-%d %H:%M UTC")
    );
    let stale = limit > 0 && hours >= 0 && hours as u64 >= limit;
    if stale {
        detail.push_str(&format!(", over stale_after_hours = {limit}"));
    }
    (stale, detail)
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
    fn freshness_warns_only_over_the_limit() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-26T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let (stale, detail) = freshness("ghsa", "2026-10-26T00:00:00+00:00", 72, now);
        assert!(!stale);
        assert_eq!(
            detail,
            "source `ghsa`: last new item 2026-10-26 00:00 UTC (12 h ago)"
        );
        let (stale, detail) = freshness("ghsa", "2026-10-22T00:00:00+00:00", 72, now);
        assert!(stale);
        assert!(
            detail.ends_with("(108 h ago), over stale_after_hours = 72"),
            "{detail}"
        );
        assert!(!freshness("feed", "2020-01-01T00:00:00+00:00", 0, now).0);
        assert!(!freshness("x", "garbage", 1, now).0);
    }

    #[test]
    fn invalid_webhook_url_is_a_failure() {
        let mut cfg = Config::parse("[discord]\nmode = \"webhook\"\n").unwrap();
        cfg.installed.enabled = false;
        let mut env = HashMap::new();
        env.insert(
            "DISCORD_WEBHOOK_URL".to_string(),
            "http://discord.com/api/webhooks/1/abc".to_string(),
        );
        let secrets = secrets_from(&env);
        let mut r = Report::default();
        check_credentials(&mut r, &cfg, &secrets, true);
        assert_eq!(r.fails, 1);
        // The detail doctor prints is this error; it must not contain the token.
        let err = format!(
            "{:#}",
            app::build_target(&cfg, &secrets, false).err().unwrap()
        );
        assert!(!err.contains("abc"), "{err}");

        env.insert(
            "DISCORD_WEBHOOK_URL".to_string(),
            "https://discord.com/api/webhooks/1/abc".to_string(),
        );
        let mut r = Report::default();
        check_credentials(&mut r, &cfg, &secrets_from(&env), true);
        assert_eq!(r.fails, 0);
    }

    #[test]
    fn heartbeat_warns_about_config_and_insecure_env() {
        let secret = "secret-uuid";
        let with = |env: Option<&str>, file: Option<&str>, from_file: bool| {
            let mut cfg = Config::parse("").unwrap();
            cfg.runtime.heartbeat_url = file.map(str::to_string);
            let mut env_map = HashMap::new();
            if let Some(v) = env {
                env_map.insert("HEARTBEAT_URL".to_string(), v.to_string());
            }
            let found = heartbeat_findings(&cfg, &secrets_from(&env_map), from_file);
            for (_, detail, hint) in &found {
                assert!(!detail.contains(secret), "{detail}");
                assert!(!hint.as_deref().unwrap_or("").contains(secret));
            }
            found.into_iter().map(|(s, _, _)| s).collect::<Vec<_>>()
        };
        let https = "https://hc-ping.com/secret-uuid";
        let http = "http://hc-ping.com/secret-uuid";
        assert!(with(None, None, true).is_empty());
        assert_eq!(with(Some(https), None, true), [Status::Ok]);
        assert_eq!(with(None, Some(https), true), [Status::Warn]);
        assert_eq!(
            with(Some(https), Some(https), true),
            [Status::Warn, Status::Ok]
        );
        assert_eq!(with(Some(http), None, true), [Status::Fail]);
        assert_eq!(
            with(Some(http), Some(https), true),
            [Status::Warn, Status::Fail]
        );
        assert_eq!(with(Some(http), None, false), [Status::Warn]);

        let mut cfg = Config::parse("").unwrap();
        cfg.runtime.heartbeat_url = Some(https.to_string());
        let found = heartbeat_findings(&cfg, &secrets_from(&HashMap::new()), true);
        assert!(found[0].1.contains("runtime.heartbeat_url"));
        assert!(found[0].2.as_deref().unwrap().contains("HEARTBEAT_URL"));
    }

    #[test]
    fn parses_env_file() {
        let env = parse_env_file(
            "# comment\n\
             DISCORD_BOT_TOKEN=abc=def\n\
             DISCORD_USER_ID=\n\
             ; other comment\n\
             GITHUB_TOKEN = ghp_x \n\
             export HEARTBEAT_URL=https://x\n\
             garbage\n",
        );
        assert_eq!(
            env.get("DISCORD_BOT_TOKEN").map(String::as_str),
            Some("abc=def")
        );
        assert_eq!(env.get("GITHUB_TOKEN").map(String::as_str), Some("ghp_x"));
        assert!(!env.contains_key("DISCORD_USER_ID"));
        // systemd rejects `export`, so the variable is not set.
        assert!(!env.contains_key("HEARTBEAT_URL"));

        // systemd removes surrounding quotes; a quoted empty value is unset.
        let env = parse_env_file(
            "HEARTBEAT_URL=\"https://hc-ping.com/x\"\n\
             GITHUB_TOKEN='ghp_y'\n\
             DISCORD_USER_ID=\"\"\n\
             DISCORD_BOT_TOKEN=\"a\\\"b\\\\c\"\n\
             DISCORD_WEBHOOK_URL=\"\n",
        );
        assert_eq!(
            env.get("HEARTBEAT_URL").map(String::as_str),
            Some("https://hc-ping.com/x")
        );
        assert_eq!(env.get("GITHUB_TOKEN").map(String::as_str), Some("ghp_y"));
        assert!(!env.contains_key("DISCORD_USER_ID"));
        assert_eq!(
            env.get("DISCORD_BOT_TOKEN").map(String::as_str),
            Some("a\"b\\c")
        );
        assert_eq!(
            env.get("DISCORD_WEBHOOK_URL").map(String::as_str),
            Some("\"")
        );
        let secrets = secrets_from(&env);
        let cfg = Config::parse("").unwrap();
        assert_eq!(
            heartbeat_findings(&cfg, &secrets, true)
                .into_iter()
                .map(|(s, _, _)| s)
                .collect::<Vec<_>>(),
            [Status::Ok]
        );
        // A quoted blank value is unset too, so doctor does not report it as insecure.
        let env = parse_env_file("HEARTBEAT_URL=\"   \"\n");
        assert!(!env.contains_key("HEARTBEAT_URL"));
        assert!(heartbeat_findings(&cfg, &secrets_from(&env), true).is_empty());
    }

    #[test]
    fn lints_env_file() {
        let issues = lint_env_file(
            "# comment\n\
             DISCORD_BOT_TOKEN=secret\n\
             RUST_LOG=info\n\
             https_proxy=http://proxy:3128\n\
             discord.mode = \"webhook\"\n\
             [discord]\n\
             DISCORD_WEBHOOK=https://x\n\
             export GITHUB_TOKEN=secret\n\
             DISCORD_USER_ID: 123\n",
        );
        assert_eq!(
            issues,
            vec![
                EnvIssue::ConfigKey {
                    line: 5,
                    head: "discord.mode".into()
                },
                EnvIssue::ConfigKey {
                    line: 6,
                    head: "[discord]".into()
                },
                EnvIssue::Unknown {
                    line: 7,
                    key: "DISCORD_WEBHOOK".into()
                },
                EnvIssue::Invalid {
                    line: 8,
                    head: Some("export GITHUB_TOKEN".into())
                },
                EnvIssue::Invalid {
                    line: 9,
                    head: Some("DISCORD_USER_ID".into())
                },
            ]
        );
        let shown = format!("{issues:?}");
        assert!(!shown.contains("secret") && !shown.contains("123"));
    }

    /// Everything `doctor` prints for the env file.
    fn printed_env_issues(text: &str) -> String {
        lint_env_file(text)
            .iter()
            .map(|i| {
                let (detail, hint) = env_issue_text(i);
                format!("{detail}\n{hint}\n")
            })
            .collect()
    }

    /// True if any 5-character window of `secret` appears in `shown`.
    fn leaks(shown: &str, secret: &str) -> bool {
        let chars: Vec<char> = secret.chars().collect();
        chars
            .windows(5)
            .any(|w| shown.contains(&w.iter().collect::<String>()))
    }

    #[test]
    fn env_lint_does_not_print_a_token_on_its_own_line() {
        let token = "ghp_aBcD1234eFgH5678iJkL9012mNoP3456qRsT";
        assert_eq!(token.len(), 40);
        let text = format!("# GITHUB_TOKEN=\n{token}\n");
        assert_eq!(
            lint_env_file(&text),
            vec![EnvIssue::Invalid {
                line: 2,
                head: None
            }]
        );
        let shown = printed_env_issues(&text);
        assert!(!leaks(&shown, token), "{shown}");
        assert!(shown.contains("line 2"), "{shown}");

        let pat = "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV";
        let shown = printed_env_issues(pat);
        assert!(!leaks(&shown, pat), "{shown}");
    }

    #[test]
    fn env_lint_does_not_print_a_dotted_token() {
        let token = "MTEyMzQ1Njc4OTAxMjM0NTY3OA.GaBcDe.xyzSECRETsecretSECRETsecret0123";
        let shown = printed_env_issues(&format!("DISCORD_BOT_TOKEN=ok\n{token}\n"));
        assert!(!leaks(&shown, token), "{shown}");
        assert!(shown.contains("line 2"), "{shown}");
    }

    #[test]
    fn env_lint_does_not_print_a_secret_line_with_a_space() {
        let line = "abcdef0123456789secret more";
        let shown = printed_env_issues(line);
        assert!(!leaks(&shown, line), "{shown}");
        let shown = printed_env_issues("abcdef0123456789secret:more\n");
        assert!(!leaks(&shown, "abcdef0123456789secret"), "{shown}");
    }

    #[test]
    fn env_lint_names_known_variables_and_sections_without_eq() {
        assert_eq!(
            lint_env_file("GITHUB_TOKEN ghp_x\n[discord]\n[a b]\nGITHUB_TOKEN\n"),
            vec![
                EnvIssue::Invalid {
                    line: 1,
                    head: Some("GITHUB_TOKEN".into())
                },
                EnvIssue::ConfigKey {
                    line: 2,
                    head: "[discord]".into()
                },
                EnvIssue::Invalid {
                    line: 3,
                    head: None
                },
                EnvIssue::Invalid {
                    line: 4,
                    head: None
                },
            ]
        );
    }

    #[test]
    fn env_lint_keeps_hints_for_lines_with_eq() {
        let shown = printed_env_issues(
            "mode = \"dm\"\ndiscord.mode = \"dm\"\nexport GITHUB_TOKEN=secret\n",
        );
        assert!(
            shown.contains("`mode` is not used by vuln-watch"),
            "{shown}"
        );
        assert!(
            shown.contains("`discord.mode` looks like a config.toml setting"),
            "{shown}"
        );
        assert!(
            shown.contains("`export GITHUB_TOKEN` is not KEY=value"),
            "{shown}"
        );
        assert!(
            !shown.contains("secret") && !shown.contains("\"dm\""),
            "{shown}"
        );
    }

    #[test]
    fn parses_systemctl_show() {
        let p = parse_show("Result=success\nExecMainExitTimestamp=\nExecMainStatus=0\n");
        assert_eq!(p["Result"], "success");
        assert_eq!(p["ExecMainExitTimestamp"], "");
    }

    #[test]
    fn state_warns_about_backfill_window() {
        let dir =
            std::env::temp_dir().join(format!("vuln-watch-doctor-state-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.db");
        let db = Db::open(&path).unwrap();
        db.set_kv("ghsa:updated_cursor_unrelated", "x").unwrap();
        let mut r = Report::default();
        check_state(&mut r, &path, None, true);
        assert_eq!(r.warns, 0);
        db.set_kv(
            &crate::sources::ghsa::backfill_key("ghsa"),
            "2026-10-01T00:00:00Z..2026-10-10T00:00:00Z",
        )
        .unwrap();
        let mut r = Report::default();
        check_state(&mut r, &path, None, true);
        drop(db);
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!((r.warns, r.fails), (1, 0));
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
