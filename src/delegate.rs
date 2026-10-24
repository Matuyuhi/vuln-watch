//! Run a command from a shell the way the systemd timers run it.
//!
//! On an installed host the credentials (/etc/vuln-watch/env) and state.db
//! belong to `vuln-watch@.service`, which runs as a DynamicUser. Opening
//! state.db as root would leave root-owned files the timers cannot write, so
//! instead of reading the env file ourselves we re-run this binary with
//! `systemd-run --pipe --wait`, using the unit's own [Service] settings. The
//! output stays on the terminal and the exit code is passed through, while the
//! secrets only ever reach the child through systemd.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{bail, Context, Result};

const UNIT_FILE: &str = "/etc/systemd/system/vuln-watch@.service";
const BUNDLED_SERVICE: &str = include_str!("../deploy/systemd/vuln-watch@.service");

/// The [Service] settings to pass as `systemd-run -p`, minus ExecStart.
///
/// Uses the installed unit so local edits apply, falling back to the copy
/// bundled with this binary.
fn service_properties() -> Vec<String> {
    let text = fs::read_to_string(UNIT_FILE).unwrap_or_else(|_| BUNDLED_SERVICE.to_string());
    parse_service_section(&text)
}

fn parse_service_section(text: &str) -> Vec<String> {
    let mut in_service = false;
    let mut props = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            in_service = line == "[Service]";
            continue;
        }
        if !in_service {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        // ExecStart carries `%i`; the command line is ours to build.
        if key.starts_with("Exec") {
            continue;
        }
        props.push(format!("{key}={}", value.trim()));
    }
    props
}

/// `systemd-run` arguments that run `exe --config <config> <args>` as the unit does.
fn systemd_run_args(
    exe: &Path,
    config: &Path,
    args: &[String],
    props: &[String],
    rust_log: Option<&str>,
) -> Vec<OsString> {
    let mut out: Vec<OsString> = ["--quiet", "--wait", "--pipe", "--collect", "--description"]
        .map(OsString::from)
        .to_vec();
    out.push(format!("vuln-watch ({} from a shell)", args[0]).into());
    for p in props {
        out.push("-p".into());
        out.push(p.into());
    }
    if let Some(level) = rust_log {
        out.push("-E".into());
        out.push(format!("RUST_LOG={level}").into());
    }
    out.push("--".into());
    out.push(exe.into());
    out.push("--config".into());
    out.push(config.into());
    out.extend(args.iter().map(OsString::from));
    out
}

/// Runs `args` (a subcommand and its flags) under systemd and returns its exit code.
pub fn run(config: &Path, args: &[String]) -> Result<ExitCode> {
    if !crate::doctor::is_root() {
        bail!(
            "on an installed host this command runs as the systemd service, which needs root: \
             sudo vuln-watch {}",
            args.join(" ")
        );
    }
    let exe = std::env::current_exe().context("locating this binary")?;
    // The child starts in / and cannot see /home (ProtectHome=yes).
    let config: PathBuf =
        fs::canonicalize(config).with_context(|| format!("config {}", config.display()))?;
    let rust_log = std::env::var("RUST_LOG").ok();
    let status = Command::new("systemd-run")
        .args(systemd_run_args(
            &exe,
            &config,
            args,
            &service_properties(),
            rust_log.as_deref(),
        ))
        .status()
        .context("running systemd-run")?;
    Ok(match status.code() {
        Some(0) => ExitCode::SUCCESS,
        Some(c) => ExitCode::from(u8::try_from(c).unwrap_or(1)),
        None => ExitCode::FAILURE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_unit_keeps_sandbox_and_drops_exec_start() {
        let props = parse_service_section(BUNDLED_SERVICE);
        for want in [
            "Type=oneshot",
            "EnvironmentFile=/etc/vuln-watch/env",
            "DynamicUser=yes",
            "StateDirectory=vuln-watch",
            "ProtectHome=yes",
            "SystemCallFilter=~@privileged",
            "CapabilityBoundingSet=",
        ] {
            assert!(props.iter().any(|p| p == want), "missing {want}");
        }
        assert!(!props.iter().any(|p| p.starts_with("ExecStart")));
        // [Unit] settings are not service properties.
        assert!(!props.iter().any(|p| p.starts_with("After=")));
    }

    #[test]
    fn repeated_keys_are_all_kept() {
        let props = parse_service_section(
            "[Unit]\nDescription=x\n[Service]\n# c\nSystemCallFilter=@system-service\nSystemCallFilter=~@privileged\n[Install]\nWantedBy=x\n",
        );
        assert_eq!(
            props,
            [
                "SystemCallFilter=@system-service",
                "SystemCallFilter=~@privileged"
            ]
        );
    }

    #[test]
    fn builds_command_line() {
        let args = systemd_run_args(
            Path::new("/usr/local/bin/vuln-watch"),
            Path::new("/etc/vuln-watch/config.toml"),
            &["run".into(), "--strict".into()],
            &["DynamicUser=yes".into()],
            Some("debug"),
        );
        let args: Vec<_> = args.iter().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "--description",
                "vuln-watch (run from a shell)",
                "-p",
                "DynamicUser=yes",
                "-E",
                "RUST_LOG=debug",
                "--",
                "/usr/local/bin/vuln-watch",
                "--config",
                "/etc/vuln-watch/config.toml",
                "run",
                "--strict",
            ]
        );
    }
}
