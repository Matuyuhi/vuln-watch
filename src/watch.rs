//! `vuln-watch watch`: list and edit the `[[watch]]` entries of config.toml.
//!
//! Edits go through `toml_edit`, so comments and formatting elsewhere in the
//! file survive. The edited text must pass `Config::parse` before it is
//! written. config.toml is root-owned and only read by the service, so unlike
//! `run` this edits the file directly instead of going through systemd.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, Value};

use crate::config::Config;

#[derive(Subcommand)]
pub enum WatchCommand {
    /// Show the watch list
    List,
    /// Add a watch entry
    Add {
        /// Entry name (also the keyword when no --keyword / --package is given)
        name: String,
        #[command(flatten)]
        set: SetArgs,
        /// Print the result without writing the config
        #[arg(long)]
        dry_run: bool,
    },
    /// Add or remove keywords, packages and sources of a watch entry
    Edit {
        /// Entry name (case-insensitive)
        name: String,
        #[command(flatten)]
        set: SetArgs,
        /// Remove a keyword (repeatable)
        #[arg(long, value_name = "WORD")]
        rm_keyword: Vec<String>,
        /// Remove a package (repeatable)
        #[arg(long, value_name = "PACKAGE")]
        rm_package: Vec<String>,
        /// Remove a source (repeatable)
        #[arg(long, value_name = "SOURCE")]
        rm_source: Vec<String>,
        /// Print the result without writing the config
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove a watch entry
    Remove {
        /// Entry name (case-insensitive)
        name: String,
        /// Print the result without writing the config
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Args, Default)]
pub struct SetArgs {
    /// Keyword matched on title, products and description (repeatable)
    #[arg(short, long, value_name = "WORD")]
    keyword: Vec<String>,
    /// Exact package name, e.g. tokio or group:artifact (repeatable)
    #[arg(short, long, value_name = "PACKAGE")]
    package: Vec<String>,
    /// Only apply to this source name (repeatable)
    #[arg(short, long, value_name = "SOURCE")]
    source: Vec<String>,
    /// Matches are urgent (the default)
    #[arg(long, conflicts_with = "no_urgent")]
    urgent: bool,
    /// Matches only go to the digest
    #[arg(long)]
    no_urgent: bool,
}

impl SetArgs {
    fn urgent(&self) -> Option<bool> {
        if self.urgent {
            Some(true)
        } else if self.no_urgent {
            Some(false)
        } else {
            None
        }
    }
}

pub fn run(config: &Path, cmd: WatchCommand) -> Result<()> {
    if let WatchCommand::List = cmd {
        let cfg = Config::load(config)?;
        print!("{}", list_table(&cfg));
        return Ok(());
    }
    let original = fs::read_to_string(config)
        .with_context(|| format!("failed to read config {}", config.display()))?;
    let (edit, dry_run) = match cmd {
        WatchCommand::List => unreachable!("handled above"),
        WatchCommand::Add { name, set, dry_run } => (Edit::Add { name, set }, dry_run),
        WatchCommand::Edit {
            name,
            set,
            rm_keyword,
            rm_package,
            rm_source,
            dry_run,
        } => (
            Edit::Change {
                name,
                set,
                rm_keyword,
                rm_package,
                rm_source,
            },
            dry_run,
        ),
        WatchCommand::Remove { name, dry_run } => (Edit::Remove { name }, dry_run),
    };
    let out = apply(&original, &edit)?;
    for w in &out.warnings {
        tracing::warn!("{w}");
    }
    print!("{}", out.summary);
    if dry_run {
        println!("(dry run: {} not changed)", config.display());
        return Ok(());
    }
    write_config(config, &out.text)?;
    println!(
        "updated {} (applies from the next run; no restart needed)",
        config.display()
    );
    Ok(())
}

enum Edit {
    Add {
        name: String,
        set: SetArgs,
    },
    Change {
        name: String,
        set: SetArgs,
        rm_keyword: Vec<String>,
        rm_package: Vec<String>,
        rm_source: Vec<String>,
    },
    Remove {
        name: String,
    },
}

#[derive(Debug)]
struct Outcome {
    /// The whole edited config.
    text: String,
    /// What to show: the edited entry, or what was removed.
    summary: String,
    warnings: Vec<String>,
}

/// Apply `edit` to the config text and validate the result.
fn apply(original: &str, edit: &Edit) -> Result<Outcome> {
    let mut doc: DocumentMut = original.parse().context("config is not valid TOML")?;
    let mut warnings = Vec::new();
    // Source names for a friendlier error than Config::parse gives.
    let sources = Config::parse(original)
        .ok()
        .map(|c| c.sources.iter().map(|s| s.name()).collect::<Vec<String>>());

    let watches = watch_tables(&mut doc)?;
    let summary = match edit {
        Edit::Add { name, set } => {
            let name = clean("name", name, &mut warnings)?;
            if let Some(i) = find(watches, &name) {
                bail!(
                    "watch `{}` already exists (use `vuln-watch watch edit`)",
                    entry_name(watches, i)
                );
            }
            let mut table = Table::new();
            table.decor_mut().set_prefix("\n");
            table.insert("name", toml_edit::value(name.as_str()));
            update_table(
                &mut table,
                set,
                &Removals::default(),
                sources.as_deref(),
                &mut warnings,
            )?;
            check_effective(&table, &name, &mut warnings);
            // Right after the last entry, not after any [[source]] tables below it.
            if let Some(last) = watches.iter().last() {
                table.set_position(last.position());
            }
            watches.push(table);
            render(watches.get(watches.len() - 1).expect("just pushed"))
        }
        Edit::Change {
            name,
            set,
            rm_keyword,
            rm_package,
            rm_source,
        } => {
            let rm = Removals {
                keyword: rm_keyword,
                package: rm_package,
                source: rm_source,
            };
            if set.keyword.is_empty()
                && set.package.is_empty()
                && set.source.is_empty()
                && set.urgent().is_none()
                && rm.is_empty()
            {
                bail!("nothing to change: give --keyword, --package, --source, --urgent / --no-urgent or --rm-*");
            }
            let i = find_or_explain(watches, name)?;
            let display = entry_name(watches, i);
            let table = watches.get_mut(i).expect("index from find");
            update_table(table, set, &rm, sources.as_deref(), &mut warnings)?;
            check_effective(table, &display, &mut warnings);
            render(table)
        }
        Edit::Remove { name } => {
            let i = find_or_explain(watches, name)?;
            let removed = render(watches.get(i).expect("index from find"));
            watches.remove(i);
            format!("removed:\n{removed}")
        }
    };
    if watches.is_empty() {
        doc.remove("watch");
    }

    let text = doc.to_string();
    Config::parse(&text).context("the edited config would be invalid; nothing was written")?;
    Ok(Outcome {
        text,
        summary,
        warnings,
    })
}

#[derive(Default)]
struct Removals<'a> {
    keyword: &'a [String],
    package: &'a [String],
    source: &'a [String],
}

impl Removals<'_> {
    fn is_empty(&self) -> bool {
        self.keyword.is_empty() && self.package.is_empty() && self.source.is_empty()
    }
}

/// The `[[watch]]` array, created when missing.
fn watch_tables(doc: &mut DocumentMut) -> Result<&mut ArrayOfTables> {
    let item = doc
        .entry("watch")
        .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()));
    item.as_array_of_tables_mut().context(
        "`watch` in the config is not written as [[watch]] tables; edit it by hand instead",
    )
}

fn entry_name(watches: &ArrayOfTables, i: usize) -> String {
    watches
        .get(i)
        .and_then(|t| t.get("name"))
        .and_then(Item::as_str)
        .unwrap_or_default()
        .to_string()
}

fn find(watches: &ArrayOfTables, name: &str) -> Option<usize> {
    let name = name.trim().to_lowercase();
    (0..watches.len()).find(|&i| entry_name(watches, i).trim().to_lowercase() == name)
}

fn find_or_explain(watches: &ArrayOfTables, name: &str) -> Result<usize> {
    if let Some(i) = find(watches, name) {
        return Ok(i);
    }
    let names: Vec<String> = (0..watches.len()).map(|i| entry_name(watches, i)).collect();
    if names.is_empty() {
        bail!("no watch `{}`: the watch list is empty", name.trim());
    }
    bail!(
        "no watch `{}`; existing entries: {}",
        name.trim(),
        names.join(", ")
    )
}

/// Trim a value from the command line; empty is an error.
fn clean(what: &str, value: &str, warnings: &mut Vec<String>) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{what} must not be empty");
    }
    if trimmed != value {
        warnings.push(format!("{what} `{value}` trimmed to `{trimmed}`"));
    }
    Ok(trimmed.to_string())
}

fn update_table(
    table: &mut Table,
    set: &SetArgs,
    rm: &Removals,
    sources: Option<&[String]>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    // Keywords match case-insensitively, so compare them that way.
    let same_word = |a: &str, b: &str| a.to_lowercase() == b.to_lowercase();
    let same = |a: &str, b: &str| a == b;

    let mut keywords = Vec::new();
    for k in &set.keyword {
        let k = clean("keyword", k, warnings)?;
        if k.chars().count() <= 2 {
            warnings.push(format!(
                "keyword `{k}` is very short and may match unrelated advisories"
            ));
        }
        keywords.push(k);
    }
    let packages = set
        .package
        .iter()
        .map(|p| clean("package", p, warnings))
        .collect::<Result<Vec<_>>>()?;
    let new_sources = set
        .source
        .iter()
        .map(|s| clean("source", s, warnings))
        .collect::<Result<Vec<_>>>()?;
    if let Some(known) = sources {
        for s in &new_sources {
            if !known.contains(s) {
                bail!(
                    "unknown source `{s}`; sources in this config: {}",
                    known.join(", ")
                );
            }
        }
    }

    edit_list(
        table, "keywords", &keywords, rm.keyword, same_word, warnings,
    )?;
    edit_list(table, "packages", &packages, rm.package, same, warnings)?;
    edit_list(table, "sources", &new_sources, rm.source, same, warnings)?;

    match set.urgent() {
        Some(false) => {
            table.insert("urgent", toml_edit::value(false));
        }
        // true is the default: only overwrite an explicit `urgent = ...`.
        Some(true) if table.contains_key("urgent") => {
            table.insert("urgent", toml_edit::value(true));
        }
        _ => {}
    }
    Ok(())
}

/// Add and remove values of the string array `key`, dropping the key when it ends up empty.
fn edit_list(
    table: &mut Table,
    key: &str,
    add: &[String],
    remove: &[String],
    same: impl Fn(&str, &str) -> bool,
    warnings: &mut Vec<String>,
) -> Result<()> {
    if add.is_empty() && remove.is_empty() {
        return Ok(());
    }
    let mut array = match table.get(key) {
        None => Array::new(),
        Some(item) => item
            .as_array()
            .cloned()
            .with_context(|| format!("`{key}` is not an array; edit it by hand instead"))?,
    };
    let contains = |a: &Array, v: &str| a.iter().any(|x| x.as_str().is_some_and(|x| same(x, v)));
    let singular = key.trim_end_matches('s');
    for r in remove {
        let r = r.trim();
        if contains(&array, r) {
            array.retain(|x| !x.as_str().is_some_and(|x| same(x, r)));
        } else {
            warnings.push(format!("{singular} `{r}` is not in {key}; nothing removed"));
        }
    }
    for v in add {
        if contains(&array, v) {
            warnings.push(format!("{singular} `{v}` is already in {key}"));
        } else {
            array.push(v.as_str());
        }
    }
    if array.is_empty() {
        table.remove(key);
    } else {
        // Keep an existing array's layout (e.g. one value per line); format a new one.
        if table.get(key).is_none() {
            array.fmt();
        }
        match table.get_mut(key) {
            Some(item) => {
                if let Some(slot) = item.as_value_mut() {
                    let decor = slot.decor().clone();
                    *slot = Value::Array(array);
                    *slot.decor_mut() = decor;
                }
            }
            None => {
                table.insert(key, toml_edit::value(array));
            }
        }
    }
    Ok(())
}

fn check_effective(table: &Table, name: &str, warnings: &mut Vec<String>) {
    if !table.contains_key("keywords") && !table.contains_key("packages") {
        warnings.push(format!(
            "watch `{name}` has no keywords or packages: its name is matched as the keyword"
        ));
    }
}

/// One entry as it appears in the config.
fn render(table: &Table) -> String {
    let mut doc = DocumentMut::new();
    let mut t = table.clone();
    t.decor_mut().clear();
    let mut array = ArrayOfTables::new();
    array.push(t);
    doc.insert("watch", Item::ArrayOfTables(array));
    doc.to_string()
}

fn list_table(cfg: &Config) -> String {
    if cfg.watches.is_empty() {
        return "no watch entries (add one with `vuln-watch watch add`)\n".to_string();
    }
    let rows: Vec<[String; 5]> = cfg
        .watches
        .iter()
        .map(|w| {
            let keywords = if w.keywords.is_empty() && w.packages.is_empty() {
                format!("({})", w.name.to_lowercase())
            } else {
                w.keywords.join(", ")
            };
            let sources = if w.sources.is_empty() {
                "all".to_string()
            } else {
                w.sources.join(", ")
            };
            [
                w.name.clone(),
                keywords,
                w.packages.join(", "),
                sources,
                if w.urgent { "yes" } else { "no" }.to_string(),
            ]
        })
        .collect();
    let header = ["NAME", "KEYWORDS", "PACKAGES", "SOURCES", "URGENT"].map(String::from);
    let mut widths = header.clone().map(|h| h.chars().count());
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in std::iter::once(&header).chain(&rows) {
        let line: Vec<String> = row
            .iter()
            .zip(widths)
            .map(|(cell, w)| format!("{cell:<w$}"))
            .collect();
        out.push_str(line.join("  ").trim_end());
        out.push('\n');
    }
    out
}

/// Replace `path` atomically, keeping its mode and owner and the old text in `<path>.bak`.
fn write_config(path: &Path, text: &str) -> Result<()> {
    let meta = fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = path
        .file_name()
        .context("config path has no file name")?
        .to_string_lossy()
        .into_owned();
    let tmp = dir.join(format!(".{file_name}.tmp"));
    let bak = PathBuf::from(format!("{}.bak", path.display()));

    let mut f = match fs::File::create(&tmp) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            bail!("no permission to write {} (run with sudo)", path.display())
        }
        Err(e) => return Err(e).with_context(|| format!("failed to create {}", tmp.display())),
    };
    let result = (|| -> Result<()> {
        f.write_all(text.as_bytes())?;
        f.set_permissions(meta.permissions())?;
        if let Err(e) = std::os::unix::fs::fchown(&f, Some(meta.uid()), Some(meta.gid())) {
            tracing::warn!("could not keep the owner of {}: {e}", path.display());
        }
        f.sync_all()?;
        fs::copy(path, &bak).with_context(|| format!("failed to back up to {}", bak.display()))?;
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"# top comment
[discord]
mode = "webhook" # inline comment

# Watch list
[[watch]]
name = "nginx"

# kernel comment
[[watch]]
name = "Linux kernel"
keywords = ["linux kernel"]
sources = ["kev"]
"#;

    fn set(keyword: &[&str], package: &[&str]) -> SetArgs {
        SetArgs {
            keyword: keyword.iter().map(|s| s.to_string()).collect(),
            package: package.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn add_appends_and_keeps_comments() {
        let out = apply(
            BASE,
            &Edit::Add {
                name: "PHP".into(),
                set: set(&["php"], &["php/php-src"]),
            },
        )
        .unwrap();
        assert!(out.text.starts_with(BASE), "{}", out.text);
        assert!(out.text.ends_with(
            "\n[[watch]]\nname = \"PHP\"\nkeywords = [\"php\"]\npackages = [\"php/php-src\"]\n"
        ));
        let cfg = Config::parse(&out.text).unwrap();
        assert_eq!(cfg.watches.len(), 3);
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    }

    #[test]
    fn add_rejects_duplicate_name_case_insensitively() {
        let err = apply(
            BASE,
            &Edit::Add {
                name: "NGINX".into(),
                set: SetArgs::default(),
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
    }

    #[test]
    fn add_rejects_empty_values_and_unknown_sources() {
        let empty = apply(
            BASE,
            &Edit::Add {
                name: "x".into(),
                set: set(&["  "], &[]),
            },
        );
        assert!(empty.is_err());
        let unknown = apply(
            BASE,
            &Edit::Add {
                name: "x".into(),
                set: SetArgs {
                    source: vec!["nope".into()],
                    ..Default::default()
                },
            },
        )
        .unwrap_err();
        assert!(
            unknown.to_string().contains("unknown source `nope`"),
            "{unknown}"
        );
    }

    #[test]
    fn add_to_config_without_watch_list() {
        let out = apply(
            "[discord]\nmode = \"webhook\"\n",
            &Edit::Add {
                name: "tokio".into(),
                set: set(&[], &["tokio"]),
            },
        )
        .unwrap();
        let cfg = Config::parse(&out.text).unwrap();
        assert_eq!(cfg.watches[0].packages, vec!["tokio"]);
    }

    #[test]
    fn edit_adds_and_removes_values() {
        let out = apply(
            BASE,
            &Edit::Change {
                name: "linux KERNEL".into(),
                set: SetArgs {
                    keyword: vec!["Linux Kernel".into(), "kvm".into()],
                    no_urgent: true,
                    ..Default::default()
                },
                rm_keyword: vec![],
                rm_package: vec![],
                rm_source: vec!["kev".into()],
            },
        )
        .unwrap();
        // The duplicate (case-insensitive) is skipped with a warning.
        assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
        assert!(out.text.contains("# kernel comment\n[[watch]]\nname = \"Linux kernel\"\nkeywords = [\"linux kernel\", \"kvm\"]\nurgent = false\n"), "{}", out.text);
        let cfg = Config::parse(&out.text).unwrap();
        assert!(cfg.watches[1].sources.is_empty());
        assert!(!cfg.watches[1].urgent);
    }

    #[test]
    fn edit_warns_when_name_becomes_the_keyword() {
        let out = apply(
            BASE,
            &Edit::Change {
                name: "Linux kernel".into(),
                set: SetArgs::default(),
                rm_keyword: vec!["linux kernel".into()],
                rm_package: vec![],
                rm_source: vec![],
            },
        )
        .unwrap();
        assert!(!out.text.contains("keywords"));
        assert!(
            out.warnings[0].contains("name is matched"),
            "{:?}",
            out.warnings
        );
    }

    #[test]
    fn edit_without_changes_is_an_error() {
        let err = apply(
            BASE,
            &Edit::Change {
                name: "nginx".into(),
                set: SetArgs::default(),
                rm_keyword: vec![],
                rm_package: vec![],
                rm_source: vec![],
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("nothing to change"));
    }

    #[test]
    fn remove_deletes_only_that_entry() {
        let out = apply(
            BASE,
            &Edit::Remove {
                name: "nginx".into(),
            },
        )
        .unwrap();
        assert!(out
            .text
            .contains("# top comment\n[discord]\nmode = \"webhook\" # inline comment\n"));
        assert!(!out.text.contains("\"nginx\""));
        assert!(out
            .text
            .contains("# kernel comment\n[[watch]]\nname = \"Linux kernel\""));
    }

    #[test]
    fn remove_unknown_lists_entries() {
        let err = apply(BASE, &Edit::Remove { name: "php".into() }).unwrap_err();
        assert!(err.to_string().contains("nginx, Linux kernel"), "{err}");
    }

    #[test]
    fn edits_the_example_config() {
        let example = include_str!("../config.example.toml");
        let out = apply(
            example,
            &Edit::Add {
                name: "PHP".into(),
                set: set(&["php"], &[]),
            },
        )
        .unwrap();
        // Inserted after the last [[watch]], before the [[source]] section; nothing else changes.
        let added = "\n[[watch]]\nname = \"PHP\"\nkeywords = [\"php\"]\n";
        let at = out.text.find(added).expect("entry added");
        assert!(out.text[at..].contains("[[source]]"));
        assert_eq!(out.text.replacen(added, "", 1), example);
    }

    #[test]
    fn list_shows_effective_keywords() {
        let cfg = Config::parse(BASE).unwrap();
        let table = list_table(&cfg);
        assert!(table.contains("nginx         (nginx)"), "{table}");
        assert!(table.contains("kev"), "{table}");
    }

    #[test]
    fn write_keeps_backup() {
        let dir = std::env::temp_dir().join(format!("vuln-watch-watch-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        fs::write(&path, "old").unwrap();
        write_config(&path, "new").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(
            fs::read_to_string(dir.join("config.toml.bak")).unwrap(),
            "old"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
