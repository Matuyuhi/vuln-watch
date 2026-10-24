use std::thread::sleep;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};

use crate::db::{Db, DigestEntry};
use crate::http::Http;
use crate::model::{Decision, Item};
use crate::text::{escape_md, truncate};

const API: &str = "https://discord.com/api/v10";

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Message {
    pub content: String,
    pub embeds: Vec<Value>,
}

impl Message {
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            embeds: Vec::new(),
        }
    }
}

pub enum Target {
    Dm {
        token: String,
        user_id: String,
    },
    Webhook {
        url: String,
        username: Option<String>,
    },
    /// Print to stdout instead of sending.
    Stdout,
    /// Keep sent messages in memory; the `fail_on`-th send attempt (1-based) fails.
    #[cfg(test)]
    Recorder {
        sent: std::cell::RefCell<Vec<Message>>,
        attempts: std::cell::Cell<usize>,
        fail_on: Option<usize>,
    },
}

pub struct Notifier<'a> {
    http: &'a Http,
    target: Target,
}

impl<'a> Notifier<'a> {
    pub fn new(http: &'a Http, target: Target) -> Self {
        Self { http, target }
    }

    pub fn send(&self, db: &Db, msg: &Message) -> Result<()> {
        match &self.target {
            Target::Stdout => {
                println!("----- message -----");
                println!("{}", msg.content);
                for e in &msg.embeds {
                    println!("{}", serde_json::to_string_pretty(e)?);
                }
                Ok(())
            }
            Target::Webhook { url, username } => {
                let mut body = payload(msg);
                if let Some(u) = username {
                    body["username"] = json!(u);
                }
                let sep = if url.contains('?') { '&' } else { '?' };
                self.post(&format!("{url}{sep}wait=true"), None, &body)?;
                Ok(())
            }
            Target::Dm { token, user_id } => {
                let auth = format!("Bot {token}");
                let body = payload(msg);
                for attempt in 0..2 {
                    let channel = self.dm_channel(db, &auth, user_id)?;
                    let url = format!("{API}/channels/{channel}/messages");
                    match self.post(&url, Some(&auth), &body) {
                        Ok(_) => return Ok(()),
                        Err(e) if attempt == 0 && is_channel_error(&e) => {
                            tracing::warn!("cached DM channel failed ({e:#}), reopening");
                            db.del_kv(&dm_key(user_id))?;
                        }
                        Err(e) => return Err(e),
                    }
                }
                unreachable!()
            }
            #[cfg(test)]
            Target::Recorder {
                sent,
                attempts,
                fail_on,
            } => {
                attempts.set(attempts.get() + 1);
                if *fail_on == Some(attempts.get()) {
                    bail!("test send failure");
                }
                sent.borrow_mut().push(msg.clone());
                Ok(())
            }
        }
    }

    /// Pause between consecutive messages so a batch stays clear of Discord rate limits.
    pub fn pace(&self) {
        if matches!(self.target, Target::Webhook { .. } | Target::Dm { .. }) {
            sleep(Duration::from_millis(600));
        }
    }

    #[cfg(test)]
    pub fn sent(&self) -> Vec<Message> {
        match &self.target {
            Target::Recorder { sent, .. } => sent.borrow().clone(),
            _ => Vec::new(),
        }
    }

    fn dm_channel(&self, db: &Db, auth: &str, user_id: &str) -> Result<String> {
        let key = dm_key(user_id);
        if let Some(id) = db.get_kv(&key)? {
            return Ok(id);
        }
        let resp = self
            .post(
                &format!("{API}/users/@me/channels"),
                Some(auth),
                &json!({ "recipient_id": user_id }),
            )
            .context("opening DM channel (does the bot share a server with you?)")?;
        let id = resp
            .get("id")
            .and_then(Value::as_str)
            .context("DM channel response without id")?
            .to_string();
        db.set_kv(&key, &id)?;
        Ok(id)
    }

    /// POST JSON with Discord rate-limit handling. Returns the parsed response body.
    fn post(&self, url: &str, auth: Option<&str>, body: &Value) -> Result<Value> {
        for _ in 0..5 {
            let mut req = self.http.client().post(url).json(body);
            if let Some(a) = auth {
                req = req.header("Authorization", a);
            }
            let resp = req
                .send()
                // The webhook URL embeds its token; reqwest errors would print it.
                .map_err(|e| e.without_url())
                .context("sending request to Discord")?;
            let status = resp.status().as_u16();
            let text = resp.text().unwrap_or_default();
            if status == 429 {
                let wait = serde_json::from_str::<Value>(&text)
                    .ok()
                    .and_then(|v| v.get("retry_after").and_then(Value::as_f64))
                    .unwrap_or(2.0)
                    .clamp(0.5, 60.0);
                tracing::warn!("Discord rate limited, retrying in {wait:.1}s");
                sleep(Duration::from_secs_f64(wait));
                continue;
            }
            if !(200..300).contains(&status) {
                bail!(DiscordError {
                    status,
                    body: truncate(&text, 400),
                });
            }
            return Ok(serde_json::from_str(&text).unwrap_or(Value::Null));
        }
        bail!("Discord rate limit retries exhausted")
    }
}

#[derive(Debug)]
struct DiscordError {
    status: u16,
    body: String,
}

impl std::fmt::Display for DiscordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Discord API returned HTTP {}: {}",
            self.status, self.body
        )
    }
}

impl std::error::Error for DiscordError {}

fn is_channel_error(e: &anyhow::Error) -> bool {
    e.downcast_ref::<DiscordError>()
        .is_some_and(|d| d.status == 403 || d.status == 404)
}

/// Discord accepted the request but refused this message's content (HTTP 400 "Invalid Form
/// Body", 413 too large), e.g. an embed URL it does not consider well formed. Resending the
/// same message can never succeed.
pub fn is_rejected(e: &anyhow::Error) -> bool {
    e.chain()
        .find_map(|c| c.downcast_ref::<DiscordError>())
        .is_some_and(|d| d.status == 400 || d.status == 413)
}

fn dm_key(user_id: &str) -> String {
    format!("discord:dm_channel:{user_id}")
}

fn payload(msg: &Message) -> Value {
    json!({
        "content": msg.content,
        "embeds": msg.embeds,
        "allowed_mentions": { "parse": [] },
    })
}

fn color(item: &Item) -> u32 {
    if item.kev {
        return 0x8B0000;
    }
    match item.cvss {
        Some(c) if c >= 9.0 => 0xE53935,
        Some(c) if c >= 7.0 => 0xFB8C00,
        Some(c) if c >= 4.0 => 0xFDD835,
        Some(_) => 0x43A047,
        None => 0x757575,
    }
}

fn cvss_label(item: &Item) -> String {
    match (item.cvss, &item.severity) {
        (Some(c), Some(s)) => format!("{c:.1} ({})", s.to_lowercase()),
        (Some(c), None) => format!("{c:.1}"),
        (None, Some(s)) => s.to_lowercase(),
        (None, None) => "-".into(),
    }
}

pub fn urgent_message(item: &Item, decision: &Decision) -> Message {
    let icon = if item.kev { "🔥" } else { "🚨" };
    let content = truncate(
        &format!("{icon} {} — {}", item.display_id(), item.title),
        200,
    );

    let mut fields = vec![
        json!({"name": "CVSS", "value": cvss_label(item), "inline": true}),
        json!({"name": "理由", "value": truncate(&decision.reason, 1024), "inline": true}),
        json!({"name": "ソース", "value": truncate(&item.source, 1024), "inline": true}),
    ];
    if !item.products.is_empty() {
        fields.push(json!({
            "name": "対象",
            "value": truncate(&item.products.join(", "), 1024),
            "inline": false,
        }));
    }
    for (k, v) in item.extra.iter().take(15) {
        if v.trim().is_empty() {
            continue;
        }
        fields.push(json!({
            "name": truncate(k, 256),
            "value": truncate(v, 1024),
            "inline": false,
        }));
    }

    let mut embed = json!({
        "title": truncate(&format!("{}: {}", item.display_id(), item.title), 256),
        "description": truncate(&item.summary, 2000),
        "color": color(item),
        "fields": fields,
        "footer": {"text": "vuln-watch"},
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    if item.url.starts_with("http") {
        embed["url"] = json!(item.url);
    }
    Message {
        content,
        embeds: vec![embed],
    }
}

/// Plain-text variant of `urgent_message` for when Discord rejects the embed.
pub fn urgent_fallback_message(item: &Item, decision: &Decision) -> Message {
    let icon = if item.kev { "🔥" } else { "🚨" };
    let mut text = format!(
        "{icon} {} — {}\n{}",
        escape_md(&truncate(item.display_id(), 200)),
        escape_md(&truncate(&item.title, 300)),
        escape_md(&truncate(&decision.reason, 300)),
    );
    if item.url.starts_with("http") {
        text.push_str(&format!("\n<{}>", truncate(&item.url, 1000)));
    }
    Message::text(truncate(&text, 2000))
}

fn digest_line(e: &DigestEntry) -> String {
    let item = &e.item;
    let id = escape_md(item.display_id());
    let head = if item.url.starts_with("http") {
        format!("[{id}](<{}>)", item.url)
    } else {
        id
    };
    format!(
        "• **{head}** {} — {} · {}",
        escape_md(&truncate(&item.title, 90)),
        cvss_label(item),
        escape_md(&e.reason),
    )
}

/// Build digest messages, each with one embed whose description stays under Discord limits,
/// together with the queue keys of the entries in each message. `resumed` marks a digest
/// that resends what a failed one left in the queue.
pub fn digest_messages(entries: &[DigestEntry], resumed: bool) -> Vec<(Message, Vec<String>)> {
    const MAX_DESC: usize = 3900;
    let mut chunks: Vec<(String, Vec<String>)> = Vec::new();
    let mut cur = String::new();
    let mut keys = Vec::new();
    for e in entries {
        let line = truncate(&digest_line(e), 600);
        if !cur.is_empty() && cur.chars().count() + line.chars().count() + 1 > MAX_DESC {
            chunks.push((std::mem::take(&mut cur), std::mem::take(&mut keys)));
        }
        if !cur.is_empty() {
            cur.push('\n');
        }
        cur.push_str(&line);
        keys.push(e.key.clone());
    }
    if !cur.is_empty() {
        chunks.push((cur, keys));
    }

    let total = chunks.len();
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, (desc, keys))| {
            let content = if i == 0 && resumed {
                format!("📋 脆弱性ダイジェスト（再送）: {}件", entries.len())
            } else if i == 0 {
                format!("📋 脆弱性ダイジェスト: {}件", entries.len())
            } else {
                format!("📋 ダイジェスト（続き {}/{}）", i + 1, total)
            };
            let msg = Message {
                content,
                embeds: vec![json!({
                    "description": desc,
                    "color": 0x5865F2,
                    "footer": {"text": "vuln-watch"},
                })],
            };
            (msg, keys)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Level;

    fn item(i: usize) -> Item {
        let mut it = Item::new("ghsa", format!("GHSA-{i:04}"));
        it.cve = Some(format!("CVE-2026-{i:05}"));
        it.title = format!("Some *vulnerable* thing number {i} with a fairly long title");
        it.url = format!("https://example.com/{i}");
        it.cvss = Some(9.1);
        it
    }

    #[test]
    fn digest_is_chunked_under_limits() {
        let entries: Vec<DigestEntry> = (0..200)
            .map(|i| DigestEntry {
                key: i.to_string(),
                item: item(i),
                reason: "CVSS 9.1 ≥ 9.0".into(),
            })
            .collect();
        let msgs = digest_messages(&entries, false);
        assert!(msgs.len() > 1);
        assert!(msgs[0].0.content.contains("200件"));
        let mut lines = 0;
        let mut keys = Vec::new();
        for (m, k) in &msgs {
            let d = m.embeds[0]["description"].as_str().unwrap();
            assert!(d.chars().count() <= 3900);
            assert_eq!(d.lines().count(), k.len());
            lines += d.lines().count();
            keys.extend(k.iter().cloned());
        }
        assert_eq!(lines, 200);
        let expected: Vec<String> = (0..200).map(|i| i.to_string()).collect();
        assert_eq!(keys, expected);
        assert!(msgs[0].0.embeds[0]["description"]
            .as_str()
            .unwrap()
            .contains("\\*vulnerable\\*"));

        let resumed = digest_messages(&entries[150..], true);
        assert!(resumed[0]
            .0
            .content
            .starts_with("📋 脆弱性ダイジェスト（再送）: 50件"));
    }

    #[test]
    fn urgent_message_shape() {
        let mut it = item(1);
        it.kev = true;
        it.products = vec!["nginx nginx".into()];
        it.extra = vec![("KEV追加日".into(), "2026-10-24".into())];
        let m = urgent_message(&it, &Decision::new(Level::Urgent, "CISA KEV"));
        assert!(m.content.starts_with("🔥 CVE-2026-00001"));
        let e = &m.embeds[0];
        assert_eq!(e["color"], 0x8B0000);
        assert_eq!(e["url"], "https://example.com/1");
        assert_eq!(e["fields"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn rejected_only_for_invalid_body() {
        let err = |status| {
            anyhow::Error::new(DiscordError {
                status,
                body: String::new(),
            })
            .context("sending notification")
        };
        assert!(is_rejected(&err(400)));
        assert!(is_rejected(&err(413)));
        assert!(!is_rejected(&err(401)));
        assert!(!is_rejected(&err(500)));
        assert!(!is_rejected(&anyhow::anyhow!("connection refused")));
    }

    #[test]
    fn fallback_message_is_plain_text() {
        let mut it = item(1);
        it.title = "x".repeat(5000);
        let m = urgent_fallback_message(&it, &Decision::new(Level::Urgent, "CISA KEV"));
        assert!(m.embeds.is_empty());
        assert!(m.content.starts_with("🚨 CVE-2026-00001"));
        assert!(m.content.contains("CISA KEV"));
        assert!(m.content.ends_with("<https://example.com/1>"));
        assert!(m.content.chars().count() <= 2000);

        // An unbounded feed GUID must not crowd out the reason and link.
        let mut it = Item::new("rel", "g".repeat(5000));
        it.url = "https://example.com/x".into();
        let m = urgent_fallback_message(&it, &Decision::new(Level::Urgent, "watch: nginx"));
        assert!(m.content.contains("watch: nginx"));
        assert!(m.content.ends_with("<https://example.com/x>"));
    }
}
