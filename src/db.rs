use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

use crate::model::{Item, Level};

pub struct Db {
    conn: Connection,
}

pub struct DigestEntry {
    pub key: String,
    pub item: Item,
    pub reason: String,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS seen (
    source     TEXT NOT NULL,
    id         TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (source, id)
);
CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerted (
    key   TEXT PRIMARY KEY,
    level INTEGER NOT NULL,
    at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS digest_queue (
    key       TEXT PRIMARY KEY,
    item      TEXT NOT NULL,
    reason    TEXT NOT NULL,
    queued_at TEXT NOT NULL
);
-- Urgent notifications waiting to be sent. Persisted before cursors/ETags are
-- committed so a Discord outage never loses an item.
CREATE TABLE IF NOT EXISTS outbox (
    key       TEXT PRIMARY KEY,
    item      TEXT NOT NULL,
    reason    TEXT NOT NULL,
    queued_at TEXT NOT NULL
);
-- Work discovered but not yet processed (e.g. CVE ids whose records are still to fetch).
CREATE TABLE IF NOT EXISTS pending (
    source    TEXT NOT NULL,
    id        TEXT NOT NULL,
    data      TEXT NOT NULL,
    attempts  INTEGER NOT NULL DEFAULT 0,
    queued_at TEXT NOT NULL,
    PRIMARY KEY (source, id)
);
"#;

/// Persistent queues of items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Queue {
    /// Sent once a day.
    Digest,
    /// Urgent, sent at the end of each run.
    Outbox,
}

impl Queue {
    fn table(self) -> &'static str {
        match self {
            Queue::Digest => "digest_queue",
            Queue::Outbox => "outbox",
        }
    }
}

pub struct PendingRow {
    pub id: String,
    pub data: String,
    pub attempts: i64,
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open database {}", path.display()))?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.busy_timeout(Duration::from_secs(30))?;
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn is_seen(&self, source: &str, id: &str) -> Result<bool> {
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM seen WHERE source = ?1 AND id = ?2",
                params![source, id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    pub fn mark_seen(&self, source: &str, id: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO seen (source, id, first_seen) VALUES (?1, ?2, ?3)",
            params![source, id, now()],
        )?;
        Ok(())
    }

    pub fn mark_seen_many<'a>(
        &mut self,
        source: &str,
        ids: impl IntoIterator<Item = &'a str>,
    ) -> Result<usize> {
        let tx = self.conn.transaction()?;
        let ts = now();
        let mut n = 0;
        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO seen (source, id, first_seen) VALUES (?1, ?2, ?3)",
            )?;
            for id in ids {
                n += stmt.execute(params![source, id, ts])?;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    pub fn get_kv(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub fn set_kv(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO kv (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn del_kv(&self, key: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM kv WHERE key = ?1", params![key])?;
        Ok(())
    }

    pub fn alerted_level(&self, key: &str) -> Result<Option<Level>> {
        let v: Option<i64> = self
            .conn
            .query_row(
                "SELECT level FROM alerted WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()?;
        Ok(v.map(Level::from_i64))
    }

    pub fn set_alerted(&self, key: &str, level: Level) -> Result<()> {
        self.conn.execute(
            "INSERT INTO alerted (key, level, at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET level = MAX(level, excluded.level), at = excluded.at",
            params![key, level.as_i64(), now()],
        )?;
        Ok(())
    }

    /// Add an item to a queue. Returns false if the key was already queued.
    pub fn enqueue(&self, q: Queue, key: &str, item: &Item, reason: &str) -> Result<bool> {
        let json = serde_json::to_string(item)?;
        let n = self.conn.execute(
            &format!(
                "INSERT INTO {} (key, item, reason, queued_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(key) DO NOTHING",
                q.table()
            ),
            params![key, json, reason, now()],
        )?;
        Ok(n > 0)
    }

    pub fn queue_entries(&self, q: Queue) -> Result<Vec<DigestEntry>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT key, item, reason FROM {} ORDER BY queued_at, rowid",
            q.table()
        ))?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (key, json, reason) = row?;
            match serde_json::from_str::<Item>(&json) {
                Ok(item) => out.push(DigestEntry { key, item, reason }),
                Err(e) => tracing::warn!("dropping unreadable {:?} entry {key}: {e}", q),
            }
        }
        Ok(out)
    }

    pub fn dequeue(&self, q: Queue, key: &str) -> Result<()> {
        self.conn.execute(
            &format!("DELETE FROM {} WHERE key = ?1", q.table()),
            params![key],
        )?;
        Ok(())
    }

    pub fn add_pending(&self, source: &str, id: &str, data: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO pending (source, id, data, queued_at) VALUES (?1, ?2, ?3, ?4)",
            params![source, id, data, now()],
        )?;
        Ok(())
    }

    /// Oldest pending rows first.
    pub fn pending(&self, source: &str, limit: usize) -> Result<Vec<PendingRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, data, attempts FROM pending WHERE source = ?1
             ORDER BY queued_at, rowid LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![source, limit as i64], |r| {
            Ok(PendingRow {
                id: r.get(0)?,
                data: r.get(1)?,
                attempts: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn pending_count(&self, source: &str) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM pending WHERE source = ?1",
            params![source],
            |r| r.get(0),
        )?)
    }

    pub fn bump_pending_attempt(&self, source: &str, id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE pending SET attempts = attempts + 1 WHERE source = ?1 AND id = ?2",
            params![source, id],
        )?;
        Ok(())
    }

    pub fn remove_pending(&self, source: &str, id: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM pending WHERE source = ?1 AND id = ?2",
            params![source, id],
        )?;
        Ok(())
    }

    /// Drop pending rows that have already been handled (marked seen).
    pub fn prune_pending_seen(&self, source: &str) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM pending WHERE source = ?1
             AND id IN (SELECT id FROM seen WHERE source = ?1)",
            params![source],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seen_and_kv_roundtrip() {
        let mut db = Db::open_in_memory().unwrap();
        assert!(!db.is_seen("kev", "CVE-1").unwrap());
        db.mark_seen("kev", "CVE-1").unwrap();
        assert!(db.is_seen("kev", "CVE-1").unwrap());
        assert_eq!(db.mark_seen_many("kev", ["CVE-1", "CVE-2"]).unwrap(), 1);

        assert_eq!(db.get_kv("a").unwrap(), None);
        db.set_kv("a", "1").unwrap();
        db.set_kv("a", "2").unwrap();
        assert_eq!(db.get_kv("a").unwrap().as_deref(), Some("2"));
        db.del_kv("a").unwrap();
        assert_eq!(db.get_kv("a").unwrap(), None);
    }

    #[test]
    fn alerted_never_downgrades() {
        let db = Db::open_in_memory().unwrap();
        db.set_alerted("CVE-1", Level::Urgent).unwrap();
        db.set_alerted("CVE-1", Level::Digest).unwrap();
        assert_eq!(db.alerted_level("CVE-1").unwrap(), Some(Level::Urgent));
    }

    #[test]
    fn queues() {
        let db = Db::open_in_memory().unwrap();
        let mut item = Item::new("ghsa", "GHSA-1");
        item.title = "t".into();
        assert!(db.enqueue(Queue::Digest, "k1", &item, "r").unwrap());
        assert!(!db.enqueue(Queue::Digest, "k1", &item, "r2").unwrap());
        assert!(db.enqueue(Queue::Outbox, "k1", &item, "u").unwrap());
        let entries = db.queue_entries(Queue::Digest).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].item, item);
        assert_eq!(entries[0].reason, "r");
        db.dequeue(Queue::Digest, "k1").unwrap();
        assert!(db.queue_entries(Queue::Digest).unwrap().is_empty());
        assert_eq!(db.queue_entries(Queue::Outbox).unwrap().len(), 1);
    }

    #[test]
    fn pending_rows() {
        let db = Db::open_in_memory().unwrap();
        db.add_pending("cvelist", "CVE-1", "l1").unwrap();
        db.add_pending("cvelist", "CVE-2", "l2").unwrap();
        db.add_pending("cvelist", "CVE-1", "dup").unwrap();
        assert_eq!(db.pending_count("cvelist").unwrap(), 2);
        let rows = db.pending("cvelist", 1).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "CVE-1");
        assert_eq!(rows[0].data, "l1");
        db.bump_pending_attempt("cvelist", "CVE-1").unwrap();
        assert_eq!(db.pending("cvelist", 5).unwrap()[0].attempts, 1);
        db.mark_seen("cvelist", "CVE-1").unwrap();
        assert_eq!(db.prune_pending_seen("cvelist").unwrap(), 1);
        db.remove_pending("cvelist", "CVE-2").unwrap();
        assert_eq!(db.pending_count("cvelist").unwrap(), 0);
    }
}
