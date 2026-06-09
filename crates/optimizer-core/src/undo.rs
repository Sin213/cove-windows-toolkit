use chrono::Utc;
use rusqlite::{Connection, params};
use crate::operation::Operation;
use crate::types::SafetyTier;

pub struct UndoLog {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct UndoEntry {
    pub id: i64,
    pub session_id: String,
    pub timestamp: String,
    pub module: String,
    pub display_name: String,
    pub safety_tier: String,
    pub operation: String,
    pub inverse_op: String,
    pub status: String,
}

impl UndoLog {
    pub fn open(path: &std::path::Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS undo_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                module      TEXT NOT NULL,
                display_name TEXT NOT NULL,
                safety_tier TEXT NOT NULL,
                operation   TEXT NOT NULL,
                inverse_op  TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'PENDING'
            );
            CREATE INDEX IF NOT EXISTS idx_session ON undo_log(session_id);
            CREATE INDEX IF NOT EXISTS idx_status ON undo_log(status);
            CREATE INDEX IF NOT EXISTS idx_timestamp ON undo_log(timestamp DESC);"
        )?;
        Ok(Self { conn })
    }

    pub fn record(
        &self,
        session_id: &str,
        module: &str,
        display_name: &str,
        safety_tier: SafetyTier,
        operation: &Operation,
    ) -> Result<i64, Box<dyn std::error::Error>> {
        let inverse = operation.inverse().ok_or("No inverse for this operation")?;
        let op_json = serde_json::to_string(operation)?;
        let inv_json = serde_json::to_string(&inverse)?;
        let tier_str = match safety_tier {
            SafetyTier::Green => "green",
            SafetyTier::Yellow => "yellow",
            SafetyTier::Red => "red",
        };
        self.conn.execute(
            "INSERT INTO undo_log (session_id, timestamp, module, display_name, safety_tier, operation, inverse_op, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'PENDING')",
            params![session_id, Utc::now().to_rfc3339(), module, display_name, tier_str, op_json, inv_json],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn mark_committed(&self, id: i64) -> Result<(), rusqlite::Error> {
        self.conn.execute("UPDATE undo_log SET status = 'COMMITTED' WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn mark_failed(&self, id: i64) -> Result<(), rusqlite::Error> {
        self.conn.execute("UPDATE undo_log SET status = 'FAILED' WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn mark_undone(&self, id: i64) -> Result<(), rusqlite::Error> {
        self.conn.execute("UPDATE undo_log SET status = 'UNDONE' WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn get_committed(&self) -> Result<Vec<UndoEntry>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, timestamp, module, display_name, safety_tier, operation, inverse_op, status
             FROM undo_log WHERE status = 'COMMITTED' ORDER BY timestamp DESC"
        )?;
        let entries = stmt.query_map([], |row| {
            Ok(UndoEntry {
                id: row.get(0)?,
                session_id: row.get(1)?,
                timestamp: row.get(2)?,
                module: row.get(3)?,
                display_name: row.get(4)?,
                safety_tier: row.get(5)?,
                operation: row.get(6)?,
                inverse_op: row.get(7)?,
                status: row.get(8)?,
            })
        })?.collect::<Result<Vec<_>, _>>()?;
        Ok(entries)
    }

    pub fn get_pending(&self) -> Result<Vec<UndoEntry>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, timestamp, module, display_name, safety_tier, operation, inverse_op, status
             FROM undo_log WHERE status = 'PENDING' ORDER BY id ASC"
        )?;
        let entries = stmt.query_map([], |row| {
            Ok(UndoEntry {
                id: row.get(0)?,
                session_id: row.get(1)?,
                timestamp: row.get(2)?,
                module: row.get(3)?,
                display_name: row.get(4)?,
                safety_tier: row.get(5)?,
                operation: row.get(6)?,
                inverse_op: row.get(7)?,
                status: row.get(8)?,
            })
        })?.collect::<Result<Vec<_>, _>>()?;
        Ok(entries)
    }
}
