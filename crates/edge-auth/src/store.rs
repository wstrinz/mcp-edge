//! SQLite persistence. Secrets (tokens, codes, cookies) are stored only as
//! SHA-256 hashes; passkeys only as public credential data.

use crate::owner::OwnerCredential;
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};

pub type StoreResult<T> = Result<T, rusqlite::Error>;

/// Seconds between `last_used` writes for one grant.
const LAST_USED_RESOLUTION: i64 = 60;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS consumed_enroll_codes (hash TEXT PRIMARY KEY, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS passkeys (
    cred_id TEXT PRIMARY KEY, data TEXT NOT NULL, created INTEGER NOT NULL, last_used INTEGER);
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY, name TEXT, redirect_uris TEXT NOT NULL, created INTEGER NOT NULL,
    ever_granted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions (
    hash TEXT PRIMARY KEY, auth_at INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS pending (
    id TEXT PRIMARY KEY, binding_hash TEXT NOT NULL, client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL, state TEXT NOT NULL, code_challenge TEXT NOT NULL,
    backend TEXT NOT NULL, scope TEXT NOT NULL, created INTEGER NOT NULL,
    expires INTEGER NOT NULL, verified_at INTEGER, used INTEGER NOT NULL DEFAULT 0,
    net TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY, client_id TEXT NOT NULL, backend TEXT NOT NULL, scope TEXT NOT NULL,
    resource_scope TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL,
    status TEXT NOT NULL, gen INTEGER NOT NULL, last_used INTEGER);
CREATE TABLE IF NOT EXISTS codes (
    hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL, client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, backend TEXT NOT NULL,
    expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS access_tokens (
    hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL, status TEXT NOT NULL, created INTEGER NOT NULL,
    rotated_at INTEGER, successor TEXT);
CREATE INDEX IF NOT EXISTS access_by_grant ON access_tokens(grant_id);
CREATE INDEX IF NOT EXISTS refresh_by_grant ON refresh_tokens(grant_id);
"#;

#[derive(Clone, Debug)]
pub struct ClientRow {
    pub client_id: String,
    pub name: Option<String>,
    pub redirect_uris: Vec<String>,
    /// Registration time (Unix seconds).
    pub created: i64,
}

#[derive(Clone, Debug)]
pub struct PendingRow {
    pub id: String,
    pub binding_hash: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub code_challenge: String,
    pub backend: String,
    pub scope: String,
    pub created: i64,
    pub expires: i64,
    pub verified_at: Option<i64>,
    pub used: bool,
}

#[derive(Clone, Debug)]
pub struct GrantRow {
    pub id: String,
    pub client_id: String,
    pub backend: String,
    pub scope: String,
    pub resource_scope: String,
    pub created: i64,
    pub expires: i64,
    pub status: String,
    pub gen: i64,
    pub last_used: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct CodeRow {
    pub grant_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub challenge: String,
    pub backend: String,
    pub expires: i64,
}

pub enum CodeTake {
    Fresh(CodeRow),
    /// The code was already used; carries its grant so it can be revoked.
    Reused(String),
    Missing,
}

pub enum RefreshOutcome {
    /// New pair issued; `grace` when an immediately-previous token was
    /// re-presented within the grace window.
    Rotated {
        grant: GrantRow,
        grace: bool,
    },
    Missing,
    /// A rotated token was presented again (or by another client): the whole
    /// grant was revoked (`Some` when this call changed its state).
    FamilyRevoked(String, Option<Revoked>),
    Inactive,
}

/// A grant this call moved to `revoked`: its backend and the `gen` it had
/// while live (the value its assertions carried).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revoked {
    pub id: String,
    pub backend: String,
    pub gen: i64,
}

pub struct Store {
    conn: Mutex<Connection>,
}

/// Columns added after phase 2 (existing databases are upgraded in place).
fn migrate(conn: &Connection) -> StoreResult<()> {
    let has_approval: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('grants') WHERE name = 'approval'",
        [],
        |r| r.get(0),
    )?;
    if has_approval == 0 {
        // Phase 4: the origin's signed approval, kept as evidence.
        conn.execute_batch("ALTER TABLE grants ADD COLUMN approval TEXT")?;
    }
    Ok(())
}

fn grant_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<GrantRow> {
    Ok(GrantRow {
        id: r.get(0)?,
        client_id: r.get(1)?,
        backend: r.get(2)?,
        scope: r.get(3)?,
        resource_scope: r.get(4)?,
        created: r.get(5)?,
        expires: r.get(6)?,
        status: r.get(7)?,
        gen: r.get(8)?,
        last_used: r.get(9)?,
    })
}

const GRANT_COLS: &str =
    "id, client_id, backend, scope, resource_scope, created, expires, status, gen, last_used";

impl Store {
    /// Open (or create) the database; `None` uses an in-memory database.
    pub fn open(path: Option<&Path>) -> StoreResult<Self> {
        let conn = match path {
            Some(p) => Connection::open(p)?,
            None => Connection::open_in_memory()?,
        };
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn ping(&self) -> bool {
        self.conn()
            .query_row("SELECT 1", [], |r| r.get::<_, i64>(0))
            .is_ok()
    }

    /// The stable owner id (created on first use).
    pub fn owner_id(&self, fresh: impl FnOnce() -> String) -> StoreResult<String> {
        let conn = self.conn();
        if let Some(v) = conn
            .query_row("SELECT v FROM meta WHERE k = 'owner_id'", [], |r| r.get(0))
            .optional()?
        {
            return Ok(v);
        }
        let id = fresh();
        conn.execute("INSERT INTO meta (k, v) VALUES ('owner_id', ?1)", [&id])?;
        Ok(id)
    }

    // ---- passkeys / enrollment ----

    pub fn passkeys(&self) -> StoreResult<Vec<OwnerCredential>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT cred_id, data FROM passkeys ORDER BY created")?;
        let rows = stmt.query_map([], |r| {
            Ok(OwnerCredential {
                cred_id: r.get(0)?,
                data: r.get(1)?,
            })
        })?;
        rows.collect()
    }

    pub fn passkey_count(&self) -> StoreResult<i64> {
        self.conn()
            .query_row("SELECT COUNT(*) FROM passkeys", [], |r| r.get(0))
    }

    pub fn enroll_code_consumed(&self, code_hash: &str) -> StoreResult<bool> {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM consumed_enroll_codes WHERE hash = ?1",
                [code_hash],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
    }

    /// Atomically: no passkey exists yet and the code is unused → store the
    /// passkey and consume the code. Returns false if either check failed.
    pub fn enroll_first_passkey(
        &self,
        code_hash: &str,
        cred: &OwnerCredential,
        now: i64,
    ) -> StoreResult<bool> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let existing: i64 = tx.query_row("SELECT COUNT(*) FROM passkeys", [], |r| r.get(0))?;
        let consumed: i64 = tx.query_row(
            "SELECT COUNT(*) FROM consumed_enroll_codes WHERE hash = ?1",
            [code_hash],
            |r| r.get(0),
        )?;
        if existing > 0 || consumed > 0 {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO consumed_enroll_codes (hash, at) VALUES (?1, ?2)",
            params![code_hash, now],
        )?;
        tx.execute(
            "INSERT INTO passkeys (cred_id, data, created) VALUES (?1, ?2, ?3)",
            params![cred.cred_id, cred.data, now],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn add_passkey(&self, cred: &OwnerCredential, now: i64) -> StoreResult<bool> {
        let n = self.conn().execute(
            "INSERT OR IGNORE INTO passkeys (cred_id, data, created) VALUES (?1, ?2, ?3)",
            params![cred.cred_id, cred.data, now],
        )?;
        Ok(n == 1)
    }

    pub fn passkey_used(&self, cred_id: &str, data: Option<&str>, now: i64) -> StoreResult<()> {
        let conn = self.conn();
        match data {
            Some(d) => conn.execute(
                "UPDATE passkeys SET data = ?2, last_used = ?3 WHERE cred_id = ?1",
                params![cred_id, d, now],
            )?,
            None => conn.execute(
                "UPDATE passkeys SET last_used = ?2 WHERE cred_id = ?1",
                params![cred_id, now],
            )?,
        };
        Ok(())
    }

    // ---- clients ----

    pub fn client_count(&self) -> StoreResult<i64> {
        self.conn()
            .query_row("SELECT COUNT(*) FROM clients", [], |r| r.get(0))
    }

    /// Remove registrations that never obtained a grant and are older than `before`.
    pub fn prune_unused_clients(&self, before: i64) -> StoreResult<usize> {
        self.conn().execute(
            "DELETE FROM clients WHERE ever_granted = 0 AND created < ?1",
            [before],
        )
    }

    pub fn insert_client(
        &self,
        client_id: &str,
        name: Option<&str>,
        redirect_uris: &[String],
        now: i64,
    ) -> StoreResult<()> {
        let uris = serde_json::to_string(redirect_uris).unwrap_or_else(|_| "[]".into());
        self.conn().execute(
            "INSERT INTO clients (client_id, name, redirect_uris, created) VALUES (?1, ?2, ?3, ?4)",
            params![client_id, name, uris, now],
        )?;
        Ok(())
    }

    pub fn client(&self, client_id: &str) -> StoreResult<Option<ClientRow>> {
        self.conn()
            .query_row(
                "SELECT client_id, name, redirect_uris, created FROM clients WHERE client_id = ?1",
                [client_id],
                |r| {
                    let uris: String = r.get(2)?;
                    Ok(ClientRow {
                        client_id: r.get(0)?,
                        name: r.get(1)?,
                        redirect_uris: serde_json::from_str(&uris).unwrap_or_default(),
                        created: r.get(3)?,
                    })
                },
            )
            .optional()
    }

    // ---- owner sessions ----

    pub fn insert_session(&self, hash: &str, now: i64, expires: i64) -> StoreResult<()> {
        self.conn().execute(
            "INSERT INTO sessions (hash, auth_at, expires) VALUES (?1, ?2, ?3)",
            params![hash, now, expires],
        )?;
        Ok(())
    }

    /// Returns the session's authentication time if it is still valid.
    pub fn session(&self, hash: &str, now: i64) -> StoreResult<Option<i64>> {
        self.conn()
            .query_row(
                "SELECT auth_at FROM sessions WHERE hash = ?1 AND expires > ?2",
                params![hash, now],
                |r| r.get(0),
            )
            .optional()
    }

    pub fn delete_session(&self, hash: &str) -> StoreResult<()> {
        self.conn()
            .execute("DELETE FROM sessions WHERE hash = ?1", [hash])?;
        Ok(())
    }

    // ---- pending authorization requests ----

    /// Make room for one more live pending request from client network `net`.
    /// Verified requests (passkey proof done) are never evicted:
    /// 1. the network keeps at most `per_net - 1` others, dropping its oldest
    ///    unverified ones;
    /// 2. if the table holds `max` live requests, the oldest unverified one
    ///    anywhere is dropped.
    ///
    /// Returns false only when nothing evictable is left.
    pub fn make_room_for_pending(
        &self,
        net: &str,
        per_net: i64,
        max: i64,
        now: i64,
    ) -> StoreResult<bool> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM pending WHERE id IN (
                SELECT id FROM pending
                WHERE net = ?1 AND expires > ?2 AND used = 0 AND verified_at IS NULL
                ORDER BY created DESC, rowid DESC LIMIT -1 OFFSET ?3)",
            params![net, now, (per_net - 1).max(0)],
        )?;
        let live: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pending WHERE expires > ?1 AND used = 0",
            [now],
            |r| r.get(0),
        )?;
        if live < max {
            return Ok(true);
        }
        let removed = conn.execute(
            "DELETE FROM pending WHERE id IN (
                SELECT id FROM pending WHERE expires > ?1 AND used = 0 AND verified_at IS NULL
                ORDER BY created, rowid LIMIT ?2)",
            params![now, live - max + 1],
        )?;
        Ok(i64::try_from(removed).unwrap_or(0) > live - max)
    }

    pub fn insert_pending(&self, p: &PendingRow, net: &str, now: i64) -> StoreResult<()> {
        self.conn().execute(
            "INSERT INTO pending (id, binding_hash, client_id, redirect_uri, state, code_challenge,
                backend, scope, created, expires, net) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                p.id,
                p.binding_hash,
                p.client_id,
                p.redirect_uri,
                p.state,
                p.code_challenge,
                p.backend,
                p.scope,
                now,
                p.expires,
                net
            ],
        )?;
        Ok(())
    }

    pub fn pending(&self, id: &str) -> StoreResult<Option<PendingRow>> {
        self.conn()
            .query_row(
                "SELECT id, binding_hash, client_id, redirect_uri, state, code_challenge, backend,
                    scope, expires, verified_at, used, created FROM pending WHERE id = ?1",
                [id],
                |r| {
                    Ok(PendingRow {
                        id: r.get(0)?,
                        binding_hash: r.get(1)?,
                        client_id: r.get(2)?,
                        redirect_uri: r.get(3)?,
                        state: r.get(4)?,
                        code_challenge: r.get(5)?,
                        backend: r.get(6)?,
                        scope: r.get(7)?,
                        expires: r.get(8)?,
                        verified_at: r.get(9)?,
                        used: r.get::<_, i64>(10)? != 0,
                        created: r.get(11)?,
                    })
                },
            )
            .optional()
    }

    pub fn mark_pending_verified(&self, id: &str, now: i64) -> StoreResult<bool> {
        let n = self.conn().execute(
            "UPDATE pending SET verified_at = ?2 WHERE id = ?1 AND used = 0 AND expires > ?2",
            params![id, now],
        )?;
        Ok(n == 1)
    }

    /// One-shot: returns true only for the first caller.
    pub fn consume_pending(&self, id: &str, now: i64) -> StoreResult<bool> {
        let n = self.conn().execute(
            "UPDATE pending SET used = 1 WHERE id = ?1 AND used = 0 AND expires > ?2",
            params![id, now],
        )?;
        Ok(n == 1)
    }

    // ---- grants and codes ----

    /// Create a pending grant and its one-use code in one transaction.
    /// `resource_scope` is the JSON object assertions carry (`{}` for edge
    /// consent; the origin-approved scope for origin consent) and `approval`
    /// the origin's signed approval, stored as evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn create_grant_with_code(
        &self,
        grant_id: &str,
        client_id: &str,
        backend: &str,
        scope: &str,
        resource_scope: &str,
        approval: Option<&str>,
        grant_expires: i64,
        code_hash: &str,
        redirect_uri: &str,
        challenge: &str,
        code_expires: i64,
        now: i64,
    ) -> StoreResult<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO grants (id, client_id, backend, scope, resource_scope, created, expires,
                status, gen, approval) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', 1, ?8)",
            params![
                grant_id,
                client_id,
                backend,
                scope,
                resource_scope,
                now,
                grant_expires,
                approval
            ],
        )?;
        tx.execute(
            "INSERT INTO codes (hash, grant_id, client_id, redirect_uri, challenge, backend, expires)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![code_hash, grant_id, client_id, redirect_uri, challenge, backend, code_expires],
        )?;
        tx.execute(
            "UPDATE clients SET ever_granted = 1 WHERE client_id = ?1",
            [client_id],
        )?;
        tx.commit()
    }

    /// Mark a code used and return it; every presentation consumes it.
    pub fn take_code(&self, code_hash: &str) -> StoreResult<CodeTake> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let row = tx
            .query_row(
                "SELECT grant_id, client_id, redirect_uri, challenge, backend, expires, used
                    FROM codes WHERE hash = ?1",
                [code_hash],
                |r| {
                    Ok((
                        CodeRow {
                            grant_id: r.get(0)?,
                            client_id: r.get(1)?,
                            redirect_uri: r.get(2)?,
                            challenge: r.get(3)?,
                            backend: r.get(4)?,
                            expires: r.get(5)?,
                        },
                        r.get::<_, i64>(6)? != 0,
                    ))
                },
            )
            .optional()?;
        let outcome = match row {
            None => CodeTake::Missing,
            Some((code, true)) => CodeTake::Reused(code.grant_id),
            Some((code, false)) => {
                tx.execute("UPDATE codes SET used = 1 WHERE hash = ?1", [code_hash])?;
                CodeTake::Fresh(code)
            }
        };
        tx.commit()?;
        Ok(outcome)
    }

    /// pending → active, storing the first token pair.
    pub fn activate_grant(
        &self,
        grant_id: &str,
        access_hash: &str,
        access_expires: i64,
        refresh_hash: &str,
        now: i64,
    ) -> StoreResult<Option<GrantRow>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let n = tx.execute(
            "UPDATE grants SET status = 'active' WHERE id = ?1 AND status = 'pending' AND expires > ?2",
            params![grant_id, now],
        )?;
        if n != 1 {
            return Ok(None);
        }
        tx.execute(
            "INSERT INTO access_tokens (hash, grant_id, expires) VALUES (?1, ?2, ?3)",
            params![access_hash, grant_id, access_expires],
        )?;
        tx.execute(
            "INSERT INTO refresh_tokens (hash, grant_id, status, created) VALUES (?1, ?2, 'active', ?3)",
            params![refresh_hash, grant_id, now],
        )?;
        let grant = tx.query_row(
            &format!("SELECT {GRANT_COLS} FROM grants WHERE id = ?1"),
            [grant_id],
            grant_from_row,
        )?;
        tx.commit()?;
        Ok(Some(grant))
    }

    /// Refresh-token rotation with family revocation on reuse.
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_refresh(
        &self,
        old_hash: &str,
        client_id: &str,
        expected_backend: Option<&str>,
        access_hash: &str,
        access_expires: i64,
        refresh_hash: &str,
        now: i64,
        grace_secs: i64,
    ) -> StoreResult<RefreshOutcome> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let row: Option<(String, String, Option<i64>, Option<String>)> = tx
            .query_row(
                "SELECT grant_id, status, rotated_at, successor FROM refresh_tokens WHERE hash = ?1",
                [old_hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((grant_id, status, rotated_at, successor)) = row else {
            return Ok(RefreshOutcome::Missing);
        };
        let grant = tx
            .query_row(
                &format!("SELECT {GRANT_COLS} FROM grants WHERE id = ?1"),
                [&grant_id],
                grant_from_row,
            )
            .optional()?;
        let Some(grant) = grant else {
            return Ok(RefreshOutcome::Missing);
        };
        // Grace: the immediately-previous token, re-presented by the same
        // client shortly after rotation (a lost response or a retry), continues
        // the family. "Immediately previous" = its successor is the current
        // active token.
        let grace_successor = match (status.as_str(), rotated_at, successor) {
            ("rotated", Some(at), Some(succ)) if now - at <= grace_secs => {
                let succ_active: Option<String> = tx
                    .query_row(
                        "SELECT status FROM refresh_tokens WHERE hash = ?1 AND grant_id = ?2",
                        params![succ, grant_id],
                        |r| r.get(0),
                    )
                    .optional()?;
                (succ_active.as_deref() == Some("active")).then_some(succ)
            }
            _ => None,
        };
        let replay = status != "active" && grace_successor.is_none();
        if replay || grant.client_id != client_id {
            let revoked = revoke_grant_tx(&tx, &grant_id)?;
            tx.commit()?;
            return Ok(RefreshOutcome::FamilyRevoked(grant_id, revoked));
        }
        if grant.status != "active" || grant.expires <= now {
            return Ok(RefreshOutcome::Inactive);
        }
        if expected_backend.is_some_and(|b| b != grant.backend) {
            return Ok(RefreshOutcome::Inactive);
        }
        match &grace_successor {
            // Retire the current active token in favour of the new one, and
            // point the re-presented token at it too (its rotated_at stays, so
            // the grace window does not extend).
            Some(current) => {
                tx.execute(
                    "UPDATE refresh_tokens SET status = 'rotated', rotated_at = ?2, successor = ?3
                        WHERE hash = ?1",
                    params![current, now, refresh_hash],
                )?;
                tx.execute(
                    "UPDATE refresh_tokens SET successor = ?2 WHERE hash = ?1",
                    params![old_hash, refresh_hash],
                )?;
            }
            None => {
                tx.execute(
                    "UPDATE refresh_tokens SET status = 'rotated', rotated_at = ?2, successor = ?3
                        WHERE hash = ?1",
                    params![old_hash, now, refresh_hash],
                )?;
            }
        }
        tx.execute(
            "INSERT INTO refresh_tokens (hash, grant_id, status, created) VALUES (?1, ?2, 'active', ?3)",
            params![refresh_hash, grant_id, now],
        )?;
        tx.execute(
            "INSERT INTO access_tokens (hash, grant_id, expires) VALUES (?1, ?2, ?3)",
            params![access_hash, grant_id, access_expires],
        )?;
        tx.commit()?;
        Ok(RefreshOutcome::Rotated {
            grant,
            grace: grace_successor.is_some(),
        })
    }

    /// Resolve an access token to its active grant.
    pub fn grant_for_access(&self, access_hash: &str, now: i64) -> StoreResult<Option<GrantRow>> {
        let conn = self.conn();
        let grant = conn
            .query_row(
                &format!(
                    "SELECT {} FROM grants g JOIN access_tokens a ON a.grant_id = g.id
                        WHERE a.hash = ?1 AND a.expires > ?2 AND g.status = 'active'
                        AND g.expires > ?2",
                    GRANT_COLS
                        .split(", ")
                        .map(|c| format!("g.{c}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                params![access_hash, now],
                grant_from_row,
            )
            .optional()?;
        // `last_used` is informational (owner page): write it at most once a
        // minute per grant instead of on every MCP request.
        if let Some(g) = &grant {
            if g.last_used.is_none_or(|t| now - t >= LAST_USED_RESOLUTION) {
                conn.execute(
                    "UPDATE grants SET last_used = ?2 WHERE id = ?1
                        AND (last_used IS NULL OR last_used <= ?2 - ?3)",
                    params![g.id, now, LAST_USED_RESOLUTION],
                )?;
            }
        }
        Ok(grant)
    }

    /// Grant id and client for a token of either kind (for RFC 7009 revocation).
    pub fn grant_for_any_token(&self, hash: &str) -> StoreResult<Option<(String, String)>> {
        let conn = self.conn();
        let grant_id: Option<String> = conn
            .query_row(
                "SELECT grant_id FROM access_tokens WHERE hash = ?1
                 UNION SELECT grant_id FROM refresh_tokens WHERE hash = ?1",
                [hash],
                |r| r.get(0),
            )
            .optional()?;
        let Some(grant_id) = grant_id else {
            return Ok(None);
        };
        conn.query_row(
            "SELECT id, client_id FROM grants WHERE id = ?1",
            [&grant_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
    }

    /// Revoke one grant (gen++). `Some` when this call changed its state.
    pub fn revoke_grant(&self, grant_id: &str) -> StoreResult<Option<Revoked>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = revoke_grant_tx(&tx, grant_id)?;
        tx.commit()?;
        Ok(changed)
    }

    pub fn revoke_all_grants(&self) -> StoreResult<Vec<Revoked>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let ids: Vec<String> = {
            let mut stmt =
                tx.prepare("SELECT id FROM grants WHERE status IN ('active', 'pending')")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut out = Vec::new();
        for id in &ids {
            if let Some(r) = revoke_grant_tx(&tx, id)? {
                out.push(r);
            }
        }
        tx.commit()?;
        Ok(out)
    }

    /// Active, unexpired grants of one backend: `(id, gen)`, oldest first.
    pub fn live_grants_for_backend(
        &self,
        backend: &str,
        now: i64,
    ) -> StoreResult<Vec<(String, i64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, gen FROM grants WHERE backend = ?1 AND status = 'active' AND expires > ?2
                ORDER BY created, id",
        )?;
        let rows = stmt.query_map(params![backend, now], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect()
    }

    /// Grants that ended without a revocation: active grants whose absolute
    /// lifetime passed in `(since, now]`, and pending grants (code never
    /// exchanged) that [`Store::cleanup`] is about to delete.
    pub fn ended_without_revocation(&self, since: i64, now: i64) -> StoreResult<Vec<Revoked>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, backend, gen FROM grants
                WHERE (status = 'active' AND expires > ?1 AND expires <= ?2)
                   OR (status = 'pending' AND created <= ?3)",
        )?;
        let rows = stmt.query_map(params![since, now, now - 3600], |r| {
            Ok(Revoked {
                id: r.get(0)?,
                backend: r.get(1)?,
                gen: r.get(2)?,
            })
        })?;
        rows.collect()
    }

    /// Record the origin EndpointId configured for `backend` (meta
    /// `origin:<backend>`). If it differs from the stored one (or none was
    /// stored), every live grant of the backend is revoked (gen++) and the new
    /// id stored, in one transaction. Returns whether a different id was
    /// stored before, and the revoked grants.
    pub fn bind_origin(&self, backend: &str, origin_id: &str) -> StoreResult<(bool, Vec<Revoked>)> {
        let key = format!("origin:{backend}");
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let stored: Option<String> = tx
            .query_row("SELECT v FROM meta WHERE k = ?1", [&key], |r| r.get(0))
            .optional()?;
        if stored.as_deref() == Some(origin_id) {
            return Ok((false, Vec::new()));
        }
        let ids: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT id FROM grants WHERE backend = ?1 AND status IN ('active', 'pending')",
            )?;
            let rows = stmt.query_map([backend], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut revoked = Vec::new();
        for id in &ids {
            if let Some(r) = revoke_grant_tx(&tx, id)? {
                revoked.push(r);
            }
        }
        tx.execute(
            "INSERT INTO meta (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![key, origin_id],
        )?;
        tx.commit()?;
        Ok((stored.is_some(), revoked))
    }

    pub fn active_grants(&self, now: i64) -> StoreResult<Vec<(GrantRow, Option<String>)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {}, c.name FROM grants g LEFT JOIN clients c ON c.client_id = g.client_id
                WHERE g.status = 'active' AND g.expires > ?1 ORDER BY g.created DESC",
            GRANT_COLS
                .split(", ")
                .map(|c| format!("g.{c}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))?;
        let rows = stmt.query_map([now], |r| Ok((grant_from_row(r)?, r.get(10)?)))?;
        rows.collect()
    }

    /// Drop expired state. Revoked/expired grants are kept for a week for the
    /// owner page and then removed.
    pub fn cleanup(&self, now: i64) -> StoreResult<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM pending WHERE expires <= ?1", [now])?;
        conn.execute("DELETE FROM codes WHERE expires <= ?1", [now - 3600])?;
        conn.execute("DELETE FROM sessions WHERE expires <= ?1", [now])?;
        conn.execute("DELETE FROM access_tokens WHERE expires <= ?1", [now])?;
        conn.execute(
            "DELETE FROM grants WHERE status = 'pending' AND created <= ?1",
            [now - 3600],
        )?;
        conn.execute(
            "DELETE FROM refresh_tokens WHERE grant_id IN
                (SELECT id FROM grants WHERE status != 'active' OR expires <= ?1)",
            [now],
        )?;
        conn.execute(
            "DELETE FROM grants WHERE (status = 'revoked' OR expires <= ?1) AND created <= ?2",
            params![now, now - 7 * 24 * 3600],
        )?;
        Ok(())
    }
}

fn revoke_grant_tx(tx: &rusqlite::Transaction<'_>, grant_id: &str) -> StoreResult<Option<Revoked>> {
    let live: Option<(String, i64)> = tx
        .query_row(
            "SELECT backend, gen FROM grants WHERE id = ?1 AND status IN ('active', 'pending')",
            [grant_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    tx.execute(
        "UPDATE grants SET status = 'revoked', gen = gen + 1
            WHERE id = ?1 AND status IN ('active', 'pending')",
        [grant_id],
    )?;
    tx.execute("DELETE FROM access_tokens WHERE grant_id = ?1", [grant_id])?;
    tx.execute(
        "UPDATE refresh_tokens SET status = 'revoked' WHERE grant_id = ?1",
        [grant_id],
    )?;
    tx.execute("UPDATE codes SET used = 1 WHERE grant_id = ?1", [grant_id])?;
    Ok(live.map(|(backend, gen)| Revoked {
        id: grant_id.to_owned(),
        backend,
        gen,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_used_is_written_at_most_once_a_minute() {
        let store = Store::open(None).unwrap();
        let t0 = 1_800_000_000;
        store
            .insert_client("c", None, &["https://cb.test/".to_string()], t0)
            .unwrap();
        store
            .create_grant_with_code(
                "g",
                "c",
                "echo",
                "mcp",
                "{}",
                None,
                t0 + 86_400,
                "code",
                "https://cb.test/",
                "ch",
                t0 + 60,
                t0,
            )
            .unwrap();
        store
            .activate_grant("g", "acc", t0 + 900, "ref", t0)
            .unwrap();
        let last_used = |s: &Store, now| s.active_grants(now).unwrap()[0].0.last_used;
        store.grant_for_access("acc", t0 + 1).unwrap().unwrap();
        assert_eq!(last_used(&store, t0 + 1), Some(t0 + 1));
        store.grant_for_access("acc", t0 + 30).unwrap().unwrap();
        assert_eq!(last_used(&store, t0 + 30), Some(t0 + 1), "throttled");
        store.grant_for_access("acc", t0 + 61).unwrap().unwrap();
        assert_eq!(last_used(&store, t0 + 61), Some(t0 + 61));
    }

    fn grant(store: &Store, id: &str, backend: &str, t0: i64, lifetime: i64) {
        store
            .create_grant_with_code(
                id,
                "c",
                backend,
                "s",
                "{\"v\":1}",
                Some("approval.sig"),
                t0 + lifetime,
                &format!("code-{id}"),
                "https://cb.test/",
                "ch",
                t0 + 60,
                t0,
            )
            .unwrap();
        store
            .activate_grant(id, &format!("acc-{id}"), t0 + 900, &format!("ref-{id}"), t0)
            .unwrap()
            .unwrap();
    }

    #[test]
    fn origin_rebinding_revokes_that_backends_grants_only() {
        let store = Store::open(None).unwrap();
        let t0 = 1_800_000_000;
        store
            .insert_client("c", None, &["https://cb.test/".to_string()], t0)
            .unwrap();
        // First binding: nothing stored yet, no grants.
        assert_eq!(store.bind_origin("wiskit", "aa").unwrap(), (false, vec![]));
        grant(&store, "g_1", "wiskit", t0, 3600);
        grant(&store, "g_2", "echo", t0, 3600);
        // Same id again: nothing happens.
        assert_eq!(store.bind_origin("wiskit", "aa").unwrap(), (false, vec![]));
        assert_eq!(
            store.live_grants_for_backend("wiskit", t0).unwrap().len(),
            1
        );
        // A different id: the backend's grants are revoked (gen++).
        let (changed, revoked) = store.bind_origin("wiskit", "bb").unwrap();
        assert!(changed);
        assert_eq!(
            revoked,
            vec![Revoked {
                id: "g_1".into(),
                backend: "wiskit".into(),
                gen: 1
            }]
        );
        assert!(store
            .live_grants_for_backend("wiskit", t0)
            .unwrap()
            .is_empty());
        assert_eq!(store.live_grants_for_backend("echo", t0).unwrap().len(), 1);
        // Revoking again reports nothing.
        assert_eq!(store.revoke_grant("g_1").unwrap(), None);
    }

    #[test]
    fn grants_ending_without_revocation_are_reported_once() {
        let store = Store::open(None).unwrap();
        let t0 = 1_800_000_000;
        store
            .insert_client("c", None, &["https://cb.test/".to_string()], t0)
            .unwrap();
        grant(&store, "g_short", "wiskit", t0, 600);
        grant(&store, "g_long", "wiskit", t0, 7200);
        assert!(store
            .ended_without_revocation(t0, t0 + 300)
            .unwrap()
            .is_empty());
        let ended = store.ended_without_revocation(t0 + 300, t0 + 900).unwrap();
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].id, "g_short");
        assert!(store
            .ended_without_revocation(t0 + 900, t0 + 1500)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn phase2_databases_gain_the_approval_column() {
        let path = std::env::temp_dir().join(format!(
            "edge-auth-migrate-{}.db",
            crate::support::random_id("")
        ));
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE grants (
                    id TEXT PRIMARY KEY, client_id TEXT NOT NULL, backend TEXT NOT NULL,
                    scope TEXT NOT NULL, resource_scope TEXT NOT NULL, created INTEGER NOT NULL,
                    expires INTEGER NOT NULL, status TEXT NOT NULL, gen INTEGER NOT NULL,
                    last_used INTEGER);
                 INSERT INTO grants VALUES ('g_old','c','echo','mcp','{}',1,2,'active',1,NULL);",
            )
            .unwrap();
        }
        let store = Store::open(Some(&path)).unwrap();
        let approval: Option<String> = store
            .conn()
            .query_row("SELECT approval FROM grants WHERE id = 'g_old'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(approval, None);
        drop(store);
        // Opening again is a no-op.
        drop(Store::open(Some(&path)).unwrap());
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
