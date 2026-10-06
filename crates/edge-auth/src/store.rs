//! SQLite persistence. Secrets (tokens, codes, cookies) are stored only as
//! SHA-256 hashes; passkeys only as public credential data.

use crate::owner::OwnerCredential;
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};

pub type StoreResult<T> = Result<T, rusqlite::Error>;

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
    hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL, status TEXT NOT NULL, created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS access_by_grant ON access_tokens(grant_id);
CREATE INDEX IF NOT EXISTS refresh_by_grant ON refresh_tokens(grant_id);
"#;

#[derive(Clone, Debug)]
pub struct ClientRow {
    pub client_id: String,
    pub name: Option<String>,
    pub redirect_uris: Vec<String>,
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
    Rotated(GrantRow),
    Missing,
    /// A rotated token was presented again (or by another client): the whole
    /// grant was revoked.
    FamilyRevoked(String),
    Inactive,
}

pub struct Store {
    conn: Mutex<Connection>,
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
                "SELECT client_id, name, redirect_uris FROM clients WHERE client_id = ?1",
                [client_id],
                |r| {
                    let uris: String = r.get(2)?;
                    Ok(ClientRow {
                        client_id: r.get(0)?,
                        name: r.get(1)?,
                        redirect_uris: serde_json::from_str(&uris).unwrap_or_default(),
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

    /// Make room for one more live pending request from client network `net`:
    /// drop that network's oldest live requests beyond `per_net - 1`, then, if
    /// the table holds `max` live requests, the oldest one not yet backed by a
    /// passkey proof. Returns false only if every live request is verified.
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
                SELECT id FROM pending WHERE net = ?1 AND expires > ?2 AND used = 0
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
                    scope, expires, verified_at, used FROM pending WHERE id = ?1",
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

    #[allow(clippy::too_many_arguments)]
    pub fn create_grant_with_code(
        &self,
        grant_id: &str,
        client_id: &str,
        backend: &str,
        scope: &str,
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
                status, gen) VALUES (?1, ?2, ?3, ?4, '{}', ?5, ?6, 'pending', 1)",
            params![grant_id, client_id, backend, scope, now, grant_expires],
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
    ) -> StoreResult<RefreshOutcome> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let row: Option<(String, String)> = tx
            .query_row(
                "SELECT grant_id, status FROM refresh_tokens WHERE hash = ?1",
                [old_hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((grant_id, status)) = row else {
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
        if status != "active" || grant.client_id != client_id {
            revoke_grant_tx(&tx, &grant_id)?;
            tx.commit()?;
            return Ok(RefreshOutcome::FamilyRevoked(grant_id));
        }
        if grant.status != "active" || grant.expires <= now {
            return Ok(RefreshOutcome::Inactive);
        }
        if expected_backend.is_some_and(|b| b != grant.backend) {
            return Ok(RefreshOutcome::Inactive);
        }
        tx.execute(
            "UPDATE refresh_tokens SET status = 'rotated' WHERE hash = ?1",
            [old_hash],
        )?;
        tx.execute(
            "INSERT INTO refresh_tokens (hash, grant_id, status, created) VALUES (?1, ?2, 'active', ?3)",
            params![refresh_hash, grant_id, now],
        )?;
        tx.execute(
            "INSERT INTO access_tokens (hash, grant_id, expires) VALUES (?1, ?2, ?3)",
            params![access_hash, grant_id, access_expires],
        )?;
        tx.commit()?;
        Ok(RefreshOutcome::Rotated(grant))
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
        if let Some(g) = &grant {
            conn.execute(
                "UPDATE grants SET last_used = ?2 WHERE id = ?1",
                params![g.id, now],
            )?;
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

    pub fn revoke_grant(&self, grant_id: &str) -> StoreResult<bool> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = revoke_grant_tx(&tx, grant_id)?;
        tx.commit()?;
        Ok(changed)
    }

    pub fn revoke_all_grants(&self) -> StoreResult<Vec<String>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let ids: Vec<String> = {
            let mut stmt =
                tx.prepare("SELECT id FROM grants WHERE status IN ('active', 'pending')")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        for id in &ids {
            revoke_grant_tx(&tx, id)?;
        }
        tx.commit()?;
        Ok(ids)
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

fn revoke_grant_tx(tx: &rusqlite::Transaction<'_>, grant_id: &str) -> StoreResult<bool> {
    let n = tx.execute(
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
    Ok(n == 1)
}
