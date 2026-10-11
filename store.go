package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// schemaVersion is the version a database is left at by migrate.
const schemaVersion = 1

const schema = `
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;
CREATE TABLE users (
    id                INTEGER PRIMARY KEY,
    username          TEXT NOT NULL UNIQUE,
    kdf_salt          BLOB NOT NULL,
    auth_hash         BLOB NOT NULL,
    wrapped_vault_key BLOB,
    revision          INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL
) STRICT;
CREATE TABLE sessions (
    token_hash   BLOB PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL
) STRICT;
CREATE INDEX sessions_user_id ON sessions(user_id);
CREATE TABLE records (
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id       TEXT NOT NULL,
    revision INTEGER NOT NULL,
    deleted  INTEGER NOT NULL CHECK (deleted IN (0, 1)),
    data     BLOB NOT NULL,
    PRIMARY KEY (user_id, id)
) STRICT;
CREATE INDEX records_revision ON records(user_id, revision);
`

var (
	errNoUser     = errors.New("no such user")
	errUserExists = errors.New("user already exists")
	errVaultSet   = errors.New("vault key already set")
)

// Store is the server's database. Everything a user syncs is ciphertext
// made on their devices; the server only orders it.
type Store struct {
	db *sql.DB
}

func openStore(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One writer keeps revisions strictly ordered without retry loops.
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	switch {
	case version == schemaVersion:
		return nil
	case version > schemaVersion:
		return fmt.Errorf("database is version %d, newer than this server (%d)", version, schemaVersion)
	}
	_, err := s.db.Exec("BEGIN;" + schema + fmt.Sprintf("PRAGMA user_version = %d; COMMIT;", schemaVersion))
	return err
}

// secret returns the server's own random value under key, making it on
// first use.
func (s *Store) secret(key string) ([]byte, error) {
	var value []byte
	err := s.db.QueryRow("SELECT value FROM meta WHERE key = ?", key).Scan(&value)
	if err == nil {
		return value, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	value = randomBytes(32)
	if _, err := s.db.Exec("INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)", key, value); err != nil {
		return nil, err
	}
	return s.secret(key)
}

type user struct {
	ID              int64
	Username        string
	KdfSalt         []byte
	AuthHash        []byte
	WrappedVaultKey []byte
	Revision        int64
}

func (s *Store) addUser(username string, salt, authHash []byte) error {
	_, err := s.db.Exec(
		"INSERT INTO users (username, kdf_salt, auth_hash, created_at) VALUES (?, ?, ?, ?)",
		username, salt, authHash, time.Now().Unix())
	if err != nil && isUniqueViolation(err) {
		return errUserExists
	}
	return err
}

// resetUser gives a user a new password. What they synced was sealed with a
// key from the old one, so it goes, and so do their sessions.
func (s *Store) resetUser(username string, salt, authHash []byte) error {
	return s.inTx(func(tx *sql.Tx) error {
		u, err := userIn(tx, username)
		if err != nil {
			return err
		}
		stmts := []struct {
			query string
			args  []any
		}{
			{"DELETE FROM records WHERE user_id = ?", []any{u.ID}},
			{"DELETE FROM sessions WHERE user_id = ?", []any{u.ID}},
			{"UPDATE users SET kdf_salt = ?, auth_hash = ?, wrapped_vault_key = NULL, revision = 0 WHERE id = ?",
				[]any{salt, authHash, u.ID}},
		}
		for _, stmt := range stmts {
			if _, err := tx.Exec(stmt.query, stmt.args...); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) deleteUser(username string) error {
	result, err := s.db.Exec("DELETE FROM users WHERE username = ?", username)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return errNoUser
	}
	return nil
}

type userSummary struct {
	Username string
	Records  int64
	Sessions int64
}

func (s *Store) listUsers() ([]userSummary, error) {
	rows, err := s.db.Query(`SELECT username,
        (SELECT COUNT(*) FROM records r WHERE r.user_id = u.id AND r.deleted = 0),
        (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id)
        FROM users u ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []userSummary
	for rows.Next() {
		var u userSummary
		if err := rows.Scan(&u.Username, &u.Records, &u.Sessions); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) user(username string) (user, error) {
	return userIn(s.db, username)
}

type querier interface {
	QueryRow(query string, args ...any) *sql.Row
}

func userIn(q querier, username string) (user, error) {
	var u user
	err := q.QueryRow(
		"SELECT id, username, kdf_salt, auth_hash, wrapped_vault_key, revision FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Username, &u.KdfSalt, &u.AuthHash, &u.WrappedVaultKey, &u.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return u, errNoUser
	}
	return u, err
}

func (s *Store) addSession(userID int64, tokenHash []byte, device string) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(
		"INSERT INTO sessions (token_hash, user_id, device, created_at, last_used_at) VALUES (?, ?, ?, ?, ?)",
		tokenHash, userID, device, now, now)
	return err
}

// sessionUser is the user a token belongs to, noting that it was used.
func (s *Store) sessionUser(tokenHash []byte) (int64, error) {
	var userID int64
	err := s.db.QueryRow(
		"UPDATE sessions SET last_used_at = ? WHERE token_hash = ? RETURNING user_id",
		time.Now().Unix(), tokenHash).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errNoUser
	}
	return userID, err
}

func (s *Store) deleteSession(tokenHash []byte) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE token_hash = ?", tokenHash)
	return err
}

func (s *Store) vaultKey(userID int64) ([]byte, error) {
	var key []byte
	err := s.db.QueryRow("SELECT wrapped_vault_key FROM users WHERE id = ?", userID).Scan(&key)
	return key, err
}

// setVaultKey stores the first device's vault key; later ones use it.
func (s *Store) setVaultKey(userID int64, key []byte) error {
	result, err := s.db.Exec(
		"UPDATE users SET wrapped_vault_key = ? WHERE id = ? AND wrapped_vault_key IS NULL", key, userID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return errVaultSet
	}
	return nil
}

func (s *Store) inTx(f func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	if err := f(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
