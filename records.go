package main

import (
	"database/sql"
	"errors"
)

// pageSize is the most records one pull returns; the client asks again
// while more is set.
const pageSize = 500

// Record is one synced item. The server never sees inside Data: what kind
// of item it is lives in the ciphertext too.
type Record struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Deleted  bool   `json:"deleted"`
	Data     []byte `json:"data"`
}

// Push is a record a device changed, against the revision it last saw of
// it (0 for one it made).
type Push struct {
	ID           string `json:"id"`
	BaseRevision int64  `json:"base_revision"`
	Deleted      bool   `json:"deleted"`
	Data         []byte `json:"data"`
}

// Applied is a pushed record the server took, at its new revision.
type Applied struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
}

// PushResult says which records went in and which were changed by another
// device since the pusher saw them; those come back as the server has them.
type PushResult struct {
	Applied   []Applied `json:"applied"`
	Conflicts []Record  `json:"conflicts"`
	Revision  int64     `json:"revision"`
}

// pull returns the records changed after since, oldest first.
func (s *Store) pull(userID, since int64) ([]Record, bool, int64, error) {
	rows, err := s.db.Query(
		"SELECT id, revision, deleted, data FROM records WHERE user_id = ? AND revision > ? ORDER BY revision LIMIT ?",
		userID, since, pageSize+1)
	if err != nil {
		return nil, false, 0, err
	}
	defer rows.Close()
	records := []Record{}
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.ID, &r.Revision, &r.Deleted, &r.Data); err != nil {
			return nil, false, 0, err
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, false, 0, err
	}
	more := len(records) > pageSize
	if more {
		records = records[:pageSize]
	}
	var revision int64
	err = s.db.QueryRow("SELECT revision FROM users WHERE id = ?", userID).Scan(&revision)
	return records, more, revision, err
}

// push stores records in one transaction. A record whose revision on the
// server is not the one the device based its change on is not touched.
func (s *Store) push(userID int64, pushes []Push) (PushResult, error) {
	result := PushResult{Applied: []Applied{}, Conflicts: []Record{}}
	err := s.inTx(func(tx *sql.Tx) error {
		var revision int64
		if err := tx.QueryRow("SELECT revision FROM users WHERE id = ?", userID).Scan(&revision); err != nil {
			return err
		}
		for _, p := range pushes {
			current, found, err := recordIn(tx, userID, p.ID)
			if err != nil {
				return err
			}
			// A record the server does not have is taken whatever its base:
			// only a password reset empties the server under a device.
			if found && current.Revision != p.BaseRevision {
				result.Conflicts = append(result.Conflicts, current)
				continue
			}
			revision++
			if err := putRecord(tx, userID, p, revision); err != nil {
				return err
			}
			result.Applied = append(result.Applied, Applied{p.ID, revision})
		}
		result.Revision = revision
		_, err := tx.Exec("UPDATE users SET revision = ? WHERE id = ?", revision, userID)
		return err
	})
	return result, err
}

func recordIn(tx *sql.Tx, userID int64, id string) (Record, bool, error) {
	var r Record
	err := tx.QueryRow("SELECT id, revision, deleted, data FROM records WHERE user_id = ? AND id = ?",
		userID, id).Scan(&r.ID, &r.Revision, &r.Deleted, &r.Data)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}

func putRecord(tx *sql.Tx, userID int64, p Push, revision int64) error {
	data := p.Data
	if p.Deleted {
		data = []byte{}
	}
	_, err := tx.Exec(`INSERT INTO records (user_id, id, revision, deleted, data) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (user_id, id) DO UPDATE SET revision = excluded.revision,
            deleted = excluded.deleted, data = excluded.data`,
		userID, p.ID, revision, p.Deleted, data)
	return err
}
