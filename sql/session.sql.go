// Code generated by pggen. DO NOT EDIT.

package sql

import (
	"context"
	"fmt"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"time"
)

const insertSessionSQL = `INSERT INTO sessions (
    token,
    created_at,
    updated_at,
    flash,
    address,
    expiry,
    user_id
) VALUES (
    $1,
    NOW(),
    NOW(),
    $2,
    $3,
    $4,
    $5
)
RETURNING *;`

type InsertSessionParams struct {
	Token   string
	Flash   []byte
	Address string
	Expiry  time.Time
	UserID  string
}

type InsertSessionRow struct {
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Address   string    `json:"address"`
	Flash     []byte    `json:"flash"`
	Expiry    time.Time `json:"expiry"`
	UserID    string    `json:"user_id"`
}

func (s InsertSessionRow) GetToken() string { return s.Token }
func (s InsertSessionRow) GetCreatedAt() time.Time { return s.CreatedAt }
func (s InsertSessionRow) GetUpdatedAt() time.Time { return s.UpdatedAt }
func (s InsertSessionRow) GetAddress() string { return s.Address }
func (s InsertSessionRow) GetFlash() []byte { return s.Flash }
func (s InsertSessionRow) GetExpiry() time.Time { return s.Expiry }
func (s InsertSessionRow) GetUserID() string { return s.UserID }


// InsertSession implements Querier.InsertSession.
func (q *DBQuerier) InsertSession(ctx context.Context, params InsertSessionParams) (InsertSessionRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "InsertSession")
	row := q.conn.QueryRow(ctx, insertSessionSQL, params.Token, params.Flash, params.Address, params.Expiry, params.UserID)
	var item InsertSessionRow
	if err := row.Scan(&item.Token, &item.CreatedAt, &item.UpdatedAt, &item.Address, &item.Flash, &item.Expiry, &item.UserID); err != nil {
		return item, fmt.Errorf("query InsertSession: %w", err)
	}
	return item, nil
}

// InsertSessionBatch implements Querier.InsertSessionBatch.
func (q *DBQuerier) InsertSessionBatch(batch genericBatch, params InsertSessionParams) {
	batch.Queue(insertSessionSQL, params.Token, params.Flash, params.Address, params.Expiry, params.UserID)
}

// InsertSessionScan implements Querier.InsertSessionScan.
func (q *DBQuerier) InsertSessionScan(results pgx.BatchResults) (InsertSessionRow, error) {
	row := results.QueryRow()
	var item InsertSessionRow
	if err := row.Scan(&item.Token, &item.CreatedAt, &item.UpdatedAt, &item.Address, &item.Flash, &item.Expiry, &item.UserID); err != nil {
		return item, fmt.Errorf("scan InsertSessionBatch row: %w", err)
	}
	return item, nil
}

const findSessionFlashByTokenSQL = `SELECT flash
FROM sessions
WHERE token = $1;`

// FindSessionFlashByToken implements Querier.FindSessionFlashByToken.
func (q *DBQuerier) FindSessionFlashByToken(ctx context.Context, token string) ([]byte, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "FindSessionFlashByToken")
	row := q.conn.QueryRow(ctx, findSessionFlashByTokenSQL, token)
	item := []byte{}
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("query FindSessionFlashByToken: %w", err)
	}
	return item, nil
}

// FindSessionFlashByTokenBatch implements Querier.FindSessionFlashByTokenBatch.
func (q *DBQuerier) FindSessionFlashByTokenBatch(batch genericBatch, token string) {
	batch.Queue(findSessionFlashByTokenSQL, token)
}

// FindSessionFlashByTokenScan implements Querier.FindSessionFlashByTokenScan.
func (q *DBQuerier) FindSessionFlashByTokenScan(results pgx.BatchResults) ([]byte, error) {
	row := results.QueryRow()
	item := []byte{}
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("scan FindSessionFlashByTokenBatch row: %w", err)
	}
	return item, nil
}

const updateSessionFlashByTokenSQL = `UPDATE sessions
SET
    flash = $1
WHERE token = $2;`

// UpdateSessionFlashByToken implements Querier.UpdateSessionFlashByToken.
func (q *DBQuerier) UpdateSessionFlashByToken(ctx context.Context, flash []byte, token string) (pgconn.CommandTag, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "UpdateSessionFlashByToken")
	cmdTag, err := q.conn.Exec(ctx, updateSessionFlashByTokenSQL, flash, token)
	if err != nil {
		return cmdTag, fmt.Errorf("exec query UpdateSessionFlashByToken: %w", err)
	}
	return cmdTag, err
}

// UpdateSessionFlashByTokenBatch implements Querier.UpdateSessionFlashByTokenBatch.
func (q *DBQuerier) UpdateSessionFlashByTokenBatch(batch genericBatch, flash []byte, token string) {
	batch.Queue(updateSessionFlashByTokenSQL, flash, token)
}

// UpdateSessionFlashByTokenScan implements Querier.UpdateSessionFlashByTokenScan.
func (q *DBQuerier) UpdateSessionFlashByTokenScan(results pgx.BatchResults) (pgconn.CommandTag, error) {
	cmdTag, err := results.Exec()
	if err != nil {
		return cmdTag, fmt.Errorf("exec UpdateSessionFlashByTokenBatch: %w", err)
	}
	return cmdTag, err
}

const updateSessionUserIDSQL = `UPDATE sessions
SET
    user_id = $1,
    updated_at = NOW()
WHERE token = $2
RETURNING *;`

type UpdateSessionUserIDRow struct {
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Address   string    `json:"address"`
	Flash     []byte    `json:"flash"`
	Expiry    time.Time `json:"expiry"`
	UserID    string    `json:"user_id"`
}

func (s UpdateSessionUserIDRow) GetToken() string { return s.Token }
func (s UpdateSessionUserIDRow) GetCreatedAt() time.Time { return s.CreatedAt }
func (s UpdateSessionUserIDRow) GetUpdatedAt() time.Time { return s.UpdatedAt }
func (s UpdateSessionUserIDRow) GetAddress() string { return s.Address }
func (s UpdateSessionUserIDRow) GetFlash() []byte { return s.Flash }
func (s UpdateSessionUserIDRow) GetExpiry() time.Time { return s.Expiry }
func (s UpdateSessionUserIDRow) GetUserID() string { return s.UserID }


// UpdateSessionUserID implements Querier.UpdateSessionUserID.
func (q *DBQuerier) UpdateSessionUserID(ctx context.Context, userID string, token string) (UpdateSessionUserIDRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "UpdateSessionUserID")
	row := q.conn.QueryRow(ctx, updateSessionUserIDSQL, userID, token)
	var item UpdateSessionUserIDRow
	if err := row.Scan(&item.Token, &item.CreatedAt, &item.UpdatedAt, &item.Address, &item.Flash, &item.Expiry, &item.UserID); err != nil {
		return item, fmt.Errorf("query UpdateSessionUserID: %w", err)
	}
	return item, nil
}

// UpdateSessionUserIDBatch implements Querier.UpdateSessionUserIDBatch.
func (q *DBQuerier) UpdateSessionUserIDBatch(batch genericBatch, userID string, token string) {
	batch.Queue(updateSessionUserIDSQL, userID, token)
}

// UpdateSessionUserIDScan implements Querier.UpdateSessionUserIDScan.
func (q *DBQuerier) UpdateSessionUserIDScan(results pgx.BatchResults) (UpdateSessionUserIDRow, error) {
	row := results.QueryRow()
	var item UpdateSessionUserIDRow
	if err := row.Scan(&item.Token, &item.CreatedAt, &item.UpdatedAt, &item.Address, &item.Flash, &item.Expiry, &item.UserID); err != nil {
		return item, fmt.Errorf("scan UpdateSessionUserIDBatch row: %w", err)
	}
	return item, nil
}

const updateSessionExpirySQL = `UPDATE sessions
SET
    expiry = $1,
    updated_at = NOW()
WHERE token = $2
RETURNING *;`

type UpdateSessionExpiryRow struct {
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Address   string    `json:"address"`
	Flash     []byte    `json:"flash"`
	Expiry    time.Time `json:"expiry"`
	UserID    string    `json:"user_id"`
}

func (s UpdateSessionExpiryRow) GetToken() string { return s.Token }
func (s UpdateSessionExpiryRow) GetCreatedAt() time.Time { return s.CreatedAt }
func (s UpdateSessionExpiryRow) GetUpdatedAt() time.Time { return s.UpdatedAt }
func (s UpdateSessionExpiryRow) GetAddress() string { return s.Address }
func (s UpdateSessionExpiryRow) GetFlash() []byte { return s.Flash }
func (s UpdateSessionExpiryRow) GetExpiry() time.Time { return s.Expiry }
func (s UpdateSessionExpiryRow) GetUserID() string { return s.UserID }


// UpdateSessionExpiry implements Querier.UpdateSessionExpiry.
func (q *DBQuerier) UpdateSessionExpiry(ctx context.Context, expiry time.Time, token string) (UpdateSessionExpiryRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "UpdateSessionExpiry")
	row := q.conn.QueryRow(ctx, updateSessionExpirySQL, expiry, token)
	var item UpdateSessionExpiryRow
	if err := row.Scan(&item.Token, &item.CreatedAt, &item.UpdatedAt, &item.Address, &item.Flash, &item.Expiry, &item.UserID); err != nil {
		return item, fmt.Errorf("query UpdateSessionExpiry: %w", err)
	}
	return item, nil
}

// UpdateSessionExpiryBatch implements Querier.UpdateSessionExpiryBatch.
func (q *DBQuerier) UpdateSessionExpiryBatch(batch genericBatch, expiry time.Time, token string) {
	batch.Queue(updateSessionExpirySQL, expiry, token)
}

// UpdateSessionExpiryScan implements Querier.UpdateSessionExpiryScan.
func (q *DBQuerier) UpdateSessionExpiryScan(results pgx.BatchResults) (UpdateSessionExpiryRow, error) {
	row := results.QueryRow()
	var item UpdateSessionExpiryRow
	if err := row.Scan(&item.Token, &item.CreatedAt, &item.UpdatedAt, &item.Address, &item.Flash, &item.Expiry, &item.UserID); err != nil {
		return item, fmt.Errorf("scan UpdateSessionExpiryBatch row: %w", err)
	}
	return item, nil
}

const updateSessionFlashSQL = `UPDATE sessions
SET
    flash = $1,
    updated_at = NOW()
WHERE token = $2
RETURNING *;`

type UpdateSessionFlashRow struct {
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Address   string    `json:"address"`
	Flash     []byte    `json:"flash"`
	Expiry    time.Time `json:"expiry"`
	UserID    string    `json:"user_id"`
}

func (s UpdateSessionFlashRow) GetToken() string { return s.Token }
func (s UpdateSessionFlashRow) GetCreatedAt() time.Time { return s.CreatedAt }
func (s UpdateSessionFlashRow) GetUpdatedAt() time.Time { return s.UpdatedAt }
func (s UpdateSessionFlashRow) GetAddress() string { return s.Address }
func (s UpdateSessionFlashRow) GetFlash() []byte { return s.Flash }
func (s UpdateSessionFlashRow) GetExpiry() time.Time { return s.Expiry }
func (s UpdateSessionFlashRow) GetUserID() string { return s.UserID }


// UpdateSessionFlash implements Querier.UpdateSessionFlash.
func (q *DBQuerier) UpdateSessionFlash(ctx context.Context, flash []byte, token string) (UpdateSessionFlashRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "UpdateSessionFlash")
	row := q.conn.QueryRow(ctx, updateSessionFlashSQL, flash, token)
	var item UpdateSessionFlashRow
	if err := row.Scan(&item.Token, &item.CreatedAt, &item.UpdatedAt, &item.Address, &item.Flash, &item.Expiry, &item.UserID); err != nil {
		return item, fmt.Errorf("query UpdateSessionFlash: %w", err)
	}
	return item, nil
}

// UpdateSessionFlashBatch implements Querier.UpdateSessionFlashBatch.
func (q *DBQuerier) UpdateSessionFlashBatch(batch genericBatch, flash []byte, token string) {
	batch.Queue(updateSessionFlashSQL, flash, token)
}

// UpdateSessionFlashScan implements Querier.UpdateSessionFlashScan.
func (q *DBQuerier) UpdateSessionFlashScan(results pgx.BatchResults) (UpdateSessionFlashRow, error) {
	row := results.QueryRow()
	var item UpdateSessionFlashRow
	if err := row.Scan(&item.Token, &item.CreatedAt, &item.UpdatedAt, &item.Address, &item.Flash, &item.Expiry, &item.UserID); err != nil {
		return item, fmt.Errorf("scan UpdateSessionFlashBatch row: %w", err)
	}
	return item, nil
}

const deleteSessionByTokenSQL = `DELETE
FROM sessions
WHERE token = $1;`

// DeleteSessionByToken implements Querier.DeleteSessionByToken.
func (q *DBQuerier) DeleteSessionByToken(ctx context.Context, token string) (pgconn.CommandTag, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "DeleteSessionByToken")
	cmdTag, err := q.conn.Exec(ctx, deleteSessionByTokenSQL, token)
	if err != nil {
		return cmdTag, fmt.Errorf("exec query DeleteSessionByToken: %w", err)
	}
	return cmdTag, err
}

// DeleteSessionByTokenBatch implements Querier.DeleteSessionByTokenBatch.
func (q *DBQuerier) DeleteSessionByTokenBatch(batch genericBatch, token string) {
	batch.Queue(deleteSessionByTokenSQL, token)
}

// DeleteSessionByTokenScan implements Querier.DeleteSessionByTokenScan.
func (q *DBQuerier) DeleteSessionByTokenScan(results pgx.BatchResults) (pgconn.CommandTag, error) {
	cmdTag, err := results.Exec()
	if err != nil {
		return cmdTag, fmt.Errorf("exec DeleteSessionByTokenBatch: %w", err)
	}
	return cmdTag, err
}

const deleteSessionsExpiredSQL = `DELETE
FROM sessions
WHERE expiry < current_timestamp;`

// DeleteSessionsExpired implements Querier.DeleteSessionsExpired.
func (q *DBQuerier) DeleteSessionsExpired(ctx context.Context) (pgconn.CommandTag, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "DeleteSessionsExpired")
	cmdTag, err := q.conn.Exec(ctx, deleteSessionsExpiredSQL)
	if err != nil {
		return cmdTag, fmt.Errorf("exec query DeleteSessionsExpired: %w", err)
	}
	return cmdTag, err
}

// DeleteSessionsExpiredBatch implements Querier.DeleteSessionsExpiredBatch.
func (q *DBQuerier) DeleteSessionsExpiredBatch(batch genericBatch) {
	batch.Queue(deleteSessionsExpiredSQL)
}

// DeleteSessionsExpiredScan implements Querier.DeleteSessionsExpiredScan.
func (q *DBQuerier) DeleteSessionsExpiredScan(results pgx.BatchResults) (pgconn.CommandTag, error) {
	cmdTag, err := results.Exec()
	if err != nil {
		return cmdTag, fmt.Errorf("exec DeleteSessionsExpiredBatch: %w", err)
	}
	return cmdTag, err
}
