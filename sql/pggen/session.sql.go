// Code generated by pggen. DO NOT EDIT.

package pggen

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
)

const insertSessionSQL = `INSERT INTO sessions (
    token,
    created_at,
    address,
    expiry,
    user_id
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
);`

type InsertSessionParams struct {
	Token     pgtype.Text
	CreatedAt time.Time
	Address   pgtype.Text
	Expiry    time.Time
	UserID    pgtype.Text
}

// InsertSession implements Querier.InsertSession.
func (q *DBQuerier) InsertSession(ctx context.Context, params InsertSessionParams) (pgconn.CommandTag, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "InsertSession")
	cmdTag, err := q.conn.Exec(ctx, insertSessionSQL, params.Token, params.CreatedAt, params.Address, params.Expiry, params.UserID)
	if err != nil {
		return cmdTag, fmt.Errorf("exec query InsertSession: %w", err)
	}
	return cmdTag, err
}

// InsertSessionBatch implements Querier.InsertSessionBatch.
func (q *DBQuerier) InsertSessionBatch(batch genericBatch, params InsertSessionParams) {
	batch.Queue(insertSessionSQL, params.Token, params.CreatedAt, params.Address, params.Expiry, params.UserID)
}

// InsertSessionScan implements Querier.InsertSessionScan.
func (q *DBQuerier) InsertSessionScan(results pgx.BatchResults) (pgconn.CommandTag, error) {
	cmdTag, err := results.Exec()
	if err != nil {
		return cmdTag, fmt.Errorf("exec InsertSessionBatch: %w", err)
	}
	return cmdTag, err
}

const updateSessionExpirySQL = `UPDATE sessions
SET
    expiry = $1
WHERE token = $2
RETURNING token
;`

// UpdateSessionExpiry implements Querier.UpdateSessionExpiry.
func (q *DBQuerier) UpdateSessionExpiry(ctx context.Context, expiry time.Time, token pgtype.Text) (pgtype.Text, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "UpdateSessionExpiry")
	row := q.conn.QueryRow(ctx, updateSessionExpirySQL, expiry, token)
	var item pgtype.Text
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("query UpdateSessionExpiry: %w", err)
	}
	return item, nil
}

// UpdateSessionExpiryBatch implements Querier.UpdateSessionExpiryBatch.
func (q *DBQuerier) UpdateSessionExpiryBatch(batch genericBatch, expiry time.Time, token pgtype.Text) {
	batch.Queue(updateSessionExpirySQL, expiry, token)
}

// UpdateSessionExpiryScan implements Querier.UpdateSessionExpiryScan.
func (q *DBQuerier) UpdateSessionExpiryScan(results pgx.BatchResults) (pgtype.Text, error) {
	row := results.QueryRow()
	var item pgtype.Text
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("scan UpdateSessionExpiryBatch row: %w", err)
	}
	return item, nil
}

const deleteSessionByTokenSQL = `DELETE
FROM sessions
WHERE token = $1
RETURNING token
;`

// DeleteSessionByToken implements Querier.DeleteSessionByToken.
func (q *DBQuerier) DeleteSessionByToken(ctx context.Context, token pgtype.Text) (pgtype.Text, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "DeleteSessionByToken")
	row := q.conn.QueryRow(ctx, deleteSessionByTokenSQL, token)
	var item pgtype.Text
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("query DeleteSessionByToken: %w", err)
	}
	return item, nil
}

// DeleteSessionByTokenBatch implements Querier.DeleteSessionByTokenBatch.
func (q *DBQuerier) DeleteSessionByTokenBatch(batch genericBatch, token pgtype.Text) {
	batch.Queue(deleteSessionByTokenSQL, token)
}

// DeleteSessionByTokenScan implements Querier.DeleteSessionByTokenScan.
func (q *DBQuerier) DeleteSessionByTokenScan(results pgx.BatchResults) (pgtype.Text, error) {
	row := results.QueryRow()
	var item pgtype.Text
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("scan DeleteSessionByTokenBatch row: %w", err)
	}
	return item, nil
}

const deleteSessionsExpiredSQL = `DELETE
FROM sessions
WHERE expiry < current_timestamp
RETURNING token
;`

// DeleteSessionsExpired implements Querier.DeleteSessionsExpired.
func (q *DBQuerier) DeleteSessionsExpired(ctx context.Context) (pgtype.Text, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "DeleteSessionsExpired")
	row := q.conn.QueryRow(ctx, deleteSessionsExpiredSQL)
	var item pgtype.Text
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("query DeleteSessionsExpired: %w", err)
	}
	return item, nil
}

// DeleteSessionsExpiredBatch implements Querier.DeleteSessionsExpiredBatch.
func (q *DBQuerier) DeleteSessionsExpiredBatch(batch genericBatch) {
	batch.Queue(deleteSessionsExpiredSQL)
}

// DeleteSessionsExpiredScan implements Querier.DeleteSessionsExpiredScan.
func (q *DBQuerier) DeleteSessionsExpiredScan(results pgx.BatchResults) (pgtype.Text, error) {
	row := results.QueryRow()
	var item pgtype.Text
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("scan DeleteSessionsExpiredBatch row: %w", err)
	}
	return item, nil
}
