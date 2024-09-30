// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: phase.sql

package sqlc

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

const findLogChunkByID = `-- name: FindLogChunkByID :one
SELECT
    chunk_id,
    run_id,
    phase,
    chunk,
    _offset AS offset
FROM logs
WHERE chunk_id = $1
`

type FindLogChunkByIDRow struct {
	ChunkID pgtype.Int4
	RunID   string
	Phase   string
	Chunk   []byte
	Offset  int32
}

func (q *Queries) FindLogChunkByID(ctx context.Context, chunkID pgtype.Int4) (FindLogChunkByIDRow, error) {
	row := q.db.QueryRow(ctx, findLogChunkByID, chunkID)
	var i FindLogChunkByIDRow
	err := row.Scan(
		&i.ChunkID,
		&i.RunID,
		&i.Phase,
		&i.Chunk,
		&i.Offset,
	)
	return i, err
}

const findLogs = `-- name: FindLogs :one
SELECT
    string_agg(chunk, '')
FROM (
    SELECT run_id, phase, chunk
    FROM logs
    WHERE run_id = $1
    AND   phase  = $2
    ORDER BY chunk_id
) c
GROUP BY run_id, phase
`

type FindLogsParams struct {
	RunID string
	Phase string
}

// FindLogs retrieves all the logs for the given run and phase.
func (q *Queries) FindLogs(ctx context.Context, arg FindLogsParams) ([]byte, error) {
	row := q.db.QueryRow(ctx, findLogs, arg.RunID, arg.Phase)
	var string_agg []byte
	err := row.Scan(&string_agg)
	return string_agg, err
}

const insertLogChunk = `-- name: InsertLogChunk :one
INSERT INTO logs (
    run_id,
    phase,
    chunk,
    _offset
) VALUES (
    $1,
    $2,
    $3,
    $4
)
RETURNING chunk_id
`

type InsertLogChunkParams struct {
	RunID  string
	Phase  string
	Chunk  []byte
	Offset int32
}

func (q *Queries) InsertLogChunk(ctx context.Context, arg InsertLogChunkParams) (pgtype.Int4, error) {
	row := q.db.QueryRow(ctx, insertLogChunk,
		arg.RunID,
		arg.Phase,
		arg.Chunk,
		arg.Offset,
	)
	var chunk_id pgtype.Int4
	err := row.Scan(&chunk_id)
	return chunk_id, err
}

const insertPhaseStatusTimestamp = `-- name: InsertPhaseStatusTimestamp :exec
INSERT INTO phase_status_timestamps (
    run_id,
    phase,
    status,
    timestamp
) VALUES (
    $1,
    $2,
    $3,
    $4
)
`

type InsertPhaseStatusTimestampParams struct {
	RunID     string
	Phase     string
	Status    string
	Timestamp pgtype.Timestamptz
}

func (q *Queries) InsertPhaseStatusTimestamp(ctx context.Context, arg InsertPhaseStatusTimestampParams) error {
	_, err := q.db.Exec(ctx, insertPhaseStatusTimestamp,
		arg.RunID,
		arg.Phase,
		arg.Status,
		arg.Timestamp,
	)
	return err
}
