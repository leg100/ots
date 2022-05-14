// Code generated by pggen. DO NOT EDIT.

package sql

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v4"
)

const insertApplyLogChunkSQL = `INSERT INTO apply_logs (
    apply_id,
    chunk
) VALUES (
    $1,
    $2
)
RETURNING *;`

type InsertApplyLogChunkRow struct {
	ApplyID string `json:"apply_id"`
	ChunkID int32  `json:"chunk_id"`
	Chunk   []byte `json:"chunk"`
}

// InsertApplyLogChunk implements Querier.InsertApplyLogChunk.
func (q *DBQuerier) InsertApplyLogChunk(ctx context.Context, applyID string, chunk []byte) (InsertApplyLogChunkRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "InsertApplyLogChunk")
	row := q.conn.QueryRow(ctx, insertApplyLogChunkSQL, applyID, chunk)
	var item InsertApplyLogChunkRow
	if err := row.Scan(&item.ApplyID, &item.ChunkID, &item.Chunk); err != nil {
		return item, fmt.Errorf("query InsertApplyLogChunk: %w", err)
	}
	return item, nil
}

// InsertApplyLogChunkBatch implements Querier.InsertApplyLogChunkBatch.
func (q *DBQuerier) InsertApplyLogChunkBatch(batch genericBatch, applyID string, chunk []byte) {
	batch.Queue(insertApplyLogChunkSQL, applyID, chunk)
}

// InsertApplyLogChunkScan implements Querier.InsertApplyLogChunkScan.
func (q *DBQuerier) InsertApplyLogChunkScan(results pgx.BatchResults) (InsertApplyLogChunkRow, error) {
	row := results.QueryRow()
	var item InsertApplyLogChunkRow
	if err := row.Scan(&item.ApplyID, &item.ChunkID, &item.Chunk); err != nil {
		return item, fmt.Errorf("scan InsertApplyLogChunkBatch row: %w", err)
	}
	return item, nil
}

const findApplyLogChunksSQL = `SELECT
    substring(string_agg(chunk, '') FROM $1 FOR $2)
FROM (
    SELECT apply_id, chunk
    FROM apply_logs
    WHERE apply_id = $3
    ORDER BY chunk_id
) c
GROUP BY apply_id
;`

type FindApplyLogChunksParams struct {
	Offset  int32
	Limit   int32
	ApplyID string
}

// FindApplyLogChunks implements Querier.FindApplyLogChunks.
func (q *DBQuerier) FindApplyLogChunks(ctx context.Context, params FindApplyLogChunksParams) ([]byte, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "FindApplyLogChunks")
	row := q.conn.QueryRow(ctx, findApplyLogChunksSQL, params.Offset, params.Limit, params.ApplyID)
	item := []byte{}
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("query FindApplyLogChunks: %w", err)
	}
	return item, nil
}

// FindApplyLogChunksBatch implements Querier.FindApplyLogChunksBatch.
func (q *DBQuerier) FindApplyLogChunksBatch(batch genericBatch, params FindApplyLogChunksParams) {
	batch.Queue(findApplyLogChunksSQL, params.Offset, params.Limit, params.ApplyID)
}

// FindApplyLogChunksScan implements Querier.FindApplyLogChunksScan.
func (q *DBQuerier) FindApplyLogChunksScan(results pgx.BatchResults) ([]byte, error) {
	row := results.QueryRow()
	item := []byte{}
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("scan FindApplyLogChunksBatch row: %w", err)
	}
	return item, nil
}
