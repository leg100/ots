// Code generated by pggen. DO NOT EDIT.

package sql

import (
	"context"
	"fmt"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"time"
)

const insertPlanStatusTimestampSQL = `INSERT INTO plan_status_timestamps (
    run_id,
    status,
    timestamp
) VALUES (
    $1,
    $2,
    current_timestamp
)
RETURNING *;`

type InsertPlanStatusTimestampRow struct {
	RunID     string    `json:"run_id"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// InsertPlanStatusTimestamp implements Querier.InsertPlanStatusTimestamp.
func (q *DBQuerier) InsertPlanStatusTimestamp(ctx context.Context, id string, status string) (InsertPlanStatusTimestampRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "InsertPlanStatusTimestamp")
	row := q.conn.QueryRow(ctx, insertPlanStatusTimestampSQL, id, status)
	var item InsertPlanStatusTimestampRow
	if err := row.Scan(&item.RunID, &item.Status, &item.Timestamp); err != nil {
		return item, fmt.Errorf("query InsertPlanStatusTimestamp: %w", err)
	}
	return item, nil
}

// InsertPlanStatusTimestampBatch implements Querier.InsertPlanStatusTimestampBatch.
func (q *DBQuerier) InsertPlanStatusTimestampBatch(batch genericBatch, id string, status string) {
	batch.Queue(insertPlanStatusTimestampSQL, id, status)
}

// InsertPlanStatusTimestampScan implements Querier.InsertPlanStatusTimestampScan.
func (q *DBQuerier) InsertPlanStatusTimestampScan(results pgx.BatchResults) (InsertPlanStatusTimestampRow, error) {
	row := results.QueryRow()
	var item InsertPlanStatusTimestampRow
	if err := row.Scan(&item.RunID, &item.Status, &item.Timestamp); err != nil {
		return item, fmt.Errorf("scan InsertPlanStatusTimestampBatch row: %w", err)
	}
	return item, nil
}

const updatePlanStatusSQL = `UPDATE runs
SET
    plan_status = $1,
    updated_at = current_timestamp
WHERE plan_id = $2
RETURNING updated_at
;`

// UpdatePlanStatus implements Querier.UpdatePlanStatus.
func (q *DBQuerier) UpdatePlanStatus(ctx context.Context, status string, id string) (time.Time, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "UpdatePlanStatus")
	row := q.conn.QueryRow(ctx, updatePlanStatusSQL, status, id)
	var item time.Time
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("query UpdatePlanStatus: %w", err)
	}
	return item, nil
}

// UpdatePlanStatusBatch implements Querier.UpdatePlanStatusBatch.
func (q *DBQuerier) UpdatePlanStatusBatch(batch genericBatch, status string, id string) {
	batch.Queue(updatePlanStatusSQL, status, id)
}

// UpdatePlanStatusScan implements Querier.UpdatePlanStatusScan.
func (q *DBQuerier) UpdatePlanStatusScan(results pgx.BatchResults) (time.Time, error) {
	row := results.QueryRow()
	var item time.Time
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("scan UpdatePlanStatusBatch row: %w", err)
	}
	return item, nil
}

const getPlanBinByRunIDSQL = `SELECT plan_bin
FROM runs
WHERE run_id = $1
;`

// GetPlanBinByRunID implements Querier.GetPlanBinByRunID.
func (q *DBQuerier) GetPlanBinByRunID(ctx context.Context, runID string) ([]byte, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "GetPlanBinByRunID")
	row := q.conn.QueryRow(ctx, getPlanBinByRunIDSQL, runID)
	item := []byte{}
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("query GetPlanBinByRunID: %w", err)
	}
	return item, nil
}

// GetPlanBinByRunIDBatch implements Querier.GetPlanBinByRunIDBatch.
func (q *DBQuerier) GetPlanBinByRunIDBatch(batch genericBatch, runID string) {
	batch.Queue(getPlanBinByRunIDSQL, runID)
}

// GetPlanBinByRunIDScan implements Querier.GetPlanBinByRunIDScan.
func (q *DBQuerier) GetPlanBinByRunIDScan(results pgx.BatchResults) ([]byte, error) {
	row := results.QueryRow()
	item := []byte{}
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("scan GetPlanBinByRunIDBatch row: %w", err)
	}
	return item, nil
}

const getPlanJSONByRunIDSQL = `SELECT plan_json
FROM runs
WHERE run_id = $1
;`

// GetPlanJSONByRunID implements Querier.GetPlanJSONByRunID.
func (q *DBQuerier) GetPlanJSONByRunID(ctx context.Context, runID string) ([]byte, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "GetPlanJSONByRunID")
	row := q.conn.QueryRow(ctx, getPlanJSONByRunIDSQL, runID)
	item := []byte{}
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("query GetPlanJSONByRunID: %w", err)
	}
	return item, nil
}

// GetPlanJSONByRunIDBatch implements Querier.GetPlanJSONByRunIDBatch.
func (q *DBQuerier) GetPlanJSONByRunIDBatch(batch genericBatch, runID string) {
	batch.Queue(getPlanJSONByRunIDSQL, runID)
}

// GetPlanJSONByRunIDScan implements Querier.GetPlanJSONByRunIDScan.
func (q *DBQuerier) GetPlanJSONByRunIDScan(results pgx.BatchResults) ([]byte, error) {
	row := results.QueryRow()
	item := []byte{}
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("scan GetPlanJSONByRunIDBatch row: %w", err)
	}
	return item, nil
}

const putPlanBinByRunIDSQL = `UPDATE runs
SET plan_bin = $1
WHERE run_id = $2
;`

// PutPlanBinByRunID implements Querier.PutPlanBinByRunID.
func (q *DBQuerier) PutPlanBinByRunID(ctx context.Context, planBin []byte, runID string) (pgconn.CommandTag, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "PutPlanBinByRunID")
	cmdTag, err := q.conn.Exec(ctx, putPlanBinByRunIDSQL, planBin, runID)
	if err != nil {
		return cmdTag, fmt.Errorf("exec query PutPlanBinByRunID: %w", err)
	}
	return cmdTag, err
}

// PutPlanBinByRunIDBatch implements Querier.PutPlanBinByRunIDBatch.
func (q *DBQuerier) PutPlanBinByRunIDBatch(batch genericBatch, planBin []byte, runID string) {
	batch.Queue(putPlanBinByRunIDSQL, planBin, runID)
}

// PutPlanBinByRunIDScan implements Querier.PutPlanBinByRunIDScan.
func (q *DBQuerier) PutPlanBinByRunIDScan(results pgx.BatchResults) (pgconn.CommandTag, error) {
	cmdTag, err := results.Exec()
	if err != nil {
		return cmdTag, fmt.Errorf("exec PutPlanBinByRunIDBatch: %w", err)
	}
	return cmdTag, err
}

const putPlanJSONByRunIDSQL = `UPDATE runs
SET plan_json = $1
WHERE run_id = $2
;`

// PutPlanJSONByRunID implements Querier.PutPlanJSONByRunID.
func (q *DBQuerier) PutPlanJSONByRunID(ctx context.Context, planJson []byte, runID string) (pgconn.CommandTag, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "PutPlanJSONByRunID")
	cmdTag, err := q.conn.Exec(ctx, putPlanJSONByRunIDSQL, planJson, runID)
	if err != nil {
		return cmdTag, fmt.Errorf("exec query PutPlanJSONByRunID: %w", err)
	}
	return cmdTag, err
}

// PutPlanJSONByRunIDBatch implements Querier.PutPlanJSONByRunIDBatch.
func (q *DBQuerier) PutPlanJSONByRunIDBatch(batch genericBatch, planJson []byte, runID string) {
	batch.Queue(putPlanJSONByRunIDSQL, planJson, runID)
}

// PutPlanJSONByRunIDScan implements Querier.PutPlanJSONByRunIDScan.
func (q *DBQuerier) PutPlanJSONByRunIDScan(results pgx.BatchResults) (pgconn.CommandTag, error) {
	cmdTag, err := results.Exec()
	if err != nil {
		return cmdTag, fmt.Errorf("exec PutPlanJSONByRunIDBatch: %w", err)
	}
	return cmdTag, err
}
