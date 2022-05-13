// Code generated by pggen. DO NOT EDIT.

package sql

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v4"
	"time"
)

const insertStateVersionOutputSQL = `INSERT INTO state_version_outputs (
    state_version_output_id,
    created_at,
    updated_at,
    name,
    sensitive,
    type,
    value,
    state_version_id
) VALUES (
    $1,
    NOW(),
    NOW(),
    $2,
    $3,
    $4,
    $5,
    $6
)
RETURNING *;`

type InsertStateVersionOutputParams struct {
	ID             string
	Name           string
	Sensitive      bool
	Type           string
	Value          string
	StateVersionID string
}

type InsertStateVersionOutputRow struct {
	StateVersionOutputID string    `json:"state_version_output_id"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
	Name                 string    `json:"name"`
	Sensitive            bool      `json:"sensitive"`
	Type                 string    `json:"type"`
	Value                string    `json:"value"`
	StateVersionID       string    `json:"state_version_id"`
}

func (s InsertStateVersionOutputRow) GetStateVersionOutputID() string { return s.StateVersionOutputID }
func (s InsertStateVersionOutputRow) GetCreatedAt() time.Time { return s.CreatedAt }
func (s InsertStateVersionOutputRow) GetUpdatedAt() time.Time { return s.UpdatedAt }
func (s InsertStateVersionOutputRow) GetName() string { return s.Name }
func (s InsertStateVersionOutputRow) GetSensitive() bool { return s.Sensitive }
func (s InsertStateVersionOutputRow) GetType() string { return s.Type }
func (s InsertStateVersionOutputRow) GetValue() string { return s.Value }
func (s InsertStateVersionOutputRow) GetStateVersionID() string { return s.StateVersionID }


// InsertStateVersionOutput implements Querier.InsertStateVersionOutput.
func (q *DBQuerier) InsertStateVersionOutput(ctx context.Context, params InsertStateVersionOutputParams) (InsertStateVersionOutputRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "InsertStateVersionOutput")
	row := q.conn.QueryRow(ctx, insertStateVersionOutputSQL, params.ID, params.Name, params.Sensitive, params.Type, params.Value, params.StateVersionID)
	var item InsertStateVersionOutputRow
	if err := row.Scan(&item.StateVersionOutputID, &item.CreatedAt, &item.UpdatedAt, &item.Name, &item.Sensitive, &item.Type, &item.Value, &item.StateVersionID); err != nil {
		return item, fmt.Errorf("query InsertStateVersionOutput: %w", err)
	}
	return item, nil
}

// InsertStateVersionOutputBatch implements Querier.InsertStateVersionOutputBatch.
func (q *DBQuerier) InsertStateVersionOutputBatch(batch genericBatch, params InsertStateVersionOutputParams) {
	batch.Queue(insertStateVersionOutputSQL, params.ID, params.Name, params.Sensitive, params.Type, params.Value, params.StateVersionID)
}

// InsertStateVersionOutputScan implements Querier.InsertStateVersionOutputScan.
func (q *DBQuerier) InsertStateVersionOutputScan(results pgx.BatchResults) (InsertStateVersionOutputRow, error) {
	row := results.QueryRow()
	var item InsertStateVersionOutputRow
	if err := row.Scan(&item.StateVersionOutputID, &item.CreatedAt, &item.UpdatedAt, &item.Name, &item.Sensitive, &item.Type, &item.Value, &item.StateVersionID); err != nil {
		return item, fmt.Errorf("scan InsertStateVersionOutputBatch row: %w", err)
	}
	return item, nil
}
