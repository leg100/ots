// Code generated by pggen. DO NOT EDIT.

package pggen

import (
	"context"
	"fmt"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
)

const insertOrganizationMembershipSQL = `INSERT INTO organization_memberships (
    user_id,
    organization_id
) VALUES (
    $1,
    $2
)
;`

// InsertOrganizationMembership implements Querier.InsertOrganizationMembership.
func (q *DBQuerier) InsertOrganizationMembership(ctx context.Context, userID pgtype.Text, organizationID pgtype.Text) (pgconn.CommandTag, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "InsertOrganizationMembership")
	cmdTag, err := q.conn.Exec(ctx, insertOrganizationMembershipSQL, userID, organizationID)
	if err != nil {
		return cmdTag, fmt.Errorf("exec query InsertOrganizationMembership: %w", err)
	}
	return cmdTag, err
}

// InsertOrganizationMembershipBatch implements Querier.InsertOrganizationMembershipBatch.
func (q *DBQuerier) InsertOrganizationMembershipBatch(batch genericBatch, userID pgtype.Text, organizationID pgtype.Text) {
	batch.Queue(insertOrganizationMembershipSQL, userID, organizationID)
}

// InsertOrganizationMembershipScan implements Querier.InsertOrganizationMembershipScan.
func (q *DBQuerier) InsertOrganizationMembershipScan(results pgx.BatchResults) (pgconn.CommandTag, error) {
	cmdTag, err := results.Exec()
	if err != nil {
		return cmdTag, fmt.Errorf("exec InsertOrganizationMembershipBatch: %w", err)
	}
	return cmdTag, err
}

const deleteOrganizationMembershipSQL = `DELETE
FROM organization_memberships
WHERE
    user_id = $1 AND
    organization_id = $2
RETURNING user_id
;`

// DeleteOrganizationMembership implements Querier.DeleteOrganizationMembership.
func (q *DBQuerier) DeleteOrganizationMembership(ctx context.Context, userID pgtype.Text, organizationID pgtype.Text) (pgtype.Text, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "DeleteOrganizationMembership")
	row := q.conn.QueryRow(ctx, deleteOrganizationMembershipSQL, userID, organizationID)
	var item pgtype.Text
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("query DeleteOrganizationMembership: %w", err)
	}
	return item, nil
}

// DeleteOrganizationMembershipBatch implements Querier.DeleteOrganizationMembershipBatch.
func (q *DBQuerier) DeleteOrganizationMembershipBatch(batch genericBatch, userID pgtype.Text, organizationID pgtype.Text) {
	batch.Queue(deleteOrganizationMembershipSQL, userID, organizationID)
}

// DeleteOrganizationMembershipScan implements Querier.DeleteOrganizationMembershipScan.
func (q *DBQuerier) DeleteOrganizationMembershipScan(results pgx.BatchResults) (pgtype.Text, error) {
	row := results.QueryRow()
	var item pgtype.Text
	if err := row.Scan(&item); err != nil {
		return item, fmt.Errorf("scan DeleteOrganizationMembershipBatch row: %w", err)
	}
	return item, nil
}
