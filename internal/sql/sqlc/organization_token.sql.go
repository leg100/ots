// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: organization_token.sql

package sqlc

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

const deleteOrganiationTokenByName = `-- name: DeleteOrganiationTokenByName :one
DELETE
FROM organization_tokens
WHERE organization_name = $1
RETURNING organization_token_id
`

func (q *Queries) DeleteOrganiationTokenByName(ctx context.Context, organizationName pgtype.Text) (pgtype.Text, error) {
	row := q.db.QueryRow(ctx, deleteOrganiationTokenByName, organizationName)
	var organization_token_id pgtype.Text
	err := row.Scan(&organization_token_id)
	return organization_token_id, err
}

const findOrganizationTokens = `-- name: FindOrganizationTokens :many
SELECT organization_token_id, created_at, organization_name, expiry
FROM organization_tokens
WHERE organization_name = $1
`

func (q *Queries) FindOrganizationTokens(ctx context.Context, organizationName pgtype.Text) ([]OrganizationToken, error) {
	rows, err := q.db.Query(ctx, findOrganizationTokens, organizationName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []OrganizationToken
	for rows.Next() {
		var i OrganizationToken
		if err := rows.Scan(
			&i.OrganizationTokenID,
			&i.CreatedAt,
			&i.OrganizationName,
			&i.Expiry,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const findOrganizationTokensByID = `-- name: FindOrganizationTokensByID :one
SELECT organization_token_id, created_at, organization_name, expiry
FROM organization_tokens
WHERE organization_token_id = $1
`

func (q *Queries) FindOrganizationTokensByID(ctx context.Context, organizationTokenID pgtype.Text) (OrganizationToken, error) {
	row := q.db.QueryRow(ctx, findOrganizationTokensByID, organizationTokenID)
	var i OrganizationToken
	err := row.Scan(
		&i.OrganizationTokenID,
		&i.CreatedAt,
		&i.OrganizationName,
		&i.Expiry,
	)
	return i, err
}

const findOrganizationTokensByName = `-- name: FindOrganizationTokensByName :one
SELECT organization_token_id, created_at, organization_name, expiry
FROM organization_tokens
WHERE organization_name = $1
`

func (q *Queries) FindOrganizationTokensByName(ctx context.Context, organizationName pgtype.Text) (OrganizationToken, error) {
	row := q.db.QueryRow(ctx, findOrganizationTokensByName, organizationName)
	var i OrganizationToken
	err := row.Scan(
		&i.OrganizationTokenID,
		&i.CreatedAt,
		&i.OrganizationName,
		&i.Expiry,
	)
	return i, err
}

const upsertOrganizationToken = `-- name: UpsertOrganizationToken :exec
INSERT INTO organization_tokens (
    organization_token_id,
    created_at,
    organization_name,
    expiry
) VALUES (
    $1,
    $2,
    $3,
    $4
) ON CONFLICT (organization_name) DO UPDATE
  SET created_at            = $2,
      organization_token_id = $1,
      expiry                = $4
`

type UpsertOrganizationTokenParams struct {
	OrganizationTokenID pgtype.Text
	CreatedAt           pgtype.Timestamptz
	OrganizationName    pgtype.Text
	Expiry              pgtype.Timestamptz
}

func (q *Queries) UpsertOrganizationToken(ctx context.Context, arg UpsertOrganizationTokenParams) error {
	_, err := q.db.Exec(ctx, upsertOrganizationToken,
		arg.OrganizationTokenID,
		arg.CreatedAt,
		arg.OrganizationName,
		arg.Expiry,
	)
	return err
}
