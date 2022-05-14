// Code generated by pggen. DO NOT EDIT.

package sql

import (
	"context"
	"fmt"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"time"
)

const insertUserSQL = `INSERT INTO users (
    user_id,
    created_at,
    updated_at,
    username,
    current_organization
) VALUES (
    $1,
    current_timestamp,
    current_timestamp,
    $2,
    $3
)
RETURNING *;`

type InsertUserParams struct {
	ID                  string
	Username            string
	CurrentOrganization string
}

type InsertUserRow struct {
	UserID              string    `json:"user_id"`
	Username            string    `json:"username"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	CurrentOrganization *string   `json:"current_organization"`
}

// InsertUser implements Querier.InsertUser.
func (q *DBQuerier) InsertUser(ctx context.Context, params InsertUserParams) (InsertUserRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "InsertUser")
	row := q.conn.QueryRow(ctx, insertUserSQL, params.ID, params.Username, params.CurrentOrganization)
	var item InsertUserRow
	if err := row.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization); err != nil {
		return item, fmt.Errorf("query InsertUser: %w", err)
	}
	return item, nil
}

// InsertUserBatch implements Querier.InsertUserBatch.
func (q *DBQuerier) InsertUserBatch(batch genericBatch, params InsertUserParams) {
	batch.Queue(insertUserSQL, params.ID, params.Username, params.CurrentOrganization)
}

// InsertUserScan implements Querier.InsertUserScan.
func (q *DBQuerier) InsertUserScan(results pgx.BatchResults) (InsertUserRow, error) {
	row := results.QueryRow()
	var item InsertUserRow
	if err := row.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization); err != nil {
		return item, fmt.Errorf("scan InsertUserBatch row: %w", err)
	}
	return item, nil
}

const findUsersSQL = `SELECT users.*,
    array_agg(sessions) AS sessions,
    array_agg(tokens) AS tokens,
    array_agg(organizations) AS organizations
FROM users
JOIN sessions USING(user_id)
JOIN tokens USING(user_id)
JOIN (organization_memberships JOIN organizations USING (organization_id)) USING(user_id)
GROUP BY users.user_id
;`

type FindUsersRow struct {
	UserID              *string         `json:"user_id"`
	Username            *string         `json:"username"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
	CurrentOrganization *string         `json:"current_organization"`
	Sessions            []Sessions      `json:"sessions"`
	Tokens              []Tokens        `json:"tokens"`
	Organizations       []Organizations `json:"organizations"`
}

// FindUsers implements Querier.FindUsers.
func (q *DBQuerier) FindUsers(ctx context.Context) ([]FindUsersRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "FindUsers")
	rows, err := q.conn.Query(ctx, findUsersSQL)
	if err != nil {
		return nil, fmt.Errorf("query FindUsers: %w", err)
	}
	defer rows.Close()
	items := []FindUsersRow{}
	sessionsArray := q.types.newSessionsArray()
	tokensArray := q.types.newTokensArray()
	organizationsArray := q.types.newOrganizationsArray()
	for rows.Next() {
		var item FindUsersRow
		if err := rows.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization, sessionsArray, tokensArray, organizationsArray); err != nil {
			return nil, fmt.Errorf("scan FindUsers row: %w", err)
		}
		if err := sessionsArray.AssignTo(&item.Sessions); err != nil {
			return nil, fmt.Errorf("assign FindUsers row: %w", err)
		}
		if err := tokensArray.AssignTo(&item.Tokens); err != nil {
			return nil, fmt.Errorf("assign FindUsers row: %w", err)
		}
		if err := organizationsArray.AssignTo(&item.Organizations); err != nil {
			return nil, fmt.Errorf("assign FindUsers row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("close FindUsers rows: %w", err)
	}
	return items, err
}

// FindUsersBatch implements Querier.FindUsersBatch.
func (q *DBQuerier) FindUsersBatch(batch genericBatch) {
	batch.Queue(findUsersSQL)
}

// FindUsersScan implements Querier.FindUsersScan.
func (q *DBQuerier) FindUsersScan(results pgx.BatchResults) ([]FindUsersRow, error) {
	rows, err := results.Query()
	if err != nil {
		return nil, fmt.Errorf("query FindUsersBatch: %w", err)
	}
	defer rows.Close()
	items := []FindUsersRow{}
	sessionsArray := q.types.newSessionsArray()
	tokensArray := q.types.newTokensArray()
	organizationsArray := q.types.newOrganizationsArray()
	for rows.Next() {
		var item FindUsersRow
		if err := rows.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization, sessionsArray, tokensArray, organizationsArray); err != nil {
			return nil, fmt.Errorf("scan FindUsersBatch row: %w", err)
		}
		if err := sessionsArray.AssignTo(&item.Sessions); err != nil {
			return nil, fmt.Errorf("assign FindUsers row: %w", err)
		}
		if err := tokensArray.AssignTo(&item.Tokens); err != nil {
			return nil, fmt.Errorf("assign FindUsers row: %w", err)
		}
		if err := organizationsArray.AssignTo(&item.Organizations); err != nil {
			return nil, fmt.Errorf("assign FindUsers row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("close FindUsersBatch rows: %w", err)
	}
	return items, err
}

const findUserByIDSQL = `SELECT users.*,
    array_agg(sessions) AS sessions,
    array_agg(tokens) AS tokens,
    array_agg(organizations) AS organizations
FROM users
JOIN sessions USING(user_id)
JOIN tokens USING(user_id)
JOIN (organization_memberships JOIN organizations USING (organization_id)) USING(user_id)
WHERE users.user_id = $1
GROUP BY users.user_id
;`

type FindUserByIDRow struct {
	UserID              *string         `json:"user_id"`
	Username            *string         `json:"username"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
	CurrentOrganization *string         `json:"current_organization"`
	Sessions            []Sessions      `json:"sessions"`
	Tokens              []Tokens        `json:"tokens"`
	Organizations       []Organizations `json:"organizations"`
}

// FindUserByID implements Querier.FindUserByID.
func (q *DBQuerier) FindUserByID(ctx context.Context, userID string) (FindUserByIDRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "FindUserByID")
	row := q.conn.QueryRow(ctx, findUserByIDSQL, userID)
	var item FindUserByIDRow
	sessionsArray := q.types.newSessionsArray()
	tokensArray := q.types.newTokensArray()
	organizationsArray := q.types.newOrganizationsArray()
	if err := row.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization, sessionsArray, tokensArray, organizationsArray); err != nil {
		return item, fmt.Errorf("query FindUserByID: %w", err)
	}
	if err := sessionsArray.AssignTo(&item.Sessions); err != nil {
		return item, fmt.Errorf("assign FindUserByID row: %w", err)
	}
	if err := tokensArray.AssignTo(&item.Tokens); err != nil {
		return item, fmt.Errorf("assign FindUserByID row: %w", err)
	}
	if err := organizationsArray.AssignTo(&item.Organizations); err != nil {
		return item, fmt.Errorf("assign FindUserByID row: %w", err)
	}
	return item, nil
}

// FindUserByIDBatch implements Querier.FindUserByIDBatch.
func (q *DBQuerier) FindUserByIDBatch(batch genericBatch, userID string) {
	batch.Queue(findUserByIDSQL, userID)
}

// FindUserByIDScan implements Querier.FindUserByIDScan.
func (q *DBQuerier) FindUserByIDScan(results pgx.BatchResults) (FindUserByIDRow, error) {
	row := results.QueryRow()
	var item FindUserByIDRow
	sessionsArray := q.types.newSessionsArray()
	tokensArray := q.types.newTokensArray()
	organizationsArray := q.types.newOrganizationsArray()
	if err := row.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization, sessionsArray, tokensArray, organizationsArray); err != nil {
		return item, fmt.Errorf("scan FindUserByIDBatch row: %w", err)
	}
	if err := sessionsArray.AssignTo(&item.Sessions); err != nil {
		return item, fmt.Errorf("assign FindUserByID row: %w", err)
	}
	if err := tokensArray.AssignTo(&item.Tokens); err != nil {
		return item, fmt.Errorf("assign FindUserByID row: %w", err)
	}
	if err := organizationsArray.AssignTo(&item.Organizations); err != nil {
		return item, fmt.Errorf("assign FindUserByID row: %w", err)
	}
	return item, nil
}

const findUserByUsernameSQL = `SELECT users.*,
    array_agg(sessions) AS sessions,
    array_agg(tokens) AS tokens,
    array_agg(organizations) AS organizations
FROM users
JOIN sessions USING(user_id)
JOIN tokens USING(user_id)
JOIN (organization_memberships JOIN organizations USING (organization_id)) USING(user_id)
WHERE users.username = $1
AND sessions.expiry > current_timestamp
GROUP BY users.user_id
;`

type FindUserByUsernameRow struct {
	UserID              *string         `json:"user_id"`
	Username            *string         `json:"username"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
	CurrentOrganization *string         `json:"current_organization"`
	Sessions            []Sessions      `json:"sessions"`
	Tokens              []Tokens        `json:"tokens"`
	Organizations       []Organizations `json:"organizations"`
}

// FindUserByUsername implements Querier.FindUserByUsername.
func (q *DBQuerier) FindUserByUsername(ctx context.Context, username string) (FindUserByUsernameRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "FindUserByUsername")
	row := q.conn.QueryRow(ctx, findUserByUsernameSQL, username)
	var item FindUserByUsernameRow
	sessionsArray := q.types.newSessionsArray()
	tokensArray := q.types.newTokensArray()
	organizationsArray := q.types.newOrganizationsArray()
	if err := row.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization, sessionsArray, tokensArray, organizationsArray); err != nil {
		return item, fmt.Errorf("query FindUserByUsername: %w", err)
	}
	if err := sessionsArray.AssignTo(&item.Sessions); err != nil {
		return item, fmt.Errorf("assign FindUserByUsername row: %w", err)
	}
	if err := tokensArray.AssignTo(&item.Tokens); err != nil {
		return item, fmt.Errorf("assign FindUserByUsername row: %w", err)
	}
	if err := organizationsArray.AssignTo(&item.Organizations); err != nil {
		return item, fmt.Errorf("assign FindUserByUsername row: %w", err)
	}
	return item, nil
}

// FindUserByUsernameBatch implements Querier.FindUserByUsernameBatch.
func (q *DBQuerier) FindUserByUsernameBatch(batch genericBatch, username string) {
	batch.Queue(findUserByUsernameSQL, username)
}

// FindUserByUsernameScan implements Querier.FindUserByUsernameScan.
func (q *DBQuerier) FindUserByUsernameScan(results pgx.BatchResults) (FindUserByUsernameRow, error) {
	row := results.QueryRow()
	var item FindUserByUsernameRow
	sessionsArray := q.types.newSessionsArray()
	tokensArray := q.types.newTokensArray()
	organizationsArray := q.types.newOrganizationsArray()
	if err := row.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization, sessionsArray, tokensArray, organizationsArray); err != nil {
		return item, fmt.Errorf("scan FindUserByUsernameBatch row: %w", err)
	}
	if err := sessionsArray.AssignTo(&item.Sessions); err != nil {
		return item, fmt.Errorf("assign FindUserByUsername row: %w", err)
	}
	if err := tokensArray.AssignTo(&item.Tokens); err != nil {
		return item, fmt.Errorf("assign FindUserByUsername row: %w", err)
	}
	if err := organizationsArray.AssignTo(&item.Organizations); err != nil {
		return item, fmt.Errorf("assign FindUserByUsername row: %w", err)
	}
	return item, nil
}

const findUserBySessionTokenSQL = `SELECT users.*,
    array_agg(sessions) AS sessions,
    array_agg(tokens) AS tokens,
    array_agg(organizations) AS organizations
FROM users
JOIN sessions USING(user_id)
JOIN tokens USING(user_id)
JOIN (organization_memberships JOIN organizations USING (organization_id)) USING(user_id)
WHERE sessions.token = $1
AND sessions.expiry > current_timestamp
GROUP BY users.user_id
;`

type FindUserBySessionTokenRow struct {
	UserID              *string         `json:"user_id"`
	Username            *string         `json:"username"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
	CurrentOrganization *string         `json:"current_organization"`
	Sessions            []Sessions      `json:"sessions"`
	Tokens              []Tokens        `json:"tokens"`
	Organizations       []Organizations `json:"organizations"`
}

// FindUserBySessionToken implements Querier.FindUserBySessionToken.
func (q *DBQuerier) FindUserBySessionToken(ctx context.Context, token string) (FindUserBySessionTokenRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "FindUserBySessionToken")
	row := q.conn.QueryRow(ctx, findUserBySessionTokenSQL, token)
	var item FindUserBySessionTokenRow
	sessionsArray := q.types.newSessionsArray()
	tokensArray := q.types.newTokensArray()
	organizationsArray := q.types.newOrganizationsArray()
	if err := row.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization, sessionsArray, tokensArray, organizationsArray); err != nil {
		return item, fmt.Errorf("query FindUserBySessionToken: %w", err)
	}
	if err := sessionsArray.AssignTo(&item.Sessions); err != nil {
		return item, fmt.Errorf("assign FindUserBySessionToken row: %w", err)
	}
	if err := tokensArray.AssignTo(&item.Tokens); err != nil {
		return item, fmt.Errorf("assign FindUserBySessionToken row: %w", err)
	}
	if err := organizationsArray.AssignTo(&item.Organizations); err != nil {
		return item, fmt.Errorf("assign FindUserBySessionToken row: %w", err)
	}
	return item, nil
}

// FindUserBySessionTokenBatch implements Querier.FindUserBySessionTokenBatch.
func (q *DBQuerier) FindUserBySessionTokenBatch(batch genericBatch, token string) {
	batch.Queue(findUserBySessionTokenSQL, token)
}

// FindUserBySessionTokenScan implements Querier.FindUserBySessionTokenScan.
func (q *DBQuerier) FindUserBySessionTokenScan(results pgx.BatchResults) (FindUserBySessionTokenRow, error) {
	row := results.QueryRow()
	var item FindUserBySessionTokenRow
	sessionsArray := q.types.newSessionsArray()
	tokensArray := q.types.newTokensArray()
	organizationsArray := q.types.newOrganizationsArray()
	if err := row.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization, sessionsArray, tokensArray, organizationsArray); err != nil {
		return item, fmt.Errorf("scan FindUserBySessionTokenBatch row: %w", err)
	}
	if err := sessionsArray.AssignTo(&item.Sessions); err != nil {
		return item, fmt.Errorf("assign FindUserBySessionToken row: %w", err)
	}
	if err := tokensArray.AssignTo(&item.Tokens); err != nil {
		return item, fmt.Errorf("assign FindUserBySessionToken row: %w", err)
	}
	if err := organizationsArray.AssignTo(&item.Organizations); err != nil {
		return item, fmt.Errorf("assign FindUserBySessionToken row: %w", err)
	}
	return item, nil
}

const findUserByAuthenticationTokenSQL = `SELECT users.*,
    array_agg(sessions) AS sessions,
    array_agg(tokens) AS tokens,
    array_agg(organizations) AS organizations
FROM users
JOIN sessions USING(user_id)
JOIN tokens USING(user_id)
JOIN (organization_memberships JOIN organizations USING (organization_id)) USING(user_id)
WHERE tokens.token = $1
AND sessions.expiry > current_timestamp
GROUP BY users.user_id
;`

type FindUserByAuthenticationTokenRow struct {
	UserID              *string         `json:"user_id"`
	Username            *string         `json:"username"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
	CurrentOrganization *string         `json:"current_organization"`
	Sessions            []Sessions      `json:"sessions"`
	Tokens              []Tokens        `json:"tokens"`
	Organizations       []Organizations `json:"organizations"`
}

// FindUserByAuthenticationToken implements Querier.FindUserByAuthenticationToken.
func (q *DBQuerier) FindUserByAuthenticationToken(ctx context.Context, token string) (FindUserByAuthenticationTokenRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "FindUserByAuthenticationToken")
	row := q.conn.QueryRow(ctx, findUserByAuthenticationTokenSQL, token)
	var item FindUserByAuthenticationTokenRow
	sessionsArray := q.types.newSessionsArray()
	tokensArray := q.types.newTokensArray()
	organizationsArray := q.types.newOrganizationsArray()
	if err := row.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization, sessionsArray, tokensArray, organizationsArray); err != nil {
		return item, fmt.Errorf("query FindUserByAuthenticationToken: %w", err)
	}
	if err := sessionsArray.AssignTo(&item.Sessions); err != nil {
		return item, fmt.Errorf("assign FindUserByAuthenticationToken row: %w", err)
	}
	if err := tokensArray.AssignTo(&item.Tokens); err != nil {
		return item, fmt.Errorf("assign FindUserByAuthenticationToken row: %w", err)
	}
	if err := organizationsArray.AssignTo(&item.Organizations); err != nil {
		return item, fmt.Errorf("assign FindUserByAuthenticationToken row: %w", err)
	}
	return item, nil
}

// FindUserByAuthenticationTokenBatch implements Querier.FindUserByAuthenticationTokenBatch.
func (q *DBQuerier) FindUserByAuthenticationTokenBatch(batch genericBatch, token string) {
	batch.Queue(findUserByAuthenticationTokenSQL, token)
}

// FindUserByAuthenticationTokenScan implements Querier.FindUserByAuthenticationTokenScan.
func (q *DBQuerier) FindUserByAuthenticationTokenScan(results pgx.BatchResults) (FindUserByAuthenticationTokenRow, error) {
	row := results.QueryRow()
	var item FindUserByAuthenticationTokenRow
	sessionsArray := q.types.newSessionsArray()
	tokensArray := q.types.newTokensArray()
	organizationsArray := q.types.newOrganizationsArray()
	if err := row.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization, sessionsArray, tokensArray, organizationsArray); err != nil {
		return item, fmt.Errorf("scan FindUserByAuthenticationTokenBatch row: %w", err)
	}
	if err := sessionsArray.AssignTo(&item.Sessions); err != nil {
		return item, fmt.Errorf("assign FindUserByAuthenticationToken row: %w", err)
	}
	if err := tokensArray.AssignTo(&item.Tokens); err != nil {
		return item, fmt.Errorf("assign FindUserByAuthenticationToken row: %w", err)
	}
	if err := organizationsArray.AssignTo(&item.Organizations); err != nil {
		return item, fmt.Errorf("assign FindUserByAuthenticationToken row: %w", err)
	}
	return item, nil
}

const findUserByAuthenticationTokenIDSQL = `SELECT users.*,
    array_agg(sessions) AS sessions,
    array_agg(tokens) AS tokens,
    array_agg(organizations) AS organizations
FROM users
JOIN sessions USING(user_id)
JOIN tokens USING(user_id)
JOIN (organization_memberships JOIN organizations USING (organization_id)) USING(user_id)
WHERE tokens.token_id = $1
AND sessions.expiry > current_timestamp
GROUP BY users.user_id
;`

type FindUserByAuthenticationTokenIDRow struct {
	UserID              *string         `json:"user_id"`
	Username            *string         `json:"username"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
	CurrentOrganization *string         `json:"current_organization"`
	Sessions            []Sessions      `json:"sessions"`
	Tokens              []Tokens        `json:"tokens"`
	Organizations       []Organizations `json:"organizations"`
}

// FindUserByAuthenticationTokenID implements Querier.FindUserByAuthenticationTokenID.
func (q *DBQuerier) FindUserByAuthenticationTokenID(ctx context.Context, tokenID string) (FindUserByAuthenticationTokenIDRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "FindUserByAuthenticationTokenID")
	row := q.conn.QueryRow(ctx, findUserByAuthenticationTokenIDSQL, tokenID)
	var item FindUserByAuthenticationTokenIDRow
	sessionsArray := q.types.newSessionsArray()
	tokensArray := q.types.newTokensArray()
	organizationsArray := q.types.newOrganizationsArray()
	if err := row.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization, sessionsArray, tokensArray, organizationsArray); err != nil {
		return item, fmt.Errorf("query FindUserByAuthenticationTokenID: %w", err)
	}
	if err := sessionsArray.AssignTo(&item.Sessions); err != nil {
		return item, fmt.Errorf("assign FindUserByAuthenticationTokenID row: %w", err)
	}
	if err := tokensArray.AssignTo(&item.Tokens); err != nil {
		return item, fmt.Errorf("assign FindUserByAuthenticationTokenID row: %w", err)
	}
	if err := organizationsArray.AssignTo(&item.Organizations); err != nil {
		return item, fmt.Errorf("assign FindUserByAuthenticationTokenID row: %w", err)
	}
	return item, nil
}

// FindUserByAuthenticationTokenIDBatch implements Querier.FindUserByAuthenticationTokenIDBatch.
func (q *DBQuerier) FindUserByAuthenticationTokenIDBatch(batch genericBatch, tokenID string) {
	batch.Queue(findUserByAuthenticationTokenIDSQL, tokenID)
}

// FindUserByAuthenticationTokenIDScan implements Querier.FindUserByAuthenticationTokenIDScan.
func (q *DBQuerier) FindUserByAuthenticationTokenIDScan(results pgx.BatchResults) (FindUserByAuthenticationTokenIDRow, error) {
	row := results.QueryRow()
	var item FindUserByAuthenticationTokenIDRow
	sessionsArray := q.types.newSessionsArray()
	tokensArray := q.types.newTokensArray()
	organizationsArray := q.types.newOrganizationsArray()
	if err := row.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization, sessionsArray, tokensArray, organizationsArray); err != nil {
		return item, fmt.Errorf("scan FindUserByAuthenticationTokenIDBatch row: %w", err)
	}
	if err := sessionsArray.AssignTo(&item.Sessions); err != nil {
		return item, fmt.Errorf("assign FindUserByAuthenticationTokenID row: %w", err)
	}
	if err := tokensArray.AssignTo(&item.Tokens); err != nil {
		return item, fmt.Errorf("assign FindUserByAuthenticationTokenID row: %w", err)
	}
	if err := organizationsArray.AssignTo(&item.Organizations); err != nil {
		return item, fmt.Errorf("assign FindUserByAuthenticationTokenID row: %w", err)
	}
	return item, nil
}

const updateUserCurrentOrganizationSQL = `UPDATE users
SET
    current_organization = $1,
    updated_at = current_timestamp
WHERE user_id = $2
RETURNING *;`

type UpdateUserCurrentOrganizationRow struct {
	UserID              string    `json:"user_id"`
	Username            string    `json:"username"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	CurrentOrganization *string   `json:"current_organization"`
}

// UpdateUserCurrentOrganization implements Querier.UpdateUserCurrentOrganization.
func (q *DBQuerier) UpdateUserCurrentOrganization(ctx context.Context, currentOrganization string, id string) (UpdateUserCurrentOrganizationRow, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "UpdateUserCurrentOrganization")
	row := q.conn.QueryRow(ctx, updateUserCurrentOrganizationSQL, currentOrganization, id)
	var item UpdateUserCurrentOrganizationRow
	if err := row.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization); err != nil {
		return item, fmt.Errorf("query UpdateUserCurrentOrganization: %w", err)
	}
	return item, nil
}

// UpdateUserCurrentOrganizationBatch implements Querier.UpdateUserCurrentOrganizationBatch.
func (q *DBQuerier) UpdateUserCurrentOrganizationBatch(batch genericBatch, currentOrganization string, id string) {
	batch.Queue(updateUserCurrentOrganizationSQL, currentOrganization, id)
}

// UpdateUserCurrentOrganizationScan implements Querier.UpdateUserCurrentOrganizationScan.
func (q *DBQuerier) UpdateUserCurrentOrganizationScan(results pgx.BatchResults) (UpdateUserCurrentOrganizationRow, error) {
	row := results.QueryRow()
	var item UpdateUserCurrentOrganizationRow
	if err := row.Scan(&item.UserID, &item.Username, &item.CreatedAt, &item.UpdatedAt, &item.CurrentOrganization); err != nil {
		return item, fmt.Errorf("scan UpdateUserCurrentOrganizationBatch row: %w", err)
	}
	return item, nil
}

const deleteUserByIDSQL = `DELETE
FROM users
WHERE user_id = $1;`

// DeleteUserByID implements Querier.DeleteUserByID.
func (q *DBQuerier) DeleteUserByID(ctx context.Context, userID string) (pgconn.CommandTag, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "DeleteUserByID")
	cmdTag, err := q.conn.Exec(ctx, deleteUserByIDSQL, userID)
	if err != nil {
		return cmdTag, fmt.Errorf("exec query DeleteUserByID: %w", err)
	}
	return cmdTag, err
}

// DeleteUserByIDBatch implements Querier.DeleteUserByIDBatch.
func (q *DBQuerier) DeleteUserByIDBatch(batch genericBatch, userID string) {
	batch.Queue(deleteUserByIDSQL, userID)
}

// DeleteUserByIDScan implements Querier.DeleteUserByIDScan.
func (q *DBQuerier) DeleteUserByIDScan(results pgx.BatchResults) (pgconn.CommandTag, error) {
	cmdTag, err := results.Exec()
	if err != nil {
		return cmdTag, fmt.Errorf("exec DeleteUserByIDBatch: %w", err)
	}
	return cmdTag, err
}

const deleteUserByUsernameSQL = `DELETE
FROM users
WHERE username = $1;`

// DeleteUserByUsername implements Querier.DeleteUserByUsername.
func (q *DBQuerier) DeleteUserByUsername(ctx context.Context, username string) (pgconn.CommandTag, error) {
	ctx = context.WithValue(ctx, "pggen_query_name", "DeleteUserByUsername")
	cmdTag, err := q.conn.Exec(ctx, deleteUserByUsernameSQL, username)
	if err != nil {
		return cmdTag, fmt.Errorf("exec query DeleteUserByUsername: %w", err)
	}
	return cmdTag, err
}

// DeleteUserByUsernameBatch implements Querier.DeleteUserByUsernameBatch.
func (q *DBQuerier) DeleteUserByUsernameBatch(batch genericBatch, username string) {
	batch.Queue(deleteUserByUsernameSQL, username)
}

// DeleteUserByUsernameScan implements Querier.DeleteUserByUsernameScan.
func (q *DBQuerier) DeleteUserByUsernameScan(results pgx.BatchResults) (pgconn.CommandTag, error) {
	cmdTag, err := results.Exec()
	if err != nil {
		return cmdTag, fmt.Errorf("exec DeleteUserByUsernameBatch: %w", err)
	}
	return cmdTag, err
}
