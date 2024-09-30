// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: configuration_version.sql

package sqlc

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

const countConfigurationVersionsByWorkspaceID = `-- name: CountConfigurationVersionsByWorkspaceID :one
SELECT count(*)
FROM configuration_versions
WHERE configuration_versions.workspace_id = $1
`

func (q *Queries) CountConfigurationVersionsByWorkspaceID(ctx context.Context, workspaceID pgtype.Text) (int64, error) {
	row := q.db.QueryRow(ctx, countConfigurationVersionsByWorkspaceID, workspaceID)
	var count int64
	err := row.Scan(&count)
	return count, err
}

const deleteConfigurationVersionByID = `-- name: DeleteConfigurationVersionByID :one
DELETE
FROM configuration_versions
WHERE configuration_version_id = $1
RETURNING configuration_version_id
`

func (q *Queries) DeleteConfigurationVersionByID(ctx context.Context, id pgtype.Text) (pgtype.Text, error) {
	row := q.db.QueryRow(ctx, deleteConfigurationVersionByID, id)
	var configuration_version_id pgtype.Text
	err := row.Scan(&configuration_version_id)
	return configuration_version_id, err
}

const downloadConfigurationVersion = `-- name: DownloadConfigurationVersion :one
SELECT config
FROM configuration_versions
WHERE configuration_version_id = $1
AND   status                   = 'uploaded'
`

// DownloadConfigurationVersion gets a configuration_version config
// tarball.
func (q *Queries) DownloadConfigurationVersion(ctx context.Context, configurationVersionID pgtype.Text) ([]byte, error) {
	row := q.db.QueryRow(ctx, downloadConfigurationVersion, configurationVersionID)
	var config []byte
	err := row.Scan(&config)
	return config, err
}

const findConfigurationVersionByID = `-- name: FindConfigurationVersionByID :one
SELECT
    cv.configuration_version_id,
    cv.created_at,
    cv.auto_queue_runs,
    cv.source,
    cv.speculative,
    cv.status,
    cv.workspace_id,
    array_agg(st.*)::"configuration_version_status_timestamps" AS status_timestamps,
    configuration_version_ingress_attributes.branch, configuration_version_ingress_attributes.commit_sha, configuration_version_ingress_attributes.identifier, configuration_version_ingress_attributes.is_pull_request, configuration_version_ingress_attributes.on_default_branch, configuration_version_ingress_attributes.configuration_version_id, configuration_version_ingress_attributes.commit_url, configuration_version_ingress_attributes.pull_request_number, configuration_version_ingress_attributes.pull_request_url, configuration_version_ingress_attributes.pull_request_title, configuration_version_ingress_attributes.tag, configuration_version_ingress_attributes.sender_username, configuration_version_ingress_attributes.sender_avatar_url, configuration_version_ingress_attributes.sender_html_url
FROM configuration_versions cv
JOIN workspaces USING (workspace_id)
JOIN configuration_version_ingress_attributes USING (configuration_version_id)
LEFT JOIN configuration_version_status_timestamps st USING (configuration_version_id)
WHERE cv.configuration_version_id = $1
GROUP BY cv.configuration_version_id
`

type FindConfigurationVersionByIDRow struct {
	ConfigurationVersionID               pgtype.Text
	CreatedAt                            pgtype.Timestamptz
	AutoQueueRuns                        pgtype.Bool
	Source                               pgtype.Text
	Speculative                          pgtype.Bool
	Status                               pgtype.Text
	WorkspaceID                          pgtype.Text
	StatusTimestamps                     ConfigurationVersionStatusTimestamp
	ConfigurationVersionIngressAttribute ConfigurationVersionIngressAttribute
}

// FindConfigurationVersionByID finds a configuration_version by its id.
func (q *Queries) FindConfigurationVersionByID(ctx context.Context, configurationVersionID pgtype.Text) (FindConfigurationVersionByIDRow, error) {
	row := q.db.QueryRow(ctx, findConfigurationVersionByID, configurationVersionID)
	var i FindConfigurationVersionByIDRow
	err := row.Scan(
		&i.ConfigurationVersionID,
		&i.CreatedAt,
		&i.AutoQueueRuns,
		&i.Source,
		&i.Speculative,
		&i.Status,
		&i.WorkspaceID,
		&i.StatusTimestamps,
		&i.ConfigurationVersionIngressAttribute.Branch,
		&i.ConfigurationVersionIngressAttribute.CommitSha,
		&i.ConfigurationVersionIngressAttribute.Identifier,
		&i.ConfigurationVersionIngressAttribute.IsPullRequest,
		&i.ConfigurationVersionIngressAttribute.OnDefaultBranch,
		&i.ConfigurationVersionIngressAttribute.ConfigurationVersionID,
		&i.ConfigurationVersionIngressAttribute.CommitURL,
		&i.ConfigurationVersionIngressAttribute.PullRequestNumber,
		&i.ConfigurationVersionIngressAttribute.PullRequestURL,
		&i.ConfigurationVersionIngressAttribute.PullRequestTitle,
		&i.ConfigurationVersionIngressAttribute.Tag,
		&i.ConfigurationVersionIngressAttribute.SenderUsername,
		&i.ConfigurationVersionIngressAttribute.SenderAvatarURL,
		&i.ConfigurationVersionIngressAttribute.SenderHtmlURL,
	)
	return i, err
}

const findConfigurationVersionByIDForUpdate = `-- name: FindConfigurationVersionByIDForUpdate :one
SELECT
    cv.configuration_version_id,
    cv.created_at,
    cv.auto_queue_runs,
    cv.source,
    cv.speculative,
    cv.status,
    cv.workspace_id,
    array_agg(st.*)::"configuration_version_status_timestamps" AS status_timestamps,
    configuration_version_ingress_attributes.branch, configuration_version_ingress_attributes.commit_sha, configuration_version_ingress_attributes.identifier, configuration_version_ingress_attributes.is_pull_request, configuration_version_ingress_attributes.on_default_branch, configuration_version_ingress_attributes.configuration_version_id, configuration_version_ingress_attributes.commit_url, configuration_version_ingress_attributes.pull_request_number, configuration_version_ingress_attributes.pull_request_url, configuration_version_ingress_attributes.pull_request_title, configuration_version_ingress_attributes.tag, configuration_version_ingress_attributes.sender_username, configuration_version_ingress_attributes.sender_avatar_url, configuration_version_ingress_attributes.sender_html_url
FROM configuration_versions cv
JOIN workspaces USING (workspace_id)
JOIN configuration_version_ingress_attributes USING (configuration_version_id)
LEFT JOIN configuration_version_status_timestamps st USING (configuration_version_id)
WHERE cv.configuration_version_id = $1
GROUP BY cv.configuration_version_id
FOR UPDATE OF configuration_versions
`

type FindConfigurationVersionByIDForUpdateRow struct {
	ConfigurationVersionID               pgtype.Text
	CreatedAt                            pgtype.Timestamptz
	AutoQueueRuns                        pgtype.Bool
	Source                               pgtype.Text
	Speculative                          pgtype.Bool
	Status                               pgtype.Text
	WorkspaceID                          pgtype.Text
	StatusTimestamps                     ConfigurationVersionStatusTimestamp
	ConfigurationVersionIngressAttribute ConfigurationVersionIngressAttribute
}

func (q *Queries) FindConfigurationVersionByIDForUpdate(ctx context.Context, configurationVersionID pgtype.Text) (FindConfigurationVersionByIDForUpdateRow, error) {
	row := q.db.QueryRow(ctx, findConfigurationVersionByIDForUpdate, configurationVersionID)
	var i FindConfigurationVersionByIDForUpdateRow
	err := row.Scan(
		&i.ConfigurationVersionID,
		&i.CreatedAt,
		&i.AutoQueueRuns,
		&i.Source,
		&i.Speculative,
		&i.Status,
		&i.WorkspaceID,
		&i.StatusTimestamps,
		&i.ConfigurationVersionIngressAttribute.Branch,
		&i.ConfigurationVersionIngressAttribute.CommitSha,
		&i.ConfigurationVersionIngressAttribute.Identifier,
		&i.ConfigurationVersionIngressAttribute.IsPullRequest,
		&i.ConfigurationVersionIngressAttribute.OnDefaultBranch,
		&i.ConfigurationVersionIngressAttribute.ConfigurationVersionID,
		&i.ConfigurationVersionIngressAttribute.CommitURL,
		&i.ConfigurationVersionIngressAttribute.PullRequestNumber,
		&i.ConfigurationVersionIngressAttribute.PullRequestURL,
		&i.ConfigurationVersionIngressAttribute.PullRequestTitle,
		&i.ConfigurationVersionIngressAttribute.Tag,
		&i.ConfigurationVersionIngressAttribute.SenderUsername,
		&i.ConfigurationVersionIngressAttribute.SenderAvatarURL,
		&i.ConfigurationVersionIngressAttribute.SenderHtmlURL,
	)
	return i, err
}

const findConfigurationVersionLatestByWorkspaceID = `-- name: FindConfigurationVersionLatestByWorkspaceID :one
SELECT
    cv.configuration_version_id,
    cv.created_at,
    cv.auto_queue_runs,
    cv.source,
    cv.speculative,
    cv.status,
    cv.workspace_id,
    array_agg(st.*)::"configuration_version_status_timestamps" AS status_timestamps,
    configuration_version_ingress_attributes.branch, configuration_version_ingress_attributes.commit_sha, configuration_version_ingress_attributes.identifier, configuration_version_ingress_attributes.is_pull_request, configuration_version_ingress_attributes.on_default_branch, configuration_version_ingress_attributes.configuration_version_id, configuration_version_ingress_attributes.commit_url, configuration_version_ingress_attributes.pull_request_number, configuration_version_ingress_attributes.pull_request_url, configuration_version_ingress_attributes.pull_request_title, configuration_version_ingress_attributes.tag, configuration_version_ingress_attributes.sender_username, configuration_version_ingress_attributes.sender_avatar_url, configuration_version_ingress_attributes.sender_html_url
FROM configuration_versions cv
JOIN workspaces USING (workspace_id)
JOIN configuration_version_ingress_attributes USING (configuration_version_id)
LEFT JOIN configuration_version_status_timestamps st USING (configuration_version_id)
WHERE cv.workspace_id = $1
GROUP BY cv.configuration_version_id
ORDER BY cv.created_at DESC
`

type FindConfigurationVersionLatestByWorkspaceIDRow struct {
	ConfigurationVersionID               pgtype.Text
	CreatedAt                            pgtype.Timestamptz
	AutoQueueRuns                        pgtype.Bool
	Source                               pgtype.Text
	Speculative                          pgtype.Bool
	Status                               pgtype.Text
	WorkspaceID                          pgtype.Text
	StatusTimestamps                     ConfigurationVersionStatusTimestamp
	ConfigurationVersionIngressAttribute ConfigurationVersionIngressAttribute
}

func (q *Queries) FindConfigurationVersionLatestByWorkspaceID(ctx context.Context, workspaceID pgtype.Text) (FindConfigurationVersionLatestByWorkspaceIDRow, error) {
	row := q.db.QueryRow(ctx, findConfigurationVersionLatestByWorkspaceID, workspaceID)
	var i FindConfigurationVersionLatestByWorkspaceIDRow
	err := row.Scan(
		&i.ConfigurationVersionID,
		&i.CreatedAt,
		&i.AutoQueueRuns,
		&i.Source,
		&i.Speculative,
		&i.Status,
		&i.WorkspaceID,
		&i.StatusTimestamps,
		&i.ConfigurationVersionIngressAttribute.Branch,
		&i.ConfigurationVersionIngressAttribute.CommitSha,
		&i.ConfigurationVersionIngressAttribute.Identifier,
		&i.ConfigurationVersionIngressAttribute.IsPullRequest,
		&i.ConfigurationVersionIngressAttribute.OnDefaultBranch,
		&i.ConfigurationVersionIngressAttribute.ConfigurationVersionID,
		&i.ConfigurationVersionIngressAttribute.CommitURL,
		&i.ConfigurationVersionIngressAttribute.PullRequestNumber,
		&i.ConfigurationVersionIngressAttribute.PullRequestURL,
		&i.ConfigurationVersionIngressAttribute.PullRequestTitle,
		&i.ConfigurationVersionIngressAttribute.Tag,
		&i.ConfigurationVersionIngressAttribute.SenderUsername,
		&i.ConfigurationVersionIngressAttribute.SenderAvatarURL,
		&i.ConfigurationVersionIngressAttribute.SenderHtmlURL,
	)
	return i, err
}

const findConfigurationVersionsByWorkspaceID = `-- name: FindConfigurationVersionsByWorkspaceID :many
SELECT
    cv.configuration_version_id,
    cv.created_at,
    cv.auto_queue_runs,
    cv.source,
    cv.speculative,
    cv.status,
    cv.workspace_id,
    array_agg(st.*)::"configuration_version_status_timestamps" AS status_timestamps,
    configuration_version_ingress_attributes.branch, configuration_version_ingress_attributes.commit_sha, configuration_version_ingress_attributes.identifier, configuration_version_ingress_attributes.is_pull_request, configuration_version_ingress_attributes.on_default_branch, configuration_version_ingress_attributes.configuration_version_id, configuration_version_ingress_attributes.commit_url, configuration_version_ingress_attributes.pull_request_number, configuration_version_ingress_attributes.pull_request_url, configuration_version_ingress_attributes.pull_request_title, configuration_version_ingress_attributes.tag, configuration_version_ingress_attributes.sender_username, configuration_version_ingress_attributes.sender_avatar_url, configuration_version_ingress_attributes.sender_html_url
FROM configuration_versions cv
JOIN workspaces USING (workspace_id)
JOIN configuration_version_ingress_attributes USING (configuration_version_id)
LEFT JOIN configuration_version_status_timestamps st USING (configuration_version_id)
WHERE workspaces.workspace_id = $1
GROUP BY cv.configuration_version_id
LIMIT $3
OFFSET $2
`

type FindConfigurationVersionsByWorkspaceIDParams struct {
	WorkspaceID pgtype.Text
	Offset      int32
	Limit       int32
}

type FindConfigurationVersionsByWorkspaceIDRow struct {
	ConfigurationVersionID               pgtype.Text
	CreatedAt                            pgtype.Timestamptz
	AutoQueueRuns                        pgtype.Bool
	Source                               pgtype.Text
	Speculative                          pgtype.Bool
	Status                               pgtype.Text
	WorkspaceID                          pgtype.Text
	StatusTimestamps                     ConfigurationVersionStatusTimestamp
	ConfigurationVersionIngressAttribute ConfigurationVersionIngressAttribute
}

// FindConfigurationVersions finds configuration_versions for a given workspace.
// Results are paginated with limit and offset, and total count is returned.
func (q *Queries) FindConfigurationVersionsByWorkspaceID(ctx context.Context, arg FindConfigurationVersionsByWorkspaceIDParams) ([]FindConfigurationVersionsByWorkspaceIDRow, error) {
	rows, err := q.db.Query(ctx, findConfigurationVersionsByWorkspaceID, arg.WorkspaceID, arg.Offset, arg.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []FindConfigurationVersionsByWorkspaceIDRow
	for rows.Next() {
		var i FindConfigurationVersionsByWorkspaceIDRow
		if err := rows.Scan(
			&i.ConfigurationVersionID,
			&i.CreatedAt,
			&i.AutoQueueRuns,
			&i.Source,
			&i.Speculative,
			&i.Status,
			&i.WorkspaceID,
			&i.StatusTimestamps,
			&i.ConfigurationVersionIngressAttribute.Branch,
			&i.ConfigurationVersionIngressAttribute.CommitSha,
			&i.ConfigurationVersionIngressAttribute.Identifier,
			&i.ConfigurationVersionIngressAttribute.IsPullRequest,
			&i.ConfigurationVersionIngressAttribute.OnDefaultBranch,
			&i.ConfigurationVersionIngressAttribute.ConfigurationVersionID,
			&i.ConfigurationVersionIngressAttribute.CommitURL,
			&i.ConfigurationVersionIngressAttribute.PullRequestNumber,
			&i.ConfigurationVersionIngressAttribute.PullRequestURL,
			&i.ConfigurationVersionIngressAttribute.PullRequestTitle,
			&i.ConfigurationVersionIngressAttribute.Tag,
			&i.ConfigurationVersionIngressAttribute.SenderUsername,
			&i.ConfigurationVersionIngressAttribute.SenderAvatarURL,
			&i.ConfigurationVersionIngressAttribute.SenderHtmlURL,
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

const insertConfigurationVersion = `-- name: InsertConfigurationVersion :exec
INSERT INTO configuration_versions (
    configuration_version_id,
    created_at,
    auto_queue_runs,
    source,
    speculative,
    status,
    workspace_id
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7
)
`

type InsertConfigurationVersionParams struct {
	ID            pgtype.Text
	CreatedAt     pgtype.Timestamptz
	AutoQueueRuns pgtype.Bool
	Source        pgtype.Text
	Speculative   pgtype.Bool
	Status        pgtype.Text
	WorkspaceID   pgtype.Text
}

func (q *Queries) InsertConfigurationVersion(ctx context.Context, arg InsertConfigurationVersionParams) error {
	_, err := q.db.Exec(ctx, insertConfigurationVersion,
		arg.ID,
		arg.CreatedAt,
		arg.AutoQueueRuns,
		arg.Source,
		arg.Speculative,
		arg.Status,
		arg.WorkspaceID,
	)
	return err
}

const insertConfigurationVersionStatusTimestamp = `-- name: InsertConfigurationVersionStatusTimestamp :one
INSERT INTO configuration_version_status_timestamps (
    configuration_version_id,
    status,
    timestamp
) VALUES (
    $1,
    $2,
    $3
)
RETURNING configuration_version_id, status, timestamp
`

type InsertConfigurationVersionStatusTimestampParams struct {
	ID        pgtype.Text
	Status    pgtype.Text
	Timestamp pgtype.Timestamptz
}

func (q *Queries) InsertConfigurationVersionStatusTimestamp(ctx context.Context, arg InsertConfigurationVersionStatusTimestampParams) (ConfigurationVersionStatusTimestamp, error) {
	row := q.db.QueryRow(ctx, insertConfigurationVersionStatusTimestamp, arg.ID, arg.Status, arg.Timestamp)
	var i ConfigurationVersionStatusTimestamp
	err := row.Scan(&i.ConfigurationVersionID, &i.Status, &i.Timestamp)
	return i, err
}

const updateConfigurationVersionConfigByID = `-- name: UpdateConfigurationVersionConfigByID :one
UPDATE configuration_versions
SET
    config = $1,
    status = 'uploaded'
WHERE configuration_version_id = $2
RETURNING configuration_version_id
`

type UpdateConfigurationVersionConfigByIDParams struct {
	Config []byte
	ID     pgtype.Text
}

func (q *Queries) UpdateConfigurationVersionConfigByID(ctx context.Context, arg UpdateConfigurationVersionConfigByIDParams) (pgtype.Text, error) {
	row := q.db.QueryRow(ctx, updateConfigurationVersionConfigByID, arg.Config, arg.ID)
	var configuration_version_id pgtype.Text
	err := row.Scan(&configuration_version_id)
	return configuration_version_id, err
}

const updateConfigurationVersionErroredByID = `-- name: UpdateConfigurationVersionErroredByID :one
UPDATE configuration_versions
SET
    status = 'errored'
WHERE configuration_version_id = $1
RETURNING configuration_version_id
`

func (q *Queries) UpdateConfigurationVersionErroredByID(ctx context.Context, id pgtype.Text) (pgtype.Text, error) {
	row := q.db.QueryRow(ctx, updateConfigurationVersionErroredByID, id)
	var configuration_version_id pgtype.Text
	err := row.Scan(&configuration_version_id)
	return configuration_version_id, err
}
