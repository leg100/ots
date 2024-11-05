package runner

import (
	"context"
	"net/netip"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/leg100/otf/internal"
	"github.com/leg100/otf/internal/resource"
	"github.com/leg100/otf/internal/sql"
	"github.com/leg100/otf/internal/sql/sqlc"
)

type db struct {
	*sql.DB
}

// runners

type runnerMetaResult struct {
	RunnerID     pgtype.Text
	Name         pgtype.Text
	Version      pgtype.Text
	MaxJobs      pgtype.Int4
	IPAddress    netip.Addr
	LastPingAt   pgtype.Timestamptz
	LastStatusAt pgtype.Timestamptz
	Status       pgtype.Text
	AgentPoolID  pgtype.Text
	AgentPool    *sqlc.AgentPool
	CurrentJobs  int64
}

func (r runnerMetaResult) toRunnerMeta() *RunnerMeta {
	meta := &RunnerMeta{
		ID:           resource.ParseID(r.RunnerID.String),
		Name:         r.Name.String,
		Version:      r.Version.String,
		MaxJobs:      int(r.MaxJobs.Int32),
		CurrentJobs:  int(r.CurrentJobs),
		IPAddress:    r.IPAddress,
		LastPingAt:   r.LastPingAt.Time.UTC(),
		LastStatusAt: r.LastStatusAt.Time.UTC(),
		Status:       RunnerStatus(r.Status.String),
	}
	if r.AgentPool != nil {
		meta.AgentPool = &RunnerMetaAgentPool{
			ID:               resource.ParseID(r.AgentPool.AgentPoolID.String),
			Name:             r.AgentPool.Name.String,
			OrganizationName: r.AgentPool.OrganizationName.String,
		}
	}
	return meta
}

func (db *db) create(ctx context.Context, meta *RunnerMeta) error {
	params := sqlc.InsertRunnerParams{
		RunnerID:     sql.ID(meta.ID),
		Name:         sql.String(meta.Name),
		Version:      sql.String(meta.Version),
		MaxJobs:      sql.Int4(meta.MaxJobs),
		IPAddress:    meta.IPAddress,
		Status:       sql.String(string(meta.Status)),
		LastPingAt:   sql.Timestamptz(meta.LastPingAt),
		LastStatusAt: sql.Timestamptz(meta.LastStatusAt),
	}
	if meta.AgentPool != nil {
		params.AgentPoolID = sql.ID(meta.AgentPool.ID)
	}
	return db.Querier(ctx).InsertRunner(ctx, params)
}

func (db *db) update(ctx context.Context, agentID resource.ID, fn func(*RunnerMeta) error) error {
	err := db.Tx(ctx, func(ctx context.Context, q *sqlc.Queries) error {
		result, err := q.FindRunnerByIDForUpdate(ctx, sql.ID(agentID))
		if err != nil {
			return err
		}
		agent := runnerMetaResult(result).toRunnerMeta()
		if err := fn(agent); err != nil {
			return err
		}
		_, err = q.UpdateRunner(ctx, sqlc.UpdateRunnerParams{
			RunnerID:     sql.ID(agent.ID),
			Status:       sql.String(string(agent.Status)),
			LastPingAt:   sql.Timestamptz(agent.LastPingAt),
			LastStatusAt: sql.Timestamptz(agent.LastStatusAt),
		})
		return err
	})
	if err != nil {
		return sql.Error(err)
	}
	return nil
}

func (db *db) get(ctx context.Context, agentID resource.ID) (*RunnerMeta, error) {
	result, err := db.Querier(ctx).FindRunnerByID(ctx, sql.ID(agentID))
	if err != nil {
		return nil, sql.Error(err)
	}
	return runnerMetaResult(result).toRunnerMeta(), nil
}

func (db *db) list(ctx context.Context) ([]*RunnerMeta, error) {
	rows, err := db.Querier(ctx).FindRunners(ctx)
	if err != nil {
		return nil, sql.Error(err)
	}
	agents := make([]*RunnerMeta, len(rows))
	for i, r := range rows {
		agents[i] = runnerMetaResult(r).toRunnerMeta()
	}
	return agents, nil
}

func (db *db) listServerRunners(ctx context.Context) ([]*RunnerMeta, error) {
	rows, err := db.Querier(ctx).FindServerRunners(ctx)
	if err != nil {
		return nil, sql.Error(err)
	}
	agents := make([]*RunnerMeta, len(rows))
	for i, r := range rows {
		agents[i] = runnerMetaResult(r).toRunnerMeta()
	}
	return agents, nil
}

func (db *db) listRunnersByOrganization(ctx context.Context, organization string) ([]*RunnerMeta, error) {
	rows, err := db.Querier(ctx).FindRunnersByOrganization(ctx, sql.String(organization))
	if err != nil {
		return nil, sql.Error(err)
	}
	agents := make([]*RunnerMeta, len(rows))
	for i, r := range rows {
		agents[i] = runnerMetaResult(r).toRunnerMeta()
	}
	return agents, nil
}

func (db *db) listRunnersByPool(ctx context.Context, poolID resource.ID) ([]*RunnerMeta, error) {
	rows, err := db.Querier(ctx).FindRunnersByPoolID(ctx, sql.ID(poolID))
	if err != nil {
		return nil, sql.Error(err)
	}
	runners := make([]*RunnerMeta, len(rows))
	for i, r := range rows {
		runners[i] = runnerMetaResult(r).toRunnerMeta()
	}
	return runners, nil
}

func (db *db) deleteRunner(ctx context.Context, agentID resource.ID) error {
	_, err := db.Querier(ctx).DeleteRunner(ctx, sql.ID(agentID))
	return sql.Error(err)
}

// jobs

type jobResult struct {
	JobID            pgtype.Text
	RunID            pgtype.Text
	Phase            pgtype.Text
	Status           pgtype.Text
	Signaled         pgtype.Bool
	RunnerID         pgtype.Text
	AgentPoolID      pgtype.Text
	WorkspaceID      pgtype.Text
	OrganizationName pgtype.Text
}

func (r jobResult) toJob() *Job {
	job := &Job{
		RunID:        resource.ParseID(r.RunID.String),
		Phase:        internal.PhaseType(r.Phase.String),
		Status:       JobStatus(r.Status.String),
		WorkspaceID:  resource.ParseID(r.WorkspaceID.String),
		Organization: r.OrganizationName.String,
	}
	if r.RunnerID.Valid {
		runnerID := resource.ParseID(r.RunnerID.String)
		job.RunnerID = &runnerID
	}
	if r.AgentPoolID.Valid {
		agentPoolID := resource.ParseID(r.AgentPoolID.String)
		job.AgentPoolID = &agentPoolID
	}
	if r.Signaled.Valid {
		job.Signaled = &r.Signaled.Bool
	}
	return job
}

func (db *db) createJob(ctx context.Context, job *Job) error {
	err := db.Querier(ctx).InsertJob(ctx, sqlc.InsertJobParams{
		JobID:  sql.ID(job.ID),
		RunID:  sql.ID(job.RunID),
		Phase:  sql.String(string(job.Phase)),
		Status: sql.String(string(job.Status)),
	})
	return sql.Error(err)
}

func (db *db) getAllocatedAndSignaledJobs(ctx context.Context, runnerID resource.ID) ([]*Job, error) {
	allocated, err := db.Querier(ctx).FindAllocatedJobs(ctx, sql.ID(runnerID))
	if err != nil {
		return nil, sql.Error(err)
	}
	signaled, err := db.Querier(ctx).FindAndUpdateSignaledJobs(ctx, sql.ID(runnerID))
	if err != nil {
		return nil, sql.Error(err)
	}
	jobs := make([]*Job, len(allocated)+len(signaled))
	for i, r := range allocated {
		jobs[i] = jobResult(r).toJob()
	}
	for i, r := range signaled {
		jobs[len(allocated)+i] = jobResult(r).toJob()
	}
	return jobs, nil
}

func (db *db) getJob(ctx context.Context, jobID resource.ID) (*Job, error) {
	result, err := db.Querier(ctx).FindJob(ctx, sql.ID(jobID))
	if err != nil {
		return nil, sql.Error(err)
	}
	return jobResult(result).toJob(), nil
}

func (db *db) listJobs(ctx context.Context) ([]*Job, error) {
	rows, err := db.Querier(ctx).FindJobs(ctx)
	if err != nil {
		return nil, sql.Error(err)
	}
	jobs := make([]*Job, len(rows))
	for i, r := range rows {
		jobs[i] = jobResult(r).toJob()
	}
	return jobs, nil
}

func (db *db) updateJob(ctx context.Context, jobID resource.ID, fn func(*Job) error) (*Job, error) {
	var job *Job
	err := db.Tx(ctx, func(ctx context.Context, q *sqlc.Queries) error {
		result, err := q.FindJobForUpdate(ctx, sql.ID(jobID))
		if err != nil {
			return err
		}
		job = jobResult(result).toJob()
		if err := fn(job); err != nil {
			return err
		}
		_, err = q.UpdateJob(ctx, sqlc.UpdateJobParams{
			Status:   sql.String(string(job.Status)),
			Signaled: sql.BoolPtr(job.Signaled),
			RunnerID: sql.IDPtr(job.RunnerID),
			JobID:    result.JobID,
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, sql.Error(err)
	}
	return job, nil
}

// agent tokens

type agentTokenRow struct {
	AgentTokenID pgtype.Text        `json:"agent_token_id"`
	CreatedAt    pgtype.Timestamptz `json:"created_at"`
	Description  pgtype.Text        `json:"description"`
	AgentPoolID  pgtype.Text        `json:"agent_pool_id"`
}

func (row agentTokenRow) toAgentToken() *agentToken {
	return &agentToken{
		ID:          resource.ParseID(row.AgentTokenID.String),
		CreatedAt:   row.CreatedAt.Time.UTC(),
		Description: row.Description.String,
		AgentPoolID: resource.ParseID(row.AgentPoolID.String),
	}
}

func (db *db) createAgentToken(ctx context.Context, token *agentToken) error {
	return db.Querier(ctx).InsertAgentToken(ctx, sqlc.InsertAgentTokenParams{
		AgentTokenID: sql.ID(token.ID),
		Description:  sql.String(token.Description),
		AgentPoolID:  sql.ID(token.AgentPoolID),
		CreatedAt:    sql.Timestamptz(token.CreatedAt.UTC()),
	})
}

func (db *db) getAgentTokenByID(ctx context.Context, id resource.ID) (*agentToken, error) {
	r, err := db.Querier(ctx).FindAgentTokenByID(ctx, sql.ID(id))
	if err != nil {
		return nil, sql.Error(err)
	}
	return agentTokenRow(r).toAgentToken(), nil
}

func (db *db) listAgentTokens(ctx context.Context, poolID resource.ID) ([]*agentToken, error) {
	rows, err := db.Querier(ctx).FindAgentTokensByAgentPoolID(ctx, sql.ID(poolID))
	if err != nil {
		return nil, sql.Error(err)
	}
	tokens := make([]*agentToken, len(rows))
	for i, r := range rows {
		tokens[i] = agentTokenRow(r).toAgentToken()
	}
	return tokens, nil
}

func (db *db) deleteAgentToken(ctx context.Context, id resource.ID) error {
	_, err := db.Querier(ctx).DeleteAgentTokenByID(ctx, sql.ID(id))
	if err != nil {
		return sql.Error(err)
	}
	return nil
}

// agent pools

type poolresult struct {
	AgentPoolID         pgtype.Text
	Name                pgtype.Text
	CreatedAt           pgtype.Timestamptz
	OrganizationName    pgtype.Text
	OrganizationScoped  pgtype.Bool
	WorkspaceIds        []pgtype.Text
	AllowedWorkspaceIds []pgtype.Text
}

func (r poolresult) toPool() *Pool {
	pool := &Pool{
		ID:                 resource.ParseID(r.AgentPoolID.String),
		Name:               r.Name.String,
		CreatedAt:          r.CreatedAt.Time.UTC(),
		Organization:       r.OrganizationName.String,
		OrganizationScoped: r.OrganizationScoped.Bool,
	}
	pool.AssignedWorkspaces = make([]resource.ID, len(r.WorkspaceIds))
	for i, wid := range r.WorkspaceIds {
		pool.AssignedWorkspaces[i] = resource.ParseID(wid.String)
	}
	pool.AllowedWorkspaces = make([]resource.ID, len(r.AllowedWorkspaceIds))
	for i, wid := range r.AllowedWorkspaceIds {
		pool.AllowedWorkspaces[i] = resource.ParseID(wid.String)
	}
	return pool
}

func (db *db) createPool(ctx context.Context, pool *Pool) error {
	err := db.Tx(ctx, func(ctx context.Context, q *sqlc.Queries) error {
		err := db.Querier(ctx).InsertAgentPool(ctx, sqlc.InsertAgentPoolParams{
			AgentPoolID:        sql.ID(pool.ID),
			Name:               sql.String(pool.Name),
			CreatedAt:          sql.Timestamptz(pool.CreatedAt),
			OrganizationName:   sql.String(pool.Organization),
			OrganizationScoped: sql.Bool(pool.OrganizationScoped),
		})
		if err != nil {
			return err
		}
		for _, workspaceID := range pool.AllowedWorkspaces {
			err := q.InsertAgentPoolAllowedWorkspace(ctx, sqlc.InsertAgentPoolAllowedWorkspaceParams{
				PoolID:      sql.ID(pool.ID),
				WorkspaceID: sql.ID(workspaceID),
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *db) updatePool(ctx context.Context, pool *Pool) error {
	_, err := db.Querier(ctx).UpdateAgentPool(ctx, sqlc.UpdateAgentPoolParams{
		PoolID:             sql.ID(pool.ID),
		Name:               sql.String(pool.Name),
		OrganizationScoped: sql.Bool(pool.OrganizationScoped),
	})
	if err != nil {
		return sql.Error(err)
	}
	return nil
}

func (db *db) addAgentPoolAllowedWorkspace(ctx context.Context, poolID, workspaceID resource.ID) error {
	err := db.Querier(ctx).InsertAgentPoolAllowedWorkspace(ctx, sqlc.InsertAgentPoolAllowedWorkspaceParams{
		PoolID:      sql.ID(poolID),
		WorkspaceID: sql.ID(workspaceID),
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *db) deleteAgentPoolAllowedWorkspace(ctx context.Context, poolID, workspaceID resource.ID) error {
	err := db.Querier(ctx).DeleteAgentPoolAllowedWorkspace(ctx, sqlc.DeleteAgentPoolAllowedWorkspaceParams{
		PoolID:      sql.ID(poolID),
		WorkspaceID: sql.ID(workspaceID),
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *db) getPool(ctx context.Context, poolID resource.ID) (*Pool, error) {
	result, err := db.Querier(ctx).FindAgentPool(ctx, sql.ID(poolID))
	if err != nil {
		return nil, sql.Error(err)
	}
	return poolresult(result).toPool(), nil
}

func (db *db) getPoolByTokenID(ctx context.Context, tokenID resource.ID) (*Pool, error) {
	result, err := db.Querier(ctx).FindAgentPoolByAgentTokenID(ctx, sql.ID(tokenID))
	if err != nil {
		return nil, sql.Error(err)
	}
	return poolresult(result).toPool(), nil
}

func (db *db) listPoolsByOrganization(ctx context.Context, organization string, opts listPoolOptions) ([]*Pool, error) {
	rows, err := db.Querier(ctx).FindAgentPoolsByOrganization(ctx, sqlc.FindAgentPoolsByOrganizationParams{
		OrganizationName:     sql.String(organization),
		NameSubstring:        sql.StringPtr(opts.NameSubstring),
		AllowedWorkspaceName: sql.StringPtr(opts.AllowedWorkspaceName),
		AllowedWorkspaceID:   sql.IDPtr(opts.AllowedWorkspaceID),
	})
	if err != nil {
		return nil, sql.Error(err)
	}
	pools := make([]*Pool, len(rows))
	for i, r := range rows {
		pools[i] = poolresult(r).toPool()
	}
	return pools, nil
}

func (db *db) deleteAgentPool(ctx context.Context, poolID resource.ID) error {
	_, err := db.Querier(ctx).DeleteAgentPool(ctx, sql.ID(poolID))
	if err != nil {
		return sql.Error(err)
	}
	return nil
}
