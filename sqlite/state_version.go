package sqlite

import (
	"fmt"
	"strings"

	sq "github.com/Masterminds/squirrel"
	"github.com/jmoiron/sqlx"
	"github.com/leg100/otf"
)

var (
	_ otf.StateVersionStore = (*StateVersionService)(nil)

	stateVersionTableName = "state_versions"

	stateVersionColumnsWithoutID = []string{"created_at", "updated_at", "external_id", "serial", "blob_id"}
	stateVersionColumns          = append(stateVersionColumnsWithoutID, "id")

	insertStateVersionSQL = fmt.Sprintf("INSERT INTO state_versions (%s, workspace_id) VALUES (%s, :workspaces.id)",
		strings.Join(stateVersionColumnsWithoutID, ", "),
		strings.Join(otf.PrefixSlice(stateVersionColumnsWithoutID, ":"), ", "))
)

type StateVersionService struct {
	*sqlx.DB
	columns []string
}

func NewStateVersionDB(db *sqlx.DB) *StateVersionService {
	return &StateVersionService{
		DB: db,
	}
}

// Create persists a StateVersion to the DB.
func (s StateVersionService) Create(sv *otf.StateVersion) (*otf.StateVersion, error) {
	// Insert
	result, err := s.NamedExec(insertStateVersionSQL, sv)
	if err != nil {
		return nil, err
	}
	sv.Model.ID, err = result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return sv, nil
}

func (s StateVersionService) List(opts otf.StateVersionListOptions) (*otf.StateVersionList, error) {
	if opts.Workspace == nil {
		return nil, fmt.Errorf("missing required option: workspace")
	}
	if opts.Organization == nil {
		return nil, fmt.Errorf("missing required option: organization")
	}

	selectBuilder := sq.Select(asColumnList("state_versions", false, stateVersionColumns...)).
		Columns(asColumnList("workspaces", true, workspaceColumns...)).
		From("state_versions").
		Join("workspaces ON workspaces.id = state_versions.workspace_id").
		Join("organizations ON organizations.id = workspaces.organization_id").
		Where("workspaces.name = ?", *opts.Workspace).
		Where("organizations.name = ?", *opts.Organization).
		Limit(opts.GetLimit()).
		Offset(opts.GetOffset())

	sql, args, err := selectBuilder.ToSql()
	if err != nil {
		return nil, err
	}

	var result []otf.StateVersion
	if err := s.Select(&result, sql, args...); err != nil {
		return nil, err
	}

	// Convert from []otf.StateVersion to []*otf.StateVersion
	var items []*otf.StateVersion
	for _, r := range result {
		items = append(items, &r)
	}

	return &otf.StateVersionList{
		Items:      items,
		Pagination: otf.NewPagination(opts.ListOptions, len(items)),
	}, nil
}

func (s StateVersionService) Get(opts otf.StateVersionGetOptions) (*otf.StateVersion, error) {
	selectBuilder := sq.Select(asColumnList("state_versions", false, stateVersionColumns...)).
		Columns(asColumnList("workspaces", true, workspaceColumns...)).
		From("state_versions").
		Join("workspaces ON workspaces.id = state_versions.workspace_id")

	switch {
	case opts.ID != nil:
		// Get state version by ID
		selectBuilder = selectBuilder.Where("state_versions.external_id = ?", *opts.ID)
	case opts.WorkspaceID != nil:
		// Get latest state version for given workspace
		selectBuilder = selectBuilder.Where("workspaces.external_id = ?", *opts.WorkspaceID)
		selectBuilder = selectBuilder.OrderBy("state_versions.serial DESC, state_versions.created_at DESC")
	default:
		return nil, otf.ErrInvalidWorkspaceSpecifier
	}

	sql, args, err := selectBuilder.ToSql()
	if err != nil {
		return nil, err
	}

	sv := otf.StateVersion{}
	if err := s.DB.Get(&sv, sql, args...); err != nil {
		return nil, err
	}

	return &sv, nil
}
