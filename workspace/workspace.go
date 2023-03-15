// Package workspace provides access to terraform workspaces
package workspace

import (
	"context"
	"errors"
	"time"

	"github.com/leg100/otf"
	"github.com/leg100/otf/rbac"
	"github.com/leg100/otf/semver"
	"github.com/leg100/otf/vcsprovider"
)

const (
	RemoteExecutionMode ExecutionMode = "remote"
	LocalExecutionMode  ExecutionMode = "local"
	AgentExecutionMode  ExecutionMode = "agent"

	DefaultAllowDestroyPlan    = true
	DefaultFileTriggersEnabled = true
)

type (
	// Workspace is a terraform workspace.
	Workspace struct {
		ID                         string
		CreatedAt                  time.Time
		UpdatedAt                  time.Time
		AllowDestroyPlan           bool
		AutoApply                  bool
		Branch                     string
		CanQueueDestroyPlan        bool
		Description                string
		Environment                string
		ExecutionMode              ExecutionMode
		FileTriggersEnabled        bool
		GlobalRemoteState          bool
		MigrationEnvironment       string
		Name                       string
		QueueAllRuns               bool
		SpeculativeEnabled         bool
		StructuredRunOutputEnabled bool
		SourceName                 string
		SourceURL                  string
		TerraformVersion           string
		TriggerPrefixes            []string
		WorkingDirectory           string
		Organization               string
		LatestRunID                *string
		Connection                 *otf.Connection
		Permissions                []otf.WorkspacePermission

		Lock
	}

	ExecutionMode string

	// WorkspaceList is a list of workspaces.
	WorkspaceList struct {
		*otf.Pagination
		Items []*Workspace
	}

	// CreateWorkspaceOptions represents the options for creating a new workspace.
	CreateWorkspaceOptions struct {
		AllowDestroyPlan           *bool
		AutoApply                  *bool
		Branch                     *string
		Description                *string
		ExecutionMode              *ExecutionMode
		FileTriggersEnabled        *bool
		GlobalRemoteState          *bool
		MigrationEnvironment       *string
		Name                       *string `schema:"name,required"`
		QueueAllRuns               *bool
		SpeculativeEnabled         *bool
		SourceName                 *string
		SourceURL                  *string
		StructuredRunOutputEnabled *bool
		TerraformVersion           *string
		TriggerPrefixes            []string
		WorkingDirectory           *string
		Organization               *string `schema:"organization_name,required"`

		*ConnectWorkspaceOptions
	}

	UpdateWorkspaceOptions struct {
		AllowDestroyPlan           *bool
		AutoApply                  *bool
		Name                       *string
		Description                *string
		ExecutionMode              *ExecutionMode `schema:"execution_mode"`
		FileTriggersEnabled        *bool
		GlobalRemoteState          *bool
		Operations                 *bool
		QueueAllRuns               *bool
		SpeculativeEnabled         *bool
		StructuredRunOutputEnabled *bool
		TerraformVersion           *string `schema:"terraform_version"`
		TriggerPrefixes            []string
		WorkingDirectory           *string
	}

	// WorkspaceListOptions are options for paginating and filtering a list of
	// Workspaces
	WorkspaceListOptions struct {
		// Pagination
		otf.ListOptions
		// Filter workspaces with name matching prefix.
		Prefix string `schema:"search[name],omitempty"`
		// Organization filters workspaces by organization name.
		Organization *string `schema:"organization_name,omitempty"`
		// Filter by those for which user has workspace-level permissions.
		UserID *string
	}

	WorkspaceLockService interface {
		LockWorkspace(ctx context.Context, workspaceID string) (Workspace, error)
		UnlockWorkspace(ctx context.Context, workspaceID string, force bool) (Workspace, error)
	}

	WorkspaceConnectionService interface {
		ConnectWorkspace(ctx context.Context, workspaceID string, opts ConnectWorkspaceOptions) (*otf.Connection, error)
		DisconnectWorkspace(ctx context.Context, workspaceID string) error
	}

	ConnectWorkspaceOptions struct {
		RepoPath      string `schema:"identifier,required"` // repo id: <owner>/<repo>
		VCSProviderID string `schema:"vcs_provider_id,required"`
	}

	WorkspacePermissionService interface {
		GetPolicy(ctx context.Context, workspaceID string) (otf.WorkspacePolicy, error)

		SetWorkspacePermission(ctx context.Context, workspaceID, team string, role rbac.Role) error
		UnsetWorkspacePermission(ctx context.Context, workspaceID, team string) error
	}

	// WorkspaceDB is a persistence store for workspaces.
	WorkspaceDB interface {
		GetWorkspace(ctx context.Context, workspaceID string) (Workspace, error)
		GetWorkspaceByName(ctx context.Context, organization, workspace string) (Workspace, error)
		GetWorkspaceIDByRunID(ctx context.Context, runID string) (string, error)
		GetWorkspaceIDByStateVersionID(ctx context.Context, svID string) (string, error)
		GetWorkspaceIDByCVID(ctx context.Context, cvID string) (string, error)
		GetOrganizationNameByWorkspaceID(ctx context.Context, workspaceID string) (string, error)

		GetWorkspacePolicy(ctx context.Context, workspaceID string) (otf.WorkspacePolicy, error)
	}

	// WorkspaceQualifiedName is the workspace's fully qualified name including the
	// name of its organization
	WorkspaceQualifiedName struct {
		Organization string
		Name         string
	}

	VCSProviderService vcsprovider.Service
)

func NewWorkspace(opts CreateWorkspaceOptions) (*Workspace, error) {
	// required options
	if opts.Name == nil {
		return nil, otf.ErrRequiredName
	}
	if opts.Organization == nil {
		return nil, otf.ErrRequiredOrg
	}

	ws := Workspace{
		ID:                  otf.NewID("ws"),
		CreatedAt:           otf.CurrentTimestamp(),
		UpdatedAt:           otf.CurrentTimestamp(),
		AllowDestroyPlan:    DefaultAllowDestroyPlan,
		ExecutionMode:       RemoteExecutionMode,
		FileTriggersEnabled: DefaultFileTriggersEnabled,
		GlobalRemoteState:   true, // Only global remote state is supported
		TerraformVersion:    otf.DefaultTerraformVersion,
		SpeculativeEnabled:  true,
		Organization:        *opts.Organization,
	}
	if err := ws.setName(*opts.Name); err != nil {
		return nil, err
	}

	if opts.ExecutionMode != nil {
		if err := ws.setExecutionMode(*opts.ExecutionMode); err != nil {
			return nil, err
		}
	}
	if opts.AllowDestroyPlan != nil {
		ws.AllowDestroyPlan = *opts.AllowDestroyPlan
	}
	if opts.AutoApply != nil {
		ws.AutoApply = *opts.AutoApply
	}
	if opts.Branch != nil {
		ws.Branch = *opts.Branch
	}
	if opts.Description != nil {
		ws.Description = *opts.Description
	}
	if opts.FileTriggersEnabled != nil {
		ws.FileTriggersEnabled = *opts.FileTriggersEnabled
	}
	if opts.QueueAllRuns != nil {
		ws.QueueAllRuns = *opts.QueueAllRuns
	}
	if opts.SourceName != nil {
		ws.SourceName = *opts.SourceName
	}
	if opts.SourceURL != nil {
		ws.SourceURL = *opts.SourceURL
	}
	if opts.SpeculativeEnabled != nil {
		ws.SpeculativeEnabled = *opts.SpeculativeEnabled
	}
	if opts.StructuredRunOutputEnabled != nil {
		ws.StructuredRunOutputEnabled = *opts.StructuredRunOutputEnabled
	}
	if opts.TerraformVersion != nil {
		if err := ws.setTerraformVersion(*opts.TerraformVersion); err != nil {
			return nil, err
		}
	}
	if opts.TriggerPrefixes != nil {
		ws.TriggerPrefixes = opts.TriggerPrefixes
	}
	if opts.WorkingDirectory != nil {
		ws.WorkingDirectory = *opts.WorkingDirectory
	}
	return &ws, nil
}

// ExecutionModePtr returns a pointer to an execution mode.
func ExecutionModePtr(m ExecutionMode) *ExecutionMode {
	return &m
}

func (ws *Workspace) String() string { return ws.Organization + "/" + ws.Name }

// ExecutionModes returns a list of possible execution modes
func (ws *Workspace) ExecutionModes() []string {
	return []string{"local", "remote", "agent"}
}

// QualifiedName returns the workspace's qualified name including the name of
// its organization
func (ws *Workspace) QualifiedName() WorkspaceQualifiedName {
	return WorkspaceQualifiedName{
		Organization: ws.Organization,
		Name:         ws.Name,
	}
}

func (ws *Workspace) MarshalLog() any {
	log := struct {
		Name         string `json:"name"`
		Organization string `json:"organization"`
	}{
		Name:         ws.Name,
		Organization: ws.Organization,
	}
	return log
}

// Update updates the workspace with the given options.
func (ws *Workspace) Update(opts UpdateWorkspaceOptions) error {
	var updated bool

	if opts.Name != nil {
		if err := ws.setName(*opts.Name); err != nil {
			return err
		}
		updated = true
	}
	if opts.AllowDestroyPlan != nil {
		ws.AllowDestroyPlan = *opts.AllowDestroyPlan
		updated = true
	}
	if opts.AutoApply != nil {
		ws.AutoApply = *opts.AutoApply
		updated = true
	}
	if opts.Description != nil {
		ws.Description = *opts.Description
		updated = true
	}
	if opts.ExecutionMode != nil {
		if err := ws.setExecutionMode(*opts.ExecutionMode); err != nil {
			return err
		}
		updated = true
	}
	if opts.FileTriggersEnabled != nil {
		ws.FileTriggersEnabled = *opts.FileTriggersEnabled
		updated = true
	}
	if opts.Operations != nil {
		if *opts.Operations {
			ws.ExecutionMode = "remote"
		} else {
			ws.ExecutionMode = "local"
		}
		updated = true
	}
	if opts.QueueAllRuns != nil {
		ws.QueueAllRuns = *opts.QueueAllRuns
		updated = true
	}
	if opts.SpeculativeEnabled != nil {
		ws.SpeculativeEnabled = *opts.SpeculativeEnabled
		updated = true
	}
	if opts.StructuredRunOutputEnabled != nil {
		ws.StructuredRunOutputEnabled = *opts.StructuredRunOutputEnabled
		updated = true
	}
	if opts.TerraformVersion != nil {
		if err := ws.setTerraformVersion(*opts.TerraformVersion); err != nil {
			return err
		}
		updated = true
	}
	if opts.TriggerPrefixes != nil {
		ws.TriggerPrefixes = opts.TriggerPrefixes
		updated = true
	}
	if opts.WorkingDirectory != nil {
		ws.WorkingDirectory = *opts.WorkingDirectory
		updated = true
	}
	if updated {
		ws.UpdatedAt = otf.CurrentTimestamp()
	}

	return nil
}

func (ws *Workspace) setName(name string) error {
	if !otf.ReStringID.MatchString(name) {
		return otf.ErrInvalidName
	}
	ws.Name = name
	return nil
}

func (ws *Workspace) setExecutionMode(m ExecutionMode) error {
	if m != RemoteExecutionMode && m != LocalExecutionMode && m != AgentExecutionMode {
		return errors.New("invalid execution mode")
	}
	ws.ExecutionMode = m
	return nil
}

func (ws *Workspace) setTerraformVersion(v string) error {
	if !otf.ValidSemanticVersion(v) {
		return otf.ErrInvalidTerraformVersion
	}
	if result := semver.Compare(v, otf.MinTerraformVersion); result < 0 {
		return otf.ErrUnsupportedTerraformVersion
	}
	ws.TerraformVersion = v
	return nil
}

// CurrentRunService provides interaction with the current run for a workspace,
// i.e. the current, or most recently current, non-speculative, run.
type CurrentRunService interface {
	// SetCurrentRun sets the ID of the latest run for a workspace.
	//
	// Take full run obj as param
	SetCurrentRun(ctx context.Context, workspaceID, runID string) (*Workspace, error)
}
