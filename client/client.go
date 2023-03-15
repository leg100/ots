// Package client allows remote interaction with the otf application
package client

import (
	"context"

	"github.com/leg100/otf"
	"github.com/leg100/otf/auth"
	"github.com/leg100/otf/http"
	"github.com/leg100/otf/organization"
	"github.com/leg100/otf/run"
	"github.com/leg100/otf/state"
	"github.com/leg100/otf/variable"
	"github.com/leg100/otf/watch"
	"github.com/leg100/otf/workspace"
)

type (
	// Client is those service endpoints that support both in-process and remote
	// invocation. Intended for use with the agent (the internal agent is
	// in-process, while the external agent is remote) as well as the CLI.
	Client interface {
		CreateOrganization(ctx context.Context, opts organization.OrganizationCreateOptions) (*organization.Organization, error)

		GetWorkspace(ctx context.Context, workspaceID string) (*workspace.Workspace, error)
		GetWorkspaceByName(ctx context.Context, organization, workspace string) (*workspace.Workspace, error)
		ListWorkspaces(ctx context.Context, opts workspace.WorkspaceListOptions) (*workspace.WorkspaceList, error)
		UpdateWorkspace(ctx context.Context, workspaceID string, opts workspace.UpdateWorkspaceOptions) (*workspace.Workspace, error)

		ListVariables(ctx context.Context, workspaceID string) ([]*variable.Variable, error)

		CreateAgentToken(ctx context.Context, opts otf.CreateAgentTokenOptions) (*otf.AgentToken, error)
		GetAgentToken(ctx context.Context, token string) (*otf.AgentToken, error)

		GetPlanFile(ctx context.Context, id string, format run.PlanFormat) ([]byte, error)
		UploadPlanFile(ctx context.Context, id string, plan []byte, format run.PlanFormat) error
		GetLockFile(ctx context.Context, id string) ([]byte, error)
		UploadLockFile(ctx context.Context, id string, lockFile []byte) error
		ListRuns(ctx context.Context, opts run.RunListOptions) (*run.RunList, error)
		GetRun(ctx context.Context, id string) (*run.Run, error)
		StartPhase(ctx context.Context, id string, phase otf.PhaseType, opts run.PhaseStartOptions) (*run.Run, error)
		FinishPhase(ctx context.Context, id string, phase otf.PhaseType, opts run.PhaseFinishOptions) (*run.Run, error)

		PutChunk(ctx context.Context, chunk otf.Chunk) error

		DownloadConfig(ctx context.Context, id string) ([]byte, error)

		Watch(context.Context, otf.WatchOptions) (<-chan otf.Event, error)

		// CreateRegistrySession creates a registry session for the given organization.
		CreateRegistrySession(ctx context.Context, organization string) (*auth.RegistrySession, error)

		workspace.WorkspaceLockService
		state.Service
		otf.HostnameService
	}

	remoteClient struct {
		*http.Client
		http.Config

		stateClient
		variableClient
		authClient
		watchClient
		organizationClient
		workspaceClient
		runClient
	}

	stateClient        = state.Client
	variableClient     = variable.Client
	authClient         = auth.Client
	organizationClient = organization.Client
	workspaceClient    = workspace.Client
	runClient          = run.Client
	watchClient        = watch.Client
)

// New constructs a client that uses the http to remotely invoke OTF
// services.
func New(config http.Config) (*remoteClient, error) {
	httpClient, err := http.NewClient(config)
	if err != nil {
		return nil, err
	}

	return &remoteClient{
		Client:             httpClient,
		stateClient:        stateClient{httpClient},
		variableClient:     variableClient{httpClient},
		authClient:         authClient{httpClient},
		organizationClient: organizationClient{httpClient},
		workspaceClient:    workspaceClient{httpClient},
		runClient:          runClient{httpClient},
		watchClient:        watchClient{config},
	}, nil
}
