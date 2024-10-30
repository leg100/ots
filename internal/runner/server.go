package runner

import (
	"context"

	"github.com/leg100/otf/internal"
	"github.com/leg100/otf/internal/logr"
	"github.com/leg100/otf/internal/releases"
)

// ServerRunnerOptions are options for constructing a server runner.
type ServerRunnerOptions struct {
	*Config

	Logger     logr.Logger
	Runners    *Service
	Runs       runClient
	Workspaces workspaceClient
	Variables  variablesClient
	State      stateClient
	Configs    configClient
	Logs       logsClient
	Server     hostnameClient
	Jobs       operationJobsClient
}

// ServerRunner is a runner built into the otfd server prcess.
type ServerRunner struct {
	*Runner
}

// NewServerRunner constructs a server runner.
func NewServerRunner(opts ServerRunnerOptions) (*ServerRunner, error) {
	daemon, err := newRunner(
		opts.Logger,
		opts.Runners,
		&localOperationSpawner{
			logger:     opts.Logger,
			runs:       opts.Runs,
			workspaces: opts.Workspaces,
			variables:  opts.Variables,
			state:      opts.State,
			configs:    opts.Configs,
			logs:       opts.Logs,
			server:     opts.Server,
			jobs:       opts.Jobs,
			downloader: releases.NewDownloader(opts.TerraformBinDir),
		},
		false,
		*opts.Config,
	)
	if err != nil {
		return nil, err
	}
	return &ServerRunner{Runner: daemon}, nil
}

// Start the server runner daemon.
func (d *ServerRunner) Start(ctx context.Context) error {
	// Authenticate as runner with server endpoints.
	ctx = internal.AddSubjectToContext(ctx, d.RunnerMeta)

	return d.Runner.Start(ctx)
}

type localOperationSpawner struct {
	logger     logr.Logger
	downloader downloader
	runs       runClient
	workspaces workspaceClient
	variables  variablesClient
	state      stateClient
	configs    configClient
	logs       logsClient
	server     hostnameClient
	jobs       operationJobsClient
}

func (l *localOperationSpawner) newOperation(job *Job, jobToken []byte) (*operation, error) {
	return newOperation(operationOptions{
		logger:     l.logger,
		job:        job,
		jobToken:   jobToken,
		downloader: l.downloader,
		runs:       l.runs,
		workspaces: l.workspaces,
		variables:  l.variables,
		state:      l.state,
		configs:    l.configs,
		logs:       l.logs,
		server:     l.server,
	}), nil
}
