package otf

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartRun(t *testing.T) {
	ctx := context.Background()
	org := NewTestOrganization(t)

	t.Run("not connected to repo", func(t *testing.T) {
		ws := NewTestWorkspace(t, org, WorkspaceCreateOptions{})
		cv := NewTestConfigurationVersion(t, ws, ConfigurationVersionCreateOptions{})
		want := NewRun(cv, ws, RunCreateOptions{})
		app := RunStarter{
			Application: &fakeStartRunApp{
				run:       want,
				workspace: ws,
				cv:        cv,
			},
		}

		got, err := app.StartRun(ctx, ws.SpecName(), ConfigurationVersionCreateOptions{})
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("connected to repo", func(t *testing.T) {
		provider := NewTestVCSProvider(t, org)
		repo := NewTestWorkspaceRepo(provider)
		ws := NewTestWorkspace(t, org, WorkspaceCreateOptions{
			Repo: repo,
		})
		cv := NewTestConfigurationVersion(t, ws, ConfigurationVersionCreateOptions{})
		want := NewRun(cv, ws, RunCreateOptions{})
		app := RunStarter{
			Application: &fakeStartRunApp{
				run:       want,
				workspace: ws,
				cv:        cv,
			},
		}

		got, err := app.StartRun(ctx, ws.SpecName(), ConfigurationVersionCreateOptions{})
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})
}

type fakeStartRunApp struct {
	run       *Run
	workspace *Workspace
	cv        *ConfigurationVersion

	Application
}

func (f *fakeStartRunApp) GetWorkspace(ctx context.Context, spec WorkspaceSpec) (*Workspace, error) {
	return f.workspace, nil
}

func (f *fakeStartRunApp) GetRepoTarball(context.Context, string, GetRepoTarballOptions) ([]byte, error) {
	return nil, nil
}

func (f *fakeStartRunApp) CreateConfigurationVersion(context.Context, string, ConfigurationVersionCreateOptions) (*ConfigurationVersion, error) {
	return f.cv, nil
}

func (f *fakeStartRunApp) GetLatestConfigurationVersion(context.Context, string) (*ConfigurationVersion, error) {
	return f.cv, nil
}

func (f *fakeStartRunApp) CloneConfigurationVersion(context.Context, string, ConfigurationVersionCreateOptions) (*ConfigurationVersion, error) {
	return f.cv, nil
}

func (f *fakeStartRunApp) UploadConfig(context.Context, string, []byte) error {
	return nil
}

func (f *fakeStartRunApp) CreateRun(ctx context.Context, spec WorkspaceSpec, opts RunCreateOptions) (*Run, error) {
	return f.run, nil
}