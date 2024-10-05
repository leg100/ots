package integration

import (
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/require"
)

// TestWritePermissionE2E demonstrates a user with write permissions on a workspace interacting
// with the workspace via the terraform CLI.
func TestWritePermissionE2E(t *testing.T) {
	integrationTest(t)

	// Create user and org, and user becomes owner of the org
	svc, org, ctx := setup(t, nil)

	// Create engineer user and team and make member of a team
	engineer, engineerCtx := svc.createUserCtx(t)
	team := svc.createTeam(t, ctx, org)
	err := svc.Users.AddTeamMembership(ctx, team.ID, []string{engineer.Username})
	require.NoError(t, err)

	// create terraform config
	config := newRootModule(t, svc.System.Hostname(), org.Name, "my-test-workspace")

	// Open browser, create workspace and assign write permissions to the
	// engineer's team.
	page := browser.New(t, ctx)
		createWorkspace(t, svc.System.Hostname(), org.Name, "my-test-workspace"),
		addWorkspacePermission(t, svc.System.Hostname(), org.Name, "my-test-workspace", team.ID, "write"),
	})

	// As engineer, run terraform init
	_ = svc.tfcli(t, engineerCtx, "init", config)

	out := svc.tfcli(t, engineerCtx, "plan", config)
	require.Contains(t, out, "Plan: 1 to add, 0 to change, 0 to destroy.")

	out = svc.tfcli(t, engineerCtx, "apply", config, "-auto-approve")
	require.Contains(t, out, "Apply complete! Resources: 1 added, 0 changed, 0 destroyed.")

	out = svc.tfcli(t, engineerCtx, "destroy", config, "-auto-approve")
	require.Contains(t, out, "Apply complete! Resources: 0 added, 0 changed, 1 destroyed.")

	// lock and unlock workspace
	svc.otfcli(t, ctx, "workspaces", "lock", "my-test-workspace", "--organization", org.Name)
	svc.otfcli(t, ctx, "workspaces", "unlock", "my-test-workspace", "--organization", org.Name)

	// list workspaces
	out = svc.otfcli(t, ctx, "workspaces", "list", "--organization", org.Name)
	require.Contains(t, out, "my-test-workspace")
}
