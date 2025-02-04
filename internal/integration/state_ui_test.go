package integration

import (
	"regexp"
	"testing"

	"github.com/leg100/otf/internal/run"
	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/require"
)

// TestIntegration_StateUI demonstrates the displaying of terraform state via
// the UI
func TestIntegration_StateUI(t *testing.T) {
	integrationTest(t)

	daemon, org, ctx := setup(t, nil)
	ws := daemon.createWorkspace(t, ctx, org)
	cv := daemon.createAndUploadConfigurationVersion(t, ctx, ws, nil)

	// create run and wait for it to complete
	r := daemon.createRun(t, ctx, ws, cv, nil)
	planned := daemon.waitRunStatus(t, r.ID, run.RunPlanned)
	err := daemon.Runs.Apply(ctx, planned.ID)
	require.NoError(t, err)
	daemon.waitRunStatus(t, r.ID, run.RunApplied)

	browser.New(t, ctx, func(page playwright.Page) {
		_, err := page.Goto(workspaceURL(daemon.System.Hostname(), org.Name, ws.Name))
		require.NoError(t, err)

		err = expect.Locator(page.Locator(`//label[@id='resources-label']`)).ToHaveText(regexp.MustCompile(`Resources \(1\)`))
		require.NoError(t, err)

		err = expect.Locator(page.Locator(`//label[@id='outputs-label']`)).ToHaveText(regexp.MustCompile(`Outputs \(0\)`))
		require.NoError(t, err)

		err = expect.Locator(page.Locator(`//table[@id='resources-table']/tbody/tr/td[1]`)).ToHaveText(`test`)
		require.NoError(t, err)

		err = expect.Locator(page.Locator(`//table[@id='resources-table']/tbody/tr/td[2]`)).ToHaveText(`hashicorp/null`)
		require.NoError(t, err)

		err = expect.Locator(page.Locator(`//table[@id='resources-table']/tbody/tr/td[3]`)).ToHaveText(`null_resource`)
		require.NoError(t, err)

		err = expect.Locator(page.Locator(`//table[@id='resources-table']/tbody/tr/td[4]`)).ToHaveText(`root`)
		require.NoError(t, err)
	})
}
