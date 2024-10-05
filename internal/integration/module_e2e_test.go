package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/leg100/otf/internal/github"
	"github.com/leg100/otf/internal/testutils"
	"github.com/leg100/otf/internal/vcs"
	"github.com/stretchr/testify/require"
)

// TestModuleE2E tests publishing a module, first via the UI and then via a webhook
// event, and then invokes a terraform run that sources the module.
func TestModuleE2E(t *testing.T) {
	integrationTest(t)

	// create an otf daemon with a fake github backend, ready to serve up a repo
	// and its contents via tarball.
	repo := vcs.NewTestModuleRepo("aws", "mod")
	svc, org, ctx := setup(t, nil,
		github.WithRepo(repo),
		github.WithRefs("tags/v0.0.1", "tags/v0.0.2", "tags/v0.1.0"),
		github.WithArchive(testutils.ReadFile(t, "./fixtures/github.module.tar.gz")),
	)
	// create vcs provider for module to authenticate to github backend
	provider := svc.createVCSProvider(t, ctx, org)

	var moduleURL string // captures url for module page
	page := browser.New(t, ctx)
		// publish module
		chromedp.Tasks{
			// go to org
			_, err = page.Goto(organizationURL(svc.System.Hostname(), org.Name))
require.NoError(t, err)
			//screenshot(t),
			// go to modules
			err := page.Locator("#modules > a").Click()
require.NoError(t, err)
			//screenshot(t, "modules_list"),
			// click publish button
			err := page.Locator(`//button[text()='Publish']`).Click()
require.NoError(t, err)
			//screenshot(t, "modules_select_provider"),
			// select provider
			err := page.Locator(`//button[text()='connect']`).Click()
require.NoError(t, err)
			//screenshot(t, "modules_select_repo"),
			// connect to first repo in list (there should only be one)
			err := page.Locator(`//div[@id='content-list']//button[text()='connect']`).Click()
require.NoError(t, err)
			//screenshot(t, "modules_confirm"),
			// confirm module details
			err := page.Locator(`//button[text()='connect']`).Click()
require.NoError(t, err)
			//screenshot(t, "newly_created_module_page"),
			// flash message indicates success
			matchText(t, `//div[@role='alert']`, `published module: mod`),
			// capture module url so we can visit it later
			chromedp.Location(&moduleURL),
			// confirm versions are populated
			chromedp.WaitEnabled(`//select[@id='version']/option[text()='0.0.1']`),
			chromedp.WaitEnabled(`//select[@id='version']/option[text()='0.0.2']`),
			chromedp.WaitEnabled(`//select[@id='version']/option[text()='0.1.0']`),
			// should show vcs repo source
			matchRegex(t, `//span[@id='vcs-repo']`, `.*/terraform-aws-mod`),
		},
	})

	// Now we test the webhook functionality by sending an event to the daemon
	// (which would usually be triggered by a git push to github). The event
	// should trigger a module version to be published.

	// generate and send push tag event for v1.0.0
	pushTpl := testutils.ReadFile(t, "fixtures/github_push_tag.json")
	push := fmt.Sprintf(string(pushTpl), "v1.0.0", repo)
	svc.SendEvent(t, github.PushEvent, []byte(push))

	// v1.0.0 should appear as latest module on workspace
	page := browser.New(t, ctx)
		// go to module
		_, err = page.Goto(moduleURL)
require.NoError(t, err)
		//screenshot(t),
		reloadUntilVisible(`//select[@id="version"]/option[@selected]`),
		//screenshot(t),
	})

	// Now run terraform with some config that sources the module. First we need
	// a workspace...
	workspaceName := "module-test"
	browser.New(t, ctx, createWorkspace(t, svc.System.Hostname(), org.Name, workspaceName))

	// generate some terraform config that sources our module
	root := newRootModule(t, svc.System.Hostname(), org.Name, workspaceName)
	config := fmt.Sprintf(`
module "mod" {
  source  = "%s/%s/%s/%s"
  version = "1.0.0"
}
`, svc.System.Hostname(), org.Name, "mod", "aws")
	err := os.WriteFile(filepath.Join(root, "sourcing.tf"), []byte(config), 0o600)
	require.NoError(t, err)

	// run terraform init, plan, and apply
	svc.tfcli(t, ctx, "init", root)
	out := svc.tfcli(t, ctx, "plan", root)
	require.Contains(t, out, "Plan: 2 to add, 0 to change, 0 to destroy.")
	out = svc.tfcli(t, ctx, "apply", root, "-auto-approve")
	require.Contains(t, string(out), "Apply complete! Resources: 2 added, 0 changed, 0 destroyed.")

	// delete vcs provider and visit the module page; it should be no longer
	// connected. Then delete the module.
	_, err = svc.VCSProviders.Delete(ctx, provider.ID)
	require.NoError(t, err)
	page := browser.New(t, ctx)
		chromedp.Tasks{
			// go to org
			_, err = page.Goto(organizationURL(svc.System.Hostname(), org.Name))
require.NoError(t, err)
			//screenshot(t),
			// go to modules
			err := page.Locator("#modules > a").Click()
require.NoError(t, err)
			// select existing module
			err := page.Locator(`.widget`).Click()
require.NoError(t, err)
			// confirm no longer connected
			chromedp.WaitNotPresent(`//span[@id='vcs-repo']`),
			// delete module
			err := page.Locator(`//button[text()='Delete module']`).Click()
require.NoError(t, err)
			// flash message indicates success
			matchText(t, `//div[@role='alert']`, `deleted module: mod`),
		},
	})
}
