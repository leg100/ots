package e2e

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	gogithub "github.com/google/go-github/v41/github"
	"github.com/leg100/otf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConnectRepo tests VCS integration, creating a VCS provider and connecting
// a workspace to a VCS repo.
func TestConnectRepo(t *testing.T) {
	addBuildsToPath(t)

	user := otf.NewTestUser(t)
	repo := otf.NewTestRepo()
	org := user.Username() // we'll be using user's personal organization
	tarball, err := os.ReadFile("../testdata/github.tar.gz")
	require.NoError(t, err)

	// create an otf daemon with a fake github backend, ready to sign in a user,
	// serve up a repo and its contents via tarball. And register a callback to
	// test receipt of commit statuses
	daemon := &daemon{}
	daemon.withGithubUser(user)
	daemon.withGithubRepo(repo)
	daemon.withGithubTarball(tarball)

	statuses := make(chan *gogithub.StatusEvent, 10)
	daemon.registerStatusCallback(func(status *gogithub.StatusEvent) {
		statuses <- status
	})

	hostname := daemon.start(t)
	url := "https://" + hostname
	workspaceName := "workspace-connect"

	// create browser
	ctx, cancel := chromedp.NewContext(allocator)
	defer cancel()

	// create timeout
	ctx, cancel = context.WithTimeout(ctx, time.Minute)
	defer cancel()

	err = chromedp.Run(ctx, chromedp.Tasks{
		// login
		githubLoginTasks(t, hostname, user.Username()),
		// create github vcs provider
		chromedp.Tasks{
			// go to org
			chromedp.Navigate(path.Join(url, "organizations", org)),
			// go to vcs providers
			chromedp.Click("#vcs_providers > a", chromedp.NodeVisible),
			screenshot(t),
			// click 'New Github VCS Provider' button
			chromedp.Click(`//button[text()='New Github VCS Provider']`, chromedp.NodeVisible),
			screenshot(t),
			// enter fake github token and name
			chromedp.Focus("input#token", chromedp.NodeVisible),
			input.InsertText("fake-github-personal-token"),
			chromedp.Focus("input#name"),
			input.InsertText("github"),
			screenshot(t),
			// submit form to create provider
			chromedp.Submit("input#token"),
			screenshot(t),
			chromedp.ActionFunc(func(ctx context.Context) error {
				var got string
				err := chromedp.Run(ctx, chromedp.Text(".flash-success", &got, chromedp.NodeVisible))
				if err != nil {
					return err
				}
				require.Equal(t, "created provider: github", strings.TrimSpace(got))
				return nil
			}),
		},
		// create workspace via UI
		createWorkspaceTasks(t, hostname, org, workspaceName),
		// connect workspace to vcs repo
		chromedp.Tasks{
			// go to workspace
			chromedp.Navigate(path.Join(url, "organizations", org, "workspaces", workspaceName)),
			screenshot(t),
			// navigate to workspace settings
			chromedp.Click(`//a[text()='settings']`, chromedp.NodeVisible),
			screenshot(t),
			// click connect button
			chromedp.Click(`//button[text()='Connect to VCS']`, chromedp.NodeVisible),
			screenshot(t),
			// select provider
			chromedp.Click(`//a[normalize-space(text())='github']`, chromedp.NodeVisible),
			screenshot(t),
			// connect to first repo in list (there should only be one)
			chromedp.Click(`//div[@class='content-list']//button[text()='connect']`, chromedp.NodeVisible),
			screenshot(t),
			// confirm connected
			// capture flash message confirming workspace has been connected
			chromedp.ActionFunc(func(ctx context.Context) error {
				var got string
				err := chromedp.Run(ctx, chromedp.Text(".flash-success", &got, chromedp.NodeVisible))
				if err != nil {
					return err
				}
				require.Equal(t, "connected workspace to repo", strings.TrimSpace(got))
				return nil
			}),
		},
		// we can now start a run via the web ui, which'll retrieve the tarball from
		// the fake github server
		startRunTasks(t, hostname, org, workspaceName),
	})
	require.NoError(t, err)

	// Now we test the webhook functionality by sending an event to the daemon
	// (which would usually be triggered by a git push to github). The event
	// should trigger a run on the workspace.

	// otfd should have registered a webhook with the github server
	require.NotNil(t, daemon.githubServer.WebhookURL)
	require.NotNil(t, daemon.githubServer.WebhookSecret)

	// generate push event using template
	pushTpl, err := os.ReadFile("fixtures/github_push.json")
	require.NoError(t, err)
	push := fmt.Sprintf(string(pushTpl), repo.Identifier)

	// generate signature for push event
	mac := hmac.New(sha256.New, []byte(*daemon.githubServer.WebhookSecret))
	mac.Write([]byte(push))
	sig := mac.Sum(nil)

	req, err := http.NewRequest("POST", *daemon.githubServer.WebhookURL, strings.NewReader(push))
	require.NoError(t, err)
	req.Header.Add("Content-type", "application/json")
	req.Header.Add("X-GitHub-Event", "push")
	req.Header.Add("X-Hub-Signature-256", "sha256="+hex.EncodeToString(sig))

	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	if !assert.Equal(t, http.StatusAccepted, res.StatusCode) {
		response, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		t.Fatal(string(response))
	}

	// commit-triggered run should appear as latest run on workspace
	err = chromedp.Run(ctx, chromedp.Tasks{
		// go to workspace
		chromedp.Navigate(fmt.Sprintf("%s/organizations/%s/workspaces/%s", url, org, workspaceName)),
		screenshot(t),
		// commit should match that of push event
		chromedp.WaitVisible(`//div[@id='latest-run']//span[@class='commit' and text()='#42d6fc7']`),
		screenshot(t),
	})
	require.NoError(t, err)

	// check github received commit statuses
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case status := <-statuses:
		require.Equal(t, "pending", *status.State)
	}

	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case status := <-statuses:
		require.Equal(t, "pending", *status.State)
	}

	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case status := <-statuses:
		require.Equal(t, "pending", *status.State)
	}

	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case status := <-statuses:
		require.Equal(t, "success", *status.State)
		require.Equal(t, "no changes", *status.Description)
	}
}
