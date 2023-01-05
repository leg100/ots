package e2e

import (
	"strings"
	"testing"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSiteAdmin demonstrates signing into the web app as a site admin, using
// their super powers to create an organization.
func TestSiteAdmin(t *testing.T) {
	addBuildsToPath(t)

	daemon := &daemon{}
	daemon.withFlags("--site-token", "abc123")
	hostname := daemon.start(t)

	org := uuid.NewString()

	ctx, cancel := chromedp.NewContext(allocator)
	defer cancel()

	var footerLoginText, loginConfirmation, orgCreated, orgLocation string

	err := chromedp.Run(ctx, chromedp.Tasks{
		// login as site admin
		chromedp.Navigate("https://" + hostname + "/login"),
		screenshot(t),
		// use the link in the bottom right corner
		chromedp.Text(".footer-site-login", &footerLoginText, chromedp.NodeVisible),
		chromedp.Click(".footer-site-login > a", chromedp.NodeVisible),
		screenshot(t),
		// enter token
		chromedp.Focus("input#token", chromedp.NodeVisible),
		input.InsertText("abc123"),
		screenshot(t),
		chromedp.Submit("input#token"),
		screenshot(t),
		chromedp.Text(".content > p", &loginConfirmation, chromedp.NodeVisible),
		// now go to the list of organizations
		chromedp.Navigate("https://" + hostname + "/organizations"),
		// add an org
		chromedp.Click("#new-organization-button", chromedp.NodeVisible),
		screenshot(t),
		chromedp.Focus("input#name", chromedp.NodeVisible),
		input.InsertText(org),
		screenshot(t),
		chromedp.Submit("input#name"),
		screenshot(t),
		chromedp.Location(&orgLocation),
		chromedp.Text(".flash-success", &orgCreated, chromedp.NodeVisible),
	})
	require.NoError(t, err)

	assert.Equal(t, "site admin", footerLoginText)
	assert.Equal(t, "You are logged in as site-admin", strings.TrimSpace(loginConfirmation))
	assert.Equal(t, "https://"+hostname+"/organizations/"+org, orgLocation)
	assert.Equal(t, "created organization: "+org, strings.TrimSpace(orgCreated))
}
