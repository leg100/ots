package configversion

import (
	"bytes"
	"context"
	"fmt"
	"net/url"

	"github.com/leg100/otf/internal"
)

type Client struct {
	internal.JSONAPIClient

	// Client does not implement all of service yet
	Service
}

// DownloadConfig downloads a configuration version tarball.  Only configuration versions in the uploaded state may be downloaded.
func (c *Client) DownloadConfig(ctx context.Context, cvID string) ([]byte, error) {
	u := fmt.Sprintf("configuration-versions/%s/download", url.QueryEscape(cvID))
	req, err := c.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := c.Do(ctx, req, &buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
