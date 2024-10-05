package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetOutboundIP(t *testing.T) {
	got, err := GetOutboundIP()
	require.NoError(t, err)
	assert.Regexp(t, `\d+\.\d+\.\d+\.\d+`, got.String())
}
