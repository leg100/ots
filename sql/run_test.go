package sql

import (
	"testing"

	"github.com/leg100/otf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRun_Create(t *testing.T) {
	db := newTestDB(t)
	org := createTestOrganization(t, db)
	ws := createTestWorkspace(t, db, org)
	cv := createTestConfigurationVersion(t, db, ws)

	_, err := db.RunStore().Create(newTestRun(ws, cv))
	require.NoError(t, err)
}

func TestRun_Get(t *testing.T) {
	db := newTestDB(t)
	org := createTestOrganization(t, db)
	ws := createTestWorkspace(t, db, org)
	cv := createTestConfigurationVersion(t, db, ws)

	want := createTestRun(t, db, ws, cv)
	want.Workspace.Organization = nil
	want.ConfigurationVersion.StatusTimestamps = nil

	tests := []struct {
		name string
		opts otf.RunGetOptions
	}{
		{
			name: "by id",
			opts: otf.RunGetOptions{ID: &want.ID},
		},
		{
			name: "by plan id",
			opts: otf.RunGetOptions{PlanID: &want.Plan.ID},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.RunStore().Get(tt.opts)
			require.NoError(t, err)

			assert.Equal(t, want, got)
		})
	}
}
