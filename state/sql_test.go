package state

import (
	"context"
	"testing"

	"github.com/leg100/otf"
	"github.com/leg100/otf/sql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStateVersion_Create(t *testing.T) {
	ctx := context.Background()
	db := sql.NewTestDB(t)
	stateDB := &pgdb{db}
	org := sql.CreateTestOrganization(t, db)
	ws := sql.CreateTestWorkspace(t, db, org)

	sv := newTestVersion(t, ws,
		StateOutput{"out1", "string", "val1", false},
		StateOutput{"out2", "string", "val2", false},
	)

	err := stateDB.createVersion(ctx, sv)
	require.NoError(t, err)
}

func TestStateVersion_Get(t *testing.T) {
	ctx := context.Background()
	db := sql.NewTestDB(t)
	stateDB := &pgdb{db}
	org := sql.CreateTestOrganization(t, db)
	ws := sql.CreateTestWorkspace(t, db, org)
	sv := createTestStateVersion(t, stateDB, ws,
		StateOutput{"out1", "string", "val1", false},
	)

	tests := []struct {
		name string
		opts otf.StateVersionGetOptions
		want func(t *testing.T, got *Version, err error)
	}{
		{
			name: "by id",
			opts: otf.StateVersionGetOptions{ID: otf.String(sv.ID())},
			want: func(t *testing.T, got *Version, err error) {
				if assert.NoError(t, err) {
					assert.Equal(t, sv, got)
				}
			},
		},
		{
			name: "by id - missing",
			opts: otf.StateVersionGetOptions{ID: otf.String("sv-does-not-exist")},
			want: func(t *testing.T, got *Version, err error) {
				assert.Equal(t, otf.ErrResourceNotFound, err)
			},
		},
		{
			name: "by workspace",
			opts: otf.StateVersionGetOptions{WorkspaceID: otf.String(ws.ID())},
			want: func(t *testing.T, got *Version, err error) {
				if assert.NoError(t, err) {
					assert.Equal(t, sv, got)
				}
			},
		},
		{
			name: "by workspace - missing",
			opts: otf.StateVersionGetOptions{WorkspaceID: otf.String("ws-does-not-exist")},
			want: func(t *testing.T, got *Version, err error) {
				assert.Equal(t, otf.ErrResourceNotFound, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := stateDB.getVersion(ctx, tt.opts)
			tt.want(t, got, err)
		})
	}
}

func TestStateVersion_List(t *testing.T) {
	ctx := context.Background()
	db := sql.NewTestDB(t)
	stateDB := &pgdb{db}
	org := sql.CreateTestOrganization(t, db)
	ws := sql.CreateTestWorkspace(t, db, org)

	sv1 := createTestStateVersion(t, stateDB, ws)
	sv2 := createTestStateVersion(t, stateDB, ws)

	tests := []struct {
		name string
		opts otf.StateVersionListOptions
		want func(*testing.T, *VersionList, ...*Version)
	}{
		{
			name: "filter by workspace",
			opts: otf.StateVersionListOptions{Workspace: ws.Name(), Organization: org.Name()},
			want: func(t *testing.T, l *VersionList, created ...*Version) {
				assert.Equal(t, 2, len(l.Items))
				for _, c := range created {
					assert.Contains(t, l.Items, c)
				}
			},
		},
		{
			name: "filter by non-existent workspace",
			opts: otf.StateVersionListOptions{Workspace: "non-existent", Organization: "non-existent"},
			want: func(t *testing.T, l *VersionList, created ...*Version) {
				assert.Equal(t, 0, len(l.Items))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := stateDB.listVersions(ctx, tt.opts)
			require.NoError(t, err)

			tt.want(t, results, sv1, sv2)
		})
	}
}

func createTestStateVersion(t *testing.T, stateDB *pgdb, ws *otf.Workspace, outputs ...StateOutput) *Version {
	ctx := context.Background()
	sv := newTestVersion(t, ws, outputs...)
	err := stateDB.createVersion(ctx, sv)
	require.NoError(t, err)
	t.Cleanup(func() {
		stateDB.deleteVersion(ctx, sv.ID())
	})
	return sv
}
