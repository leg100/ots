package repo

import (
	"context"
	"testing"

	"github.com/leg100/otf"
	"github.com/leg100/otf/sql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDB(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	provider := createVCSProvider(t)

	t.Run("create hook", func(t *testing.T) {
		want := newTestHook(t, db.factory, otf.String("123"))

		got, err := db.getOrCreateHook(ctx, want)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("update hook cloud ID", func(t *testing.T) {
		hook := newTestHook(t, db.factory, nil)
		want, err := db.getOrCreateHook(ctx, hook)
		require.NoError(t, err)

		err = db.updateHookCloudID(ctx, hook.id, "123")
		require.NoError(t, err)

		got, err := db.getHookByID(ctx, want.id)
		require.NoError(t, err)
		assert.Equal(t, "123", *got.cloudID)
	})

	t.Run("get hook", func(t *testing.T) {
		hook := newTestHook(t, db.factory, otf.String("123"))
		want, err := db.getOrCreateHook(ctx, hook)
		require.NoError(t, err)

		got, err := db.getHookByID(ctx, want.id)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("delete hook", func(t *testing.T) {
		hook := newTestHook(t, db.factory, otf.String("123"))
		_, err := db.getOrCreateHook(ctx, hook)
		require.NoError(t, err)

		_, err = db.deleteHook(ctx, hook.id)
		require.NoError(t, err)
	})

	t.Run("create workspace connection", func(t *testing.T) {
		ws := createTestWorkspace(t)
		hook := createTestHook(t, db, nil)

		err := db.createConnection(ctx, hook.id, otf.ConnectOptions{
			ConnectionType: otf.WorkspaceConnection,
			VCSProviderID:  provider.ID,
			ResourceID:     ws.ID,
			RepoPath:       hook.identifier,
		})
		assert.NoError(t, err)
	})

	t.Run("create module connection", func(t *testing.T) {
		module := createTestModule(t)
		hook := createTestHook(t, db, nil)

		err := db.createConnection(ctx, hook.id, otf.ConnectOptions{
			ConnectionType: otf.ModuleConnection,
			VCSProviderID:  provider.ID,
			ResourceID:     module.ID,
			RepoPath:       hook.identifier,
		})
		assert.NoError(t, err)
	})

	t.Run("delete workspace connection", func(t *testing.T) {
		ws := createTestWorkspace(t)
		hook := createTestHook(t, db, nil)
		_ = createTestConnection(t, db, provider, hook, otf.WorkspaceConnection, ws.ID)

		gotHookID, gotProviderID, err := db.deleteConnection(ctx, otf.DisconnectOptions{
			ConnectionType: otf.WorkspaceConnection,
			ResourceID:     ws.ID,
		})
		assert.NoError(t, err)
		assert.Equal(t, hook.id, gotHookID)
		assert.Equal(t, provider.ID, gotProviderID)
	})

	t.Run("delete module connection", func(t *testing.T) {
		module := createTestModule(t)
		hook := createTestHook(t, db, nil)
		_ = createTestConnection(t, db, provider, hook, otf.ModuleConnection, module.ID)

		gotHookID, gotProviderID, err := db.deleteConnection(ctx, otf.DisconnectOptions{
			ConnectionType: otf.ModuleConnection,
			ResourceID:     module.ID,
		})
		assert.NoError(t, err)
		assert.Equal(t, hook.id, gotHookID)
		assert.Equal(t, provider.ID, gotProviderID)
	})

	t.Run("count connections", func(t *testing.T) {
		ws1 := createTestWorkspace(t)
		ws2 := createTestWorkspace(t)
		module1 := createTestModule(t)

		hook := createTestHook(t, db, nil)
		_ = createTestConnection(t, db, provider, hook, otf.WorkspaceConnection, ws1.ID)
		_ = createTestConnection(t, db, provider, hook, otf.WorkspaceConnection, ws2.ID)
		_ = createTestConnection(t, db, provider, hook, otf.ModuleConnection, module1.ID)

		got, err := db.countConnections(ctx, hook.id)
		require.NoError(t, err)
		assert.Equal(t, 3, *got)
	})
}

func newTestDB(t *testing.T) *pgdb {
	return &pgdb{
		DB: sql.NewTestDB(t),
		factory: factory{
			Service:         fakeCloudService{},
			HostnameService: fakeHostnameService{},
		},
	}
}

func createTestHook(t *testing.T, db *pgdb, cloudID *string) *hook {
	ctx := context.Background()
	hook := newTestHook(t, db.factory, cloudID)

	_, err := db.getOrCreateHook(ctx, hook)
	require.NoError(t, err)

	t.Cleanup(func() {
		db.deleteHook(ctx, hook.id)
	})
	return hook
}

func createTestConnection(t *testing.T, db *pgdb, provider *otf.VCSProvider, hook *hook, connType otf.ConnectionType, resourceID string) *otf.Connection {
	ctx := context.Background()

	err := db.createConnection(ctx, hook.id, otf.ConnectOptions{
		ConnectionType: connType,
		VCSProviderID:  provider.ID,
		ResourceID:     resourceID,
		RepoPath:       hook.identifier,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		db.deleteConnection(ctx, otf.DisconnectOptions{
			ConnectionType: connType,
			ResourceID:     resourceID,
		})
	})
	return &otf.Connection{
		VCSProviderID: provider.ID,
		Repo:          hook.id,
	}
}

func createTestModule(t *testing.T) *otf.Module {
	db := sql.NewTestDB(t)
	org := sql.CreateTestOrganization(t, db)
	return sql.CreateTestModule(t, db, org)
}
