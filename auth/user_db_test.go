package auth

import (
	"context"
	"testing"

	"github.com/leg100/otf"
	"github.com/leg100/otf/organization"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserDB(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	t.Run("get", func(t *testing.T) {
		org1 := organization.CreateTestOrganization(t, db)
		org2 := organization.CreateTestOrganization(t, db)
		team1 := createTestTeam(t, db, org1.Name)
		team2 := createTestTeam(t, db, org2.Name)

		user := createTestUser(t, db,
			WithOrganizations(org1.Name, org2.Name),
			WithTeams(team1, team2))

		session1 := createTestSession(t, db, user.ID, nil)
		_ = createTestSession(t, db, user.ID, nil)

		token1 := createTestToken(t, db, user.ID, "testing")
		_ = createTestToken(t, db, user.ID, "testing")

		tests := []struct {
			name string
			spec UserSpec
		}{
			{
				name: "id",
				spec: UserSpec{UserID: otf.String(user.ID)},
			},
			{
				name: "username",
				spec: UserSpec{Username: otf.String(user.Username)},
			},
			{
				name: "session token",
				spec: UserSpec{SessionToken: otf.String(session1.Token())},
			},
			{
				name: "auth token",
				spec: UserSpec{AuthenticationToken: otf.String(token1.Token)},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := db.getUser(ctx, tt.spec)
				require.NoError(t, err)

				assert.Equal(t, got.ID, user.ID)
				assert.Equal(t, got.Username, user.Username)
				assert.Equal(t, got.CreatedAt, user.CreatedAt)
				assert.Equal(t, got.UpdatedAt, user.UpdatedAt)
				assert.Equal(t, 2, len(got.Organizations))
				assert.Equal(t, 2, len(got.Teams))
			})
		}
	})

	t.Run("get not found error", func(t *testing.T) {
		_, err := db.getUser(ctx, UserSpec{Username: otf.String("does-not-exist")})
		assert.Equal(t, otf.ErrResourceNotFound, err)
	})

	t.Run("list", func(t *testing.T) {
		org := organization.CreateTestOrganization(t, db)
		user1 := createTestUser(t, db)
		user2 := createTestUser(t, db, WithOrganizations(org.Name))
		user3 := createTestUser(t, db, WithOrganizations(org.Name))

		users, err := db.listUsers(ctx, org.Name)
		require.NoError(t, err)

		assert.NotContains(t, users, user1)
		assert.Contains(t, users, user2)
		assert.Contains(t, users, user3)
	})

	t.Run("delete", func(t *testing.T) {
		user := createTestUser(t, db)

		spec := UserSpec{Username: otf.String(user.Username)}
		err := db.DeleteUser(ctx, spec)
		require.NoError(t, err)

		_, err = db.getUser(ctx, spec)
		assert.Equal(t, err, otf.ErrResourceNotFound)
	})

	t.Run("add organization membership", func(t *testing.T) {
		org := organization.CreateTestOrganization(t, db)
		user := createTestUser(t, db, WithOrganizations(org.Name))

		err := db.addOrganizationMembership(ctx, user.ID, org.Name)
		require.NoError(t, err)

		got, err := db.getUser(ctx, UserSpec{Username: otf.String(user.Username)})
		require.NoError(t, err)

		assert.Contains(t, got.Organizations, org.Name)
	})

	t.Run("remove organization membership", func(t *testing.T) {
		org := organization.CreateTestOrganization(t, db)
		user := createTestUser(t, db, WithOrganizations(org.Name))

		err := db.removeOrganizationMembership(ctx, user.ID, org.Name)
		require.NoError(t, err)

		got, err := db.getUser(ctx, UserSpec{Username: otf.String(user.Username)})
		require.NoError(t, err)

		assert.NotContains(t, got.Organizations, org.Name)
	})

	t.Run("add team membership", func(t *testing.T) {
		org := organization.CreateTestOrganization(t, db)
		team := createTestTeam(t, db, org.Name)
		user := createTestUser(t, db, WithOrganizations(org.Name))

		err := db.addTeamMembership(ctx, user.ID, team.ID)
		require.NoError(t, err)

		got, err := db.getUser(ctx, UserSpec{Username: otf.String(user.Username)})
		require.NoError(t, err)

		assert.Contains(t, got.Teams, team)
	})

	t.Run("remove team membership", func(t *testing.T) {
		org := organization.CreateTestOrganization(t, db)
		team := createTestTeam(t, db, org.Name)
		user := createTestUser(t, db, WithOrganizations(org.Name), WithTeams(team))

		err := db.removeTeamMembership(ctx, user.ID, team.ID)
		require.NoError(t, err)

		got, err := db.getUser(ctx, UserSpec{Username: otf.String(user.Username)})
		require.NoError(t, err)

		assert.NotContains(t, got.Teams, team)
	})
}
