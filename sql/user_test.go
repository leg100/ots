package sql

import (
	"context"
	"testing"

	"github.com/leg100/otf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUser_Create(t *testing.T) {
	db := newTestDB(t)
	user := newTestUser()

	defer db.UserStore().Delete(context.Background(), otf.UserSpecifier{Username: &user.Username})

	err := db.UserStore().Create(context.Background(), user)
	require.NoError(t, err)
}

func TestUser_Get(t *testing.T) {
	db := newTestDB(t)
	user := createTestUser(t, db)
	//_ = createTestSession(t, db)

	got, err := db.UserStore().Get(context.Background(), otf.UserSpecifier{Username: &user.Username})
	require.NoError(t, err)

	assert.Equal(t, got, user)
}

func TestUser_Get_WithSessions(t *testing.T) {
	db := newTestDB(t)
	user := createTestUser(t, db)
	_ = createTestSession(t, db, user.ID)
	_ = createTestSession(t, db, user.ID)

	got, err := db.UserStore().Get(context.Background(), otf.UserSpecifier{Username: &user.Username})
	require.NoError(t, err)

	assert.Equal(t, 2, len(got.Sessions))
}

func TestUser_List(t *testing.T) {
	db := newTestDB(t)
	user1 := createTestUser(t, db)
	user2 := createTestUser(t, db)
	user3 := createTestUser(t, db)

	users, err := db.UserStore().List(context.Background())
	require.NoError(t, err)

	assert.Contains(t, users, user1)
	assert.Contains(t, users, user2)
	assert.Contains(t, users, user3)
}

func TestUser_Delete(t *testing.T) {
	db := newTestDB(t)
	user := createTestUser(t, db)

	err := db.UserStore().Delete(context.Background(), otf.UserSpecifier{Username: &user.Username})
	require.NoError(t, err)

	// Verify zero users after deletion
	users, err := db.UserStore().List(context.Background())
	require.NoError(t, err)
	assert.NotContains(t, users, user)
}

func TestUser_UpdateSession(t *testing.T) {
	db := newTestDB(t)
	user := createTestUser(t, db)
	session := createTestSession(t, db, user.ID)

	require.NotNil(t, session.Flash)

	session.PopFlash()

	err := db.UserStore().UpdateSession(context.Background(), session.Token, session)
	require.NoError(t, err)

	// Verify session's flash has popped
	user, err = db.UserStore().Get(context.Background(), otf.UserSpecifier{Token: &session.Token})
	require.NoError(t, err)
	assert.Nil(t, user.Sessions[0].Flash)
}
