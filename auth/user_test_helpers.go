package auth

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/leg100/otf"
	"github.com/stretchr/testify/require"
)

func CreateTestUser(t *testing.T, db otf.DB, opts ...NewUserOption) *User {
	userDB := newDB(db, logr.Discard())
	return createTestUser(t, userDB, opts...)
}

func createTestUser(t *testing.T, db *pgdb, opts ...NewUserOption) *User {
	ctx := context.Background()

	user := NewUser(uuid.NewString(), opts...)
	err := db.CreateUser(ctx, user)
	require.NoError(t, err)

	t.Cleanup(func() {
		db.DeleteUser(ctx, UserSpec{UserID: &user.ID})
	})
	return user
}
