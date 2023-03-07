package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func createTestSession(t *testing.T, db *pgdb, userID string, expiry *time.Time) *Session {
	ctx := context.Background()

	session := newTestSession(t, userID, expiry)
	err := db.createSession(ctx, session)
	require.NoError(t, err)

	t.Cleanup(func() {
		db.deleteSession(ctx, session.Token())
	})
	return session
}

func newTestSession(t *testing.T, userID string, expiry *time.Time) *Session {
	r := httptest.NewRequest("", "/", nil)
	session, err := newSession(r, userID)
	require.NoError(t, err)
	if expiry != nil {
		session.expiry = *expiry
	}

	return session
}

type fakeSessionService struct {
	sessions []*Session

	sessionService
}

func (f *fakeSessionService) ListSessions(context.Context, string) ([]*Session, error) {
	return f.sessions, nil
}

func (f *fakeSessionService) DeleteSession(context.Context, string) error {
	return nil
}

func (f *fakeSessionService) createSession(*http.Request, string) (*Session, error) {
	return &Session{}, nil
}