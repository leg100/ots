package session

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/leg100/otf"
)

type Application struct {
	otf.Authorizer
	logr.Logger

	db DB
	*handlers
	*htmlApp
}

func NewApplication(opts ApplicationOptions) *Application {
	app := &Application{
		Authorizer: opts.Authorizer,
		db:         newPGDB(opts.Database),
		Logger:     opts.Logger,
	}
	app.handlers = &handlers{
		Application: app,
	}
	app.htmlApp = &htmlApp{
		app:      app,
		Renderer: opts.Renderer,
	}
	return app
}

type ApplicationOptions struct {
	otf.Authorizer
	otf.Database
	otf.Renderer
	logr.Logger
}


// CreateSession creates and persists a user session.
func (a *Application) CreateSession(ctx context.Context, userID, address string) (*otf.Session, error) {
	session, err := otf.NewSession(userID, address)
	if err != nil {
		a.Error(err, "building new session", "uid", userID)
		return nil, err
	}
	if err := a.db.CreateSession(ctx, session); err != nil {
		a.Error(err, "creating session", "uid", userID)
		return nil, err
	}

	a.V(1).Info("created session", "uid", userID)

	return session, nil
}

func (a *Application) GetSessionByToken(ctx context.Context, token string) (*otf.Session, error) {
	return a.db.GetSessionByToken(ctx, token)
}

func (a *Application) ListSessions(ctx context.Context, userID string) ([]*otf.Session, error) {
	return a.db.ListSessions(ctx, userID)
}

func (a *Application) DeleteSession(ctx context.Context, token string) error {
	if err := a.db.DeleteSession(ctx, token); err != nil {
		a.Error(err, "deleting session")
		return err
	}

	a.V(2).Info("deleted session")

	return nil
}
