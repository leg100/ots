package authz

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/leg100/otf/internal"
	"github.com/leg100/otf/internal/rbac"
	"github.com/leg100/otf/internal/resource"
)

// Authorizer is capable of granting or denying access to resources based on the
// subject contained within the context.
type Authorizer interface {
	CanAccess(ctx context.Context, action rbac.Action, id resource.ID) (Subject, error)
}

type Authorizer2 struct {
	logr.Logger
}

func (a *Authorizer2) CanAccess(ctx context.Context, action rbac.Action, _ resource.ID) (Subject, error) {
	subj, err := SubjectFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if subj.CanAccessSite(action) {
		return subj, nil
	}
	a.Error(nil, "unauthorized action", "action", action, "subject", subj)
	return nil, internal.ErrAccessNotPermitted
}
