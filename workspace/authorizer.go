package workspace

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/leg100/otf"
	"github.com/leg100/otf/rbac"
)

// authorizer authorizes access to a workspace
type authorizer struct {
	logr.Logger

	db *pgdb
}

func (a *authorizer) CanAccessWorkspaceByName(ctx context.Context, action rbac.Action, organization, workspace string) (otf.Subject, error) {
	ws, err := a.db.GetWorkspaceByName(ctx, organization, workspace)
	if err != nil {
		return nil, err
	}
	return a.CanAccessWorkspaceByID(ctx, action, ws.ID())
}

func (a *authorizer) CanAccessWorkspaceByID(ctx context.Context, action rbac.Action, workspaceID string) (otf.Subject, error) {
	subj, err := otf.SubjectFromContext(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := a.db.GetWorkspacePolicy(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	if subj.CanAccessWorkspace(action, policy) {
		return subj, nil
	}
	a.Error(nil, "unauthorized action", "workspace", workspaceID, "organization", policy.Organization, "action", action, "subject", subj)
	return nil, otf.ErrAccessNotPermitted
}
