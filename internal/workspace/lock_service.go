package workspace

import (
	"context"
	"fmt"

	"github.com/leg100/otf/internal/rbac"
	"github.com/leg100/otf/internal/resource"
	"github.com/leg100/otf/internal/user"
)

// Lock locks the workspace. A workspace can only be locked on behalf of a run or a
// user. If the former then runID must be populated. Otherwise a user is
// extracted from the context.
func (s *Service) Lock(ctx context.Context, workspaceID resource.ID, runID *resource.ID) (*Workspace, error) {
	var id resource.ID
	if runID != nil {
		id = *runID
	} else {
		subject, err := s.CanAccess(ctx, rbac.LockWorkspaceAction, workspaceID)
		if err != nil {
			return nil, err
		}
		user, ok := subject.(*user.User)
		if !ok {
			return nil, fmt.Errorf("only a run or a user can lock a workspace")
		}
		id = user.ID
	}
	ws, err := s.db.toggleLock(ctx, workspaceID, func(ws *Workspace) error {
		return ws.Enlock(id)
	})
	if err != nil {
		s.Error(err, "locking workspace", "subject", id, "workspace", workspaceID)
		return nil, err
	}
	s.V(1).Info("locked workspace", "subject", id, "workspace", workspaceID)

	return ws, nil
}

// Unlock unlocks the workspace. A workspace can only be unlocked on behalf of a run or
// a user. If the former then runID must be non-nil; otherwise a user is
// extracted from the context.
func (s *Service) Unlock(ctx context.Context, workspaceID resource.ID, runID *resource.ID, force bool) (*Workspace, error) {
	var id resource.ID
	if runID != nil {
		id = *runID
	} else {
		var action rbac.Action
		if force {
			action = rbac.ForceUnlockWorkspaceAction
		} else {
			action = rbac.UnlockWorkspaceAction
		}
		subject, err := s.CanAccess(ctx, action, workspaceID)
		if err != nil {
			return nil, err
		}
		user, ok := subject.(*user.User)
		if !ok {
			return nil, fmt.Errorf("only a run or a user can unlock a workspace")
		}
		id = user.ID
	}

	ws, err := s.db.toggleLock(ctx, workspaceID, func(ws *Workspace) error {
		return ws.Unlock(id, force)
	})
	if err != nil {
		s.Error(err, "unlocking workspace", "subject", id, "workspace", workspaceID, "forced", force)
		return nil, err
	}
	s.V(1).Info("unlocked workspace", "subject", id, "workspace", workspaceID, "forced", force)

	return ws, nil
}
