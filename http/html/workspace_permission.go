package html

import (
	"net/http"

	"github.com/leg100/otf/http/decode"
	"github.com/leg100/otf/http/html/paths"
	"github.com/leg100/otf/rbac"
)

func (app *Application) setWorkspacePermission(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		WorkspaceID string `schema:"workspace_id,required"`
		TeamName    string `schema:"team_name,required"`
		Role        string `schema:"role,required"`
	}
	params := parameters{}
	if err := decode.All(&params, r); err != nil {
		Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	role, err := rbac.WorkspaceRoleFromString(params.Role)
	if err != nil {
		Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ws, err := app.GetWorkspace(r.Context(), params.WorkspaceID)
	if err != nil {
		Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = app.SetWorkspacePermission(r.Context(), params.WorkspaceID, params.TeamName, role)
	if err != nil {
		Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	FlashSuccess(w, "updated workspace permissions")
	http.Redirect(w, r, paths.EditWorkspace(ws.ID()), http.StatusFound)
}

func (app *Application) unsetWorkspacePermission(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		WorkspaceID string `schema:"workspace_id,required"`
		TeamName    string `schema:"team_name,required"`
	}
	var params parameters
	if err := decode.All(&params, r); err != nil {
		Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	ws, err := app.GetWorkspace(r.Context(), params.WorkspaceID)
	if err != nil {
		Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = app.UnsetWorkspacePermission(r.Context(), params.WorkspaceID, params.TeamName)
	if err != nil {
		Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	FlashSuccess(w, "deleted workspace permission")
	http.Redirect(w, r, paths.EditWorkspace(ws.ID()), http.StatusFound)
}
