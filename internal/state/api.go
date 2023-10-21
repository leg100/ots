package state

import (
	"net/http"

	"github.com/gorilla/mux"
	otfapi "github.com/leg100/otf/internal/api"
	"github.com/leg100/otf/internal/http/decode"
	"github.com/leg100/otf/internal/resource"
	"github.com/leg100/otf/internal/tfeapi"
	"github.com/leg100/otf/internal/tfeapi/types"
)

type api struct {
	Service
	*tfeapi.Responder

	tfeapi *tfe
}

func (a *api) addHandlers(r *mux.Router) {
	r = r.PathPrefix(otfapi.DefaultBasePath).Subrouter()

	// proxy this endpoint to the tfeapi endpoint because the behaviour is
	// identical (although it returns a tfe struct the only user of this
	// endpoint, the agent, ignores the return value).
	r.HandleFunc("/workspaces/{workspace_id}/state-versions", a.tfeapi.createVersion).Methods("POST")

	r.HandleFunc("/workspaces/{workspace_id}/current-state-version", a.getCurrentVersion).Methods("GET")
	r.HandleFunc("/workspaces/{workspace_id}/state-versions", a.rollbackVersion).Methods("PATCH")
	r.HandleFunc("/workspaces/{workspace_id}/state-versions", a.listVersions).Methods("GET")

	r.HandleFunc("/state-versions/{id}/download", a.downloadState).Methods("GET")
	r.HandleFunc("/state-versions/{id}", a.deleteVersion).Methods("DELETE")
}

func (a *api) listVersions(w http.ResponseWriter, r *http.Request) {
	var params struct {
		WorkspaceID string `schema:"workspace_id,required"`
		resource.PageOptions
	}
	if err := decode.All(&params, r); err != nil {
		tfeapi.Error(w, err)
		return
	}
	page, err := a.ListStateVersions(r.Context(), params.WorkspaceID, params.PageOptions)
	if err != nil {
		tfeapi.Error(w, err)
		return
	}
	a.RespondWithPage(w, r, page.Items, page.Pagination)
}

func (a *api) getCurrentVersion(w http.ResponseWriter, r *http.Request) {
	workspaceID, err := decode.Param("workspace_id", r)
	if err != nil {
		tfeapi.Error(w, err)
		return
	}

	sv, err := a.GetCurrentStateVersion(r.Context(), workspaceID)
	if err != nil {
		tfeapi.Error(w, err)
		return
	}

	a.Respond(w, r, sv, http.StatusOK)
}

func (a *api) deleteVersion(w http.ResponseWriter, r *http.Request) {
	versionID, err := decode.Param("id", r)
	if err != nil {
		tfeapi.Error(w, err)
		return
	}
	if err := a.DeleteStateVersion(r.Context(), versionID); err != nil {
		tfeapi.Error(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) rollbackVersion(w http.ResponseWriter, r *http.Request) {
	opts := types.RollbackStateVersionOptions{}
	if err := tfeapi.Unmarshal(r.Body, &opts); err != nil {
		tfeapi.Error(w, err)
		return
	}

	sv, err := a.RollbackStateVersion(r.Context(), opts.RollbackStateVersion.ID)
	if err != nil {
		tfeapi.Error(w, err)
		return
	}

	a.Respond(w, r, sv, http.StatusOK)
}

func (a *api) downloadState(w http.ResponseWriter, r *http.Request) {
	versionID, err := decode.Param("id", r)
	if err != nil {
		tfeapi.Error(w, err)
		return
	}
	resp, err := a.DownloadState(r.Context(), versionID)
	if err != nil {
		tfeapi.Error(w, err)
		return
	}
	w.Write(resp)
}
