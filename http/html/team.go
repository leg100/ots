package html

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/leg100/otf"
)

// teamRequest provides metadata about a request for a workspace
type teamRequest struct {
	r *http.Request
}

func (w teamRequest) OrganizationName() string {
	return param(w.r, "organization_name")
}

func (w teamRequest) TeamName() string {
	return param(w.r, "team_name")
}

func (app *Application) listTeams(w http.ResponseWriter, r *http.Request) {
	teams, err := app.ListTeams(r.Context(), mux.Vars(r)["organization_name"])
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	app.render("team_list.tmpl", w, r, teams)
}

func (app *Application) listTeamUsers(w http.ResponseWriter, r *http.Request) {
	opts := otf.UserListOptions{
		OrganizationName: otf.String(mux.Vars(r)["organization_name"]),
		TeamName:         otf.String(mux.Vars(r)["team_name"]),
	}
	users, err := app.ListUsers(r.Context(), opts)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	app.render("team_users_list.tmpl", w, r, UserList{users, opts})
}
