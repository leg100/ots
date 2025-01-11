package variable

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/gorilla/mux"
	"github.com/leg100/otf/internal/authz"
	"github.com/leg100/otf/internal/http/decode"
	"github.com/leg100/otf/internal/http/html"
	"github.com/leg100/otf/internal/http/html/paths"
	"github.com/leg100/otf/internal/organization"
	"github.com/leg100/otf/internal/resource"
	"github.com/leg100/otf/internal/workspace"
)

type (
	web struct {
		html.Renderer
		workspaces webWorkspaceClient

		variables  webVariablesClient
		authorizer webAuthorizer
	}

	// webVariablesClient provides web handlers with access to variables
	webVariablesClient interface {
		CreateWorkspaceVariable(ctx context.Context, workspaceID resource.ID, opts CreateVariableOptions) (*Variable, error)
		GetWorkspaceVariable(ctx context.Context, variableID resource.ID) (*WorkspaceVariable, error)
		ListWorkspaceVariables(ctx context.Context, workspaceID resource.ID) ([]*Variable, error)
		listWorkspaceVariableSets(ctx context.Context, workspaceID resource.ID) ([]*VariableSet, error)
		UpdateWorkspaceVariable(ctx context.Context, variableID resource.ID, opts UpdateVariableOptions) (*WorkspaceVariable, error)
		DeleteWorkspaceVariable(ctx context.Context, variableID resource.ID) (*WorkspaceVariable, error)

		createVariableSet(ctx context.Context, organization string, opts CreateVariableSetOptions) (*VariableSet, error)
		updateVariableSet(ctx context.Context, setID resource.ID, opts UpdateVariableSetOptions) (*VariableSet, error)
		getVariableSet(ctx context.Context, setID resource.ID) (*VariableSet, error)
		getVariableSetByVariableID(ctx context.Context, variableID resource.ID) (*VariableSet, error)
		listVariableSets(ctx context.Context, organization string) ([]*VariableSet, error)
		deleteVariableSet(ctx context.Context, setID resource.ID) (*VariableSet, error)
		createVariableSetVariable(ctx context.Context, setID resource.ID, opts CreateVariableOptions) (*Variable, error)
		updateVariableSetVariable(ctx context.Context, variableID resource.ID, opts UpdateVariableOptions) (*VariableSet, error)
		deleteVariableSetVariable(ctx context.Context, variableID resource.ID) (*VariableSet, error)
	}

	// webWorkspaceClient provides web handlers with access to workspaces
	webWorkspaceClient interface {
		Get(ctx context.Context, workspaceID resource.ID) (*workspace.Workspace, error)
		List(ctx context.Context, opts workspace.ListOptions) (*resource.Page[*workspace.Workspace], error)
		GetWorkspacePolicy(ctx context.Context, workspaceID resource.ID) (authz.WorkspacePolicy, error)
	}

	webAuthorizer interface {
		CanAccess(context.Context, authz.Action, *authz.AccessRequest) bool
	}

	workspaceInfo struct {
		ID   resource.ID `json:"id"`
		Name string      `json:"name"`
	}

	createVariableParams struct {
		Key         *string `schema:"key,required"`
		Value       *string
		Description *string
		Category    *VariableCategory `schema:"category,required"`
		Sensitive   bool
		HCL         bool
	}

	updateVariableParams struct {
		Key         *string
		Value       *string
		Description *string
		Category    *VariableCategory
		Sensitive   *bool
		HCL         bool
		VariableID  resource.ID `schema:"variable_id,required"`
	}

	// Create variable type specifically for templates
	variable struct {
		*Variable
		*VariableSet // nil if workspace var

		Overridden              bool
		CanUpdate               bool
		CanDelete               bool
		EditPath                string
		DeletePath              string
		WorkspaceVariablesTable bool
	}
)

func (h *web) addHandlers(r *mux.Router) {
	r = html.UIRouter(r)

	r.HandleFunc("/workspaces/{workspace_id}/variables", h.listWorkspaceVariables).Methods("GET")
	r.HandleFunc("/workspaces/{workspace_id}/variables/new", h.newWorkspaceVariable).Methods("GET")
	r.HandleFunc("/workspaces/{workspace_id}/variables/create", h.createWorkspaceVariable).Methods("POST")
	r.HandleFunc("/variables/{variable_id}/edit", h.editWorkspaceVariable).Methods("GET")
	r.HandleFunc("/variables/{variable_id}/update", h.updateWorkspaceVariable).Methods("POST")
	r.HandleFunc("/variables/{variable_id}/delete", h.deleteWorkspaceVariable).Methods("POST")

	r.HandleFunc("/organizations/{organization_name}/variable-sets", h.listVariableSets).Methods("GET")
	r.HandleFunc("/organizations/{organization_name}/variable-sets/new", h.newVariableSet).Methods("GET")
	r.HandleFunc("/organizations/{organization_name}/variable-sets/create", h.createVariableSet).Methods("POST")
	r.HandleFunc("/variable-sets/{variable_set_id}/edit", h.editVariableSet).Methods("GET")
	r.HandleFunc("/variable-sets/{variable_set_id}/update", h.updateVariableSet).Methods("POST")
	r.HandleFunc("/variable-sets/{variable_set_id}/delete", h.deleteVariableSet).Methods("POST")

	r.HandleFunc("/variable-sets/{variable_set_id}/variable-set-variables/new", h.newVariableSetVariable).Methods("GET")
	r.HandleFunc("/variable-sets/{variable_set_id}/variable-set-variables/create", h.createVariableSetVariable).Methods("POST")
	r.HandleFunc("/variable-set-variables/{variable_id}/edit", h.editVariableSetVariable).Methods("GET")
	r.HandleFunc("/variable-set-variables/{variable_id}/update", h.updateVariableSetVariable).Methods("POST")
	r.HandleFunc("/variable-set-variables/{variable_id}/delete", h.deleteVariableSetVariable).Methods("POST")
}

func (h *web) newWorkspaceVariable(w http.ResponseWriter, r *http.Request) {
	workspaceID, err := decode.ID("workspace_id", r)
	if err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	ws, err := h.workspaces.Get(r.Context(), workspaceID)
	if err != nil {
		h.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.Render("variable_new.tmpl", w, struct {
		workspace.WorkspacePage
		Variable   *Variable
		EditMode   bool
		FormAction string
	}{
		WorkspacePage: workspace.NewPage(r, "new variable", ws),
		Variable:      &Variable{},
		EditMode:      false,
		FormAction:    paths.CreateVariable(workspaceID.String()),
	})
}

func (h *web) createWorkspaceVariable(w http.ResponseWriter, r *http.Request) {
	var params struct {
		createVariableParams
		WorkspaceID resource.ID `schema:"workspace_id,required"`
	}
	if err := decode.All(&params, r); err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	variable, err := h.variables.CreateWorkspaceVariable(r.Context(), params.WorkspaceID, CreateVariableOptions{
		Key:         params.Key,
		Value:       params.Value,
		Description: params.Description,
		Category:    params.Category,
		Sensitive:   &params.Sensitive,
		HCL:         &params.HCL,
	})
	if err != nil {
		html.FlashError(w, err.Error())
		http.Redirect(w, r, paths.NewVariable(params.WorkspaceID.String()), http.StatusFound)
		return
	}

	html.FlashSuccess(w, "added variable: "+variable.Key)
	http.Redirect(w, r, paths.Variables(params.WorkspaceID.String()), http.StatusFound)
}

func (h *web) listWorkspaceVariables(w http.ResponseWriter, r *http.Request) {
	var params struct {
		WorkspaceID resource.ID `schema:"workspace_id,required"`
		resource.PageOptions
	}
	if err := decode.All(&params, r); err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	ws, err := h.workspaces.Get(r.Context(), params.WorkspaceID)
	if err != nil {
		h.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	workspaceVariables, err := h.variables.ListWorkspaceVariables(r.Context(), params.WorkspaceID)
	if err != nil {
		h.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sets, err := h.variables.listWorkspaceVariableSets(r.Context(), params.WorkspaceID)
	if err != nil {
		h.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	canUpdateVariable := h.authorizer.CanAccess(r.Context(), authz.UpdateWorkspaceVariableAction, &authz.AccessRequest{ID: &ws.ID})
	canDeleteVariable := h.authorizer.CanAccess(r.Context(), authz.DeleteWorkspaceVariableAction, &authz.AccessRequest{ID: &ws.ID})
	// Merge variables from sets and workspace vars, with the latter taking
	// precedence.
	merged := mergeVariables(sets, workspaceVariables, nil)
	// Copy workspace variables into slice
	allVariables := make([]*variable, len(workspaceVariables))
	for i, wv := range workspaceVariables {
		allVariables[i] = &variable{
			Variable:                wv,
			CanUpdate:               canUpdateVariable,
			CanDelete:               canDeleteVariable,
			DeletePath:              paths.DeleteVariable(wv.ID.String()),
			WorkspaceVariablesTable: true,
		}
	}
	// Append variable sets to slice, including those that are overridden, for
	// the user's information.
	for _, set := range sets {
		for _, sv := range set.Variables {
			v := variable{
				Variable:    sv,
				VariableSet: set,
				// Variable is deemed overridden if it's not in the merged
				// variables slice
				Overridden: !slices.ContainsFunc(merged, func(mergedVar *Variable) bool {
					return mergedVar.ID == sv.ID
				}),
				WorkspaceVariablesTable: true,
			}
			allVariables = append(allVariables, &v)
		}
	}
	// sort variables by key and then by whether it is overridden.
	slices.SortFunc(allVariables, func(a, b *variable) int {
		if a.Key == b.Key {
			if a.Overridden {
				return 1
			}
			return -1
		}
		if a.Key > b.Key {
			return 1
		}
		return -1
	})
	h.Render("variable_list.tmpl", w, struct {
		workspace.WorkspacePage
		html.Page[*variable]
		CanCreateVariable       bool
		CanUpdateWorkspace      bool
		WorkspaceVariablesTable bool
	}{
		WorkspacePage: workspace.NewPage(r, "variables", ws),
		Page: html.Page[*variable]{
			Page:    resource.NewPage(allVariables, params.PageOptions, nil),
			Request: r,
		},
		CanCreateVariable:       h.authorizer.CanAccess(r.Context(), authz.CreateWorkspaceVariableAction, &authz.AccessRequest{ID: &ws.ID}),
		CanUpdateWorkspace:      h.authorizer.CanAccess(r.Context(), authz.UpdateWorkspaceAction, &authz.AccessRequest{ID: &ws.ID}),
		WorkspaceVariablesTable: true,
	})
}

func (h *web) editWorkspaceVariable(w http.ResponseWriter, r *http.Request) {
	variableID, err := decode.ID("variable_id", r)
	if err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	wv, err := h.variables.GetWorkspaceVariable(r.Context(), variableID)
	if err != nil {
		h.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ws, err := h.workspaces.Get(r.Context(), wv.WorkspaceID)
	if err != nil {
		h.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.Render("variable_edit.tmpl", w, struct {
		workspace.WorkspacePage
		Variable   *Variable
		EditMode   bool
		FormAction string
	}{
		WorkspacePage: workspace.NewPage(r, "edit | "+wv.ID.String(), ws),
		Variable:      wv.Variable,
		EditMode:      true,
		FormAction:    paths.UpdateVariable(wv.ID.String()),
	})
}

func (h *web) updateWorkspaceVariable(w http.ResponseWriter, r *http.Request) {
	var params updateVariableParams
	if err := decode.All(&params, r); err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	wv, err := h.variables.UpdateWorkspaceVariable(r.Context(), params.VariableID, UpdateVariableOptions{
		Key:         params.Key,
		Value:       params.Value,
		Description: params.Description,
		Category:    params.Category,
		Sensitive:   params.Sensitive,
		HCL:         &params.HCL,
	})
	if err != nil {
		html.FlashError(w, err.Error())
		http.Redirect(w, r, paths.EditVariable(params.VariableID.String()), http.StatusFound)
		return
	}

	html.FlashSuccess(w, "updated variable: "+wv.Key)
	http.Redirect(w, r, paths.Variables(wv.WorkspaceID.String()), http.StatusFound)
}

func (h *web) deleteWorkspaceVariable(w http.ResponseWriter, r *http.Request) {
	variableID, err := decode.ID("variable_id", r)
	if err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	wv, err := h.variables.DeleteWorkspaceVariable(r.Context(), variableID)
	if err != nil {
		h.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	html.FlashSuccess(w, "deleted variable: "+wv.Key)
	http.Redirect(w, r, paths.Variables(wv.WorkspaceID.String()), http.StatusFound)
}

func (h *web) listVariableSets(w http.ResponseWriter, r *http.Request) {
	var params struct {
		Organization string `schema:"organization_name,required"`
		resource.PageOptions
	}
	if err := decode.All(&params, r); err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	sets, err := h.variables.listVariableSets(r.Context(), params.Organization)
	if err != nil {
		h.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.Render("variable_set_list.tmpl", w, struct {
		organization.OrganizationPage
		html.Page[*VariableSet]
		CanCreate bool
	}{
		OrganizationPage: organization.NewPage(r, "variable sets", params.Organization),
		Page: html.Page[*VariableSet]{
			Page:    resource.NewPage(sets, params.PageOptions, nil),
			Request: r,
		},
		CanCreate: h.authorizer.CanAccess(r.Context(), authz.CreateVariableSetAction, &authz.AccessRequest{Organization: params.Organization}),
	})
}

func (h *web) newVariableSet(w http.ResponseWriter, r *http.Request) {
	org, err := decode.Param("organization_name", r)
	if err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	// retrieve names of all workspaces in org to show in dropdown widget
	availableWorkspaces, err := h.getAvailableWorkspaces(r.Context(), org)
	if err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	h.Render("variable_set_new.tmpl", w, struct {
		organization.OrganizationPage
		VariableSet         *VariableSet
		EditMode            bool
		FormAction          string
		AvailableWorkspaces []workspaceInfo
		ExistingWorkspaces  []workspaceInfo
	}{
		OrganizationPage: organization.NewPage(r, "variable sets", org),
		VariableSet: &VariableSet{
			Global: true, // set global as default
		},
		EditMode:            false,
		FormAction:          paths.CreateVariableSet(org),
		AvailableWorkspaces: availableWorkspaces,
		ExistingWorkspaces:  []workspaceInfo{},
	})
}

func (h *web) createVariableSet(w http.ResponseWriter, r *http.Request) {
	var params struct {
		Name           *string `schema:"name,required"`
		Description    string
		Global         bool
		Organization   string `schema:"organization_name,required"`
		WorkspacesJSON string `schema:"workspaces"`
	}
	if err := decode.All(&params, r); err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	var workspaces []workspaceInfo
	if err := json.Unmarshal([]byte(params.WorkspacesJSON), &workspaces); err != nil {
		h.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	workspaceIDs := make([]resource.ID, len(workspaces))
	for i, ws := range workspaces {
		workspaceIDs[i] = ws.ID
	}

	set, err := h.variables.createVariableSet(r.Context(), params.Organization, CreateVariableSetOptions{
		Name:        *params.Name,
		Description: params.Description,
		Global:      params.Global,
		Workspaces:  workspaceIDs,
	})
	if err != nil {
		html.FlashError(w, err.Error())
		http.Redirect(w, r, paths.NewVariableSet(params.Organization), http.StatusFound)
		return
	}

	html.FlashSuccess(w, "added variable set: "+set.Name)
	http.Redirect(w, r, paths.EditVariableSet(set.ID.String()), http.StatusFound)
}

func (h *web) editVariableSet(w http.ResponseWriter, r *http.Request) {
	var params struct {
		VariableSetID resource.ID `schema:"variable_set_id,required"`
		resource.PageOptions
	}
	if err := decode.All(&params, r); err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	set, err := h.variables.getVariableSet(r.Context(), params.VariableSetID)
	if err != nil {
		h.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// retrieve names of workspaces in org to show in dropdown widget
	availableWorkspaces, err := h.getAvailableWorkspaces(r.Context(), set.Organization)
	if err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	// create list of existing workspaces and remove them from available
	// workspaces
	existingWorkspaces := make([]workspaceInfo, len(set.Workspaces))
	for i, existing := range set.Workspaces {
		for j, avail := range availableWorkspaces {
			if avail.ID == existing {
				// add to existing
				existingWorkspaces[i] = workspaceInfo{Name: avail.Name, ID: avail.ID}
				// remove from available
				availableWorkspaces = append(availableWorkspaces[:j], availableWorkspaces[j+1:]...)
				break
			}
		}
	}
	allVariables := make([]*variable, len(set.Variables))
	for i, sv := range set.Variables {
		v := variable{
			Variable:    sv,
			VariableSet: set,
		}
		allVariables[i] = &v
	}
	// sort variables by key
	slices.SortFunc(allVariables, func(a, b *variable) int {
		if a.Key > b.Key {
			return 1
		}
		return -1
	})

	h.Render("variable_set_edit.tmpl", w, struct {
		organization.OrganizationPage
		*VariableSet
		html.Page[*variable]
		EditMode                bool
		FormAction              string
		AvailableWorkspaces     []workspaceInfo
		ExistingWorkspaces      []workspaceInfo
		CanCreateVariable       bool
		CanDeleteVariable       bool
		WorkspaceVariablesTable bool
	}{
		OrganizationPage: organization.NewPage(r, "edit | "+set.ID.String(), set.Organization),
		VariableSet:      set,
		Page: html.Page[*variable]{
			Page:    resource.NewPage(allVariables, params.PageOptions, nil),
			Request: r,
		},
		EditMode:                true,
		FormAction:              paths.UpdateVariableSet(set.ID.String()),
		AvailableWorkspaces:     availableWorkspaces,
		ExistingWorkspaces:      existingWorkspaces,
		CanCreateVariable:       h.authorizer.CanAccess(r.Context(), authz.CreateWorkspaceVariableAction, &authz.AccessRequest{Organization: set.Organization}),
		CanDeleteVariable:       h.authorizer.CanAccess(r.Context(), authz.DeleteWorkspaceVariableAction, &authz.AccessRequest{Organization: set.Organization}),
		WorkspaceVariablesTable: false,
	})
}

func (h *web) updateVariableSet(w http.ResponseWriter, r *http.Request) {
	var params struct {
		SetID          resource.ID `schema:"variable_set_id,required"`
		Name           *string
		Description    *string
		Global         *bool
		WorkspacesJSON string `schema:"workspaces"`
	}
	if err := decode.All(&params, r); err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	var workspaces []workspaceInfo
	if err := json.Unmarshal([]byte(params.WorkspacesJSON), &workspaces); err != nil {
		h.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	workspaceIDs := make([]resource.ID, len(workspaces))
	for i, ws := range workspaces {
		workspaceIDs[i] = ws.ID
	}

	set, err := h.variables.updateVariableSet(r.Context(), params.SetID, UpdateVariableSetOptions{
		Name:        params.Name,
		Description: params.Description,
		Global:      params.Global,
		Workspaces:  workspaceIDs,
	})
	if err != nil {
		html.FlashError(w, err.Error())
		http.Redirect(w, r, paths.EditVariableSet(params.SetID.String()), http.StatusFound)
		return
	}

	html.FlashSuccess(w, "updated variable set: "+set.Name)
	http.Redirect(w, r, paths.EditVariableSet(set.ID.String()), http.StatusFound)
}

func (h *web) deleteVariableSet(w http.ResponseWriter, r *http.Request) {
	setID, err := decode.ID("variable_set_id", r)
	if err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	set, err := h.variables.deleteVariableSet(r.Context(), setID)
	if err != nil {
		h.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	html.FlashSuccess(w, "deleted variable set: "+set.Name)
	http.Redirect(w, r, paths.VariableSets(set.Organization), http.StatusFound)
}

func (h *web) newVariableSetVariable(w http.ResponseWriter, r *http.Request) {
	setID, err := decode.ID("variable_set_id", r)
	if err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	set, err := h.variables.getVariableSet(r.Context(), setID)
	if err != nil {
		h.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.Render("variable_set_new_variable.tmpl", w, struct {
		organization.OrganizationPage
		VariableSet *VariableSet
		Variable    *Variable
		EditMode    bool
		FormAction  string
	}{
		OrganizationPage: organization.NewPage(r, "new variable | variable sets", set.Organization),
		VariableSet:      set,
		Variable:         &Variable{},
		EditMode:         false,
		FormAction:       paths.CreateVariableSetVariable(setID.String()),
	})
}

func (h *web) createVariableSetVariable(w http.ResponseWriter, r *http.Request) {
	var params struct {
		createVariableParams
		SetID resource.ID `schema:"variable_set_id,required"`
	}
	if err := decode.All(&params, r); err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	variable, err := h.variables.createVariableSetVariable(r.Context(), params.SetID, CreateVariableOptions{
		Key:         params.Key,
		Value:       params.Value,
		Description: params.Description,
		Category:    params.Category,
		Sensitive:   &params.Sensitive,
		HCL:         &params.HCL,
	})
	if err != nil {
		html.FlashError(w, err.Error())
		http.Redirect(w, r, paths.NewVariableSetVariable(params.SetID.String()), http.StatusFound)
		return
	}

	html.FlashSuccess(w, "added variable: "+variable.Key)
	http.Redirect(w, r, paths.EditVariableSet(params.SetID.String()), http.StatusFound)
}

func (h *web) editVariableSetVariable(w http.ResponseWriter, r *http.Request) {
	variableID, err := decode.ID("variable_id", r)
	if err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	set, err := h.variables.getVariableSetByVariableID(r.Context(), variableID)
	if err != nil {
		h.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	v := set.getVariable(variableID)

	h.Render("variable_set_edit_variable.tmpl", w, struct {
		organization.OrganizationPage
		VariableSet *VariableSet
		Variable    *Variable
		EditMode    bool
		FormAction  string
	}{
		OrganizationPage: organization.NewPage(r, "edit variable", set.Organization),
		VariableSet:      set,
		Variable:         v,
		EditMode:         true,
		FormAction:       paths.UpdateVariableSetVariable(v.ID.String()),
	})
}

func (h *web) updateVariableSetVariable(w http.ResponseWriter, r *http.Request) {
	var params updateVariableParams
	if err := decode.All(&params, r); err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	set, err := h.variables.updateVariableSetVariable(r.Context(), params.VariableID, UpdateVariableOptions{
		Key:         params.Key,
		Value:       params.Value,
		Description: params.Description,
		Category:    params.Category,
		Sensitive:   params.Sensitive,
		HCL:         &params.HCL,
	})
	if err != nil {
		html.FlashError(w, err.Error())
		http.Redirect(w, r, paths.EditVariableSetVariable(params.VariableID.String()), http.StatusFound)
		return
	}
	v := set.getVariable(params.VariableID)

	html.FlashSuccess(w, "updated variable: "+v.Key)
	http.Redirect(w, r, paths.EditVariableSet(set.ID.String()), http.StatusFound)
}

func (h *web) deleteVariableSetVariable(w http.ResponseWriter, r *http.Request) {
	variableID, err := decode.ID("variable_id", r)
	if err != nil {
		h.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	set, err := h.variables.deleteVariableSetVariable(r.Context(), variableID)
	if err != nil {
		h.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	v := set.getVariable(variableID)

	html.FlashSuccess(w, "deleted variable: "+v.Key)
	http.Redirect(w, r, paths.EditVariableSet(set.ID.String()), http.StatusFound)
}

func (h *web) getAvailableWorkspaces(ctx context.Context, org string) ([]workspaceInfo, error) {
	// retrieve names of all workspaces in org to show in dropdown widget
	workspaces, err := resource.ListAll(func(opts resource.PageOptions) (*resource.Page[*workspace.Workspace], error) {
		return h.workspaces.List(ctx, workspace.ListOptions{
			Organization: &org,
			PageOptions:  opts,
		})
	})
	if err != nil {
		return nil, err
	}

	availableWorkspaces := make([]workspaceInfo, len(workspaces))
	for i, ws := range workspaces {
		availableWorkspaces[i] = workspaceInfo{
			ID:   ws.ID,
			Name: ws.Name,
		}
	}
	return availableWorkspaces, nil
}
