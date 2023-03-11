package module

import (
	"errors"
	"html/template"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/leg100/otf"
	"github.com/leg100/otf/cloud"
	"github.com/leg100/otf/http/decode"
	"github.com/leg100/otf/http/html"
	"github.com/leg100/otf/http/html/paths"
)

// webHandlers provides handlers for the webUI
type webHandlers struct {
	otf.Signer
	otf.Renderer
	otf.VCSProviderService

	hostname string
	svc      service
}

type newModuleStep string

const (
	newModuleConnectStep newModuleStep = "connect-vcs"
	newModuleRepoStep    newModuleStep = "select-repo"
	newModuleConfirmStep newModuleStep = "confirm-selection"
)

func (h *webHandlers) addHandlers(r *mux.Router) {
	r.HandleFunc("/organizations/{organization_name}/modules", h.list)
	r.HandleFunc("/organizations/{organization_name}/modules/new", h.new)
	r.HandleFunc("/modules/{module_id}", h.get)
	r.HandleFunc("/modules/{module_id}/delete", h.delete)
	r.HandleFunc("/modules/create", h.publish)
}

func (h *webHandlers) list(w http.ResponseWriter, r *http.Request) {
	var opts ListModulesOptions
	if err := decode.All(&opts, r); err != nil {
		html.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	modules, err := h.svc.ListModules(r.Context(), opts)
	if err != nil {
		html.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.Render("module_list.tmpl", w, r, struct {
		Items        []*Module
		Organization string
	}{
		Items:        modules,
		Organization: opts.Organization,
	})
}

func (h *webHandlers) get(w http.ResponseWriter, r *http.Request) {
	var params struct {
		ID      string  `schema:"module_id,required"`
		Version *string `schema:"version"`
	}
	if err := decode.All(&params, r); err != nil {
		html.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	module, err := h.svc.GetModuleByID(r.Context(), params.ID)
	if err != nil {
		html.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var modver *ModuleVersion
	if params.Version != nil {
		modver = module.Version(*params.Version)
	} else {
		modver = module.Latest()
	}
	if modver == nil {
		// TODO: set flash and render
		html.Error(w, "no version found", http.StatusNotFound)
		return
	}

	modinfo, err := h.svc.GetModuleInfo(r.Context(), modver.ID)
	if err != nil {
		html.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var readme template.HTML
	switch module.Status {
	case ModuleStatusSetupComplete:
		readme = html.MarkdownToHTML(modinfo.readme)
	}

	h.Render("module_get.tmpl", w, r, struct {
		*Module
		TerraformModule *TerraformModule
		Readme          template.HTML
		CurrentVersion  *ModuleVersion
		Hostname        string
	}{
		Module:          module,
		TerraformModule: modinfo,
		Readme:          readme,
		CurrentVersion:  modver,
		Hostname:        h.hostname,
	})
}

func (h *webHandlers) new(w http.ResponseWriter, r *http.Request) {
	var params struct {
		Step newModuleStep `schema:"step"`
	}
	if err := decode.All(&params, r); err != nil {
		html.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	switch params.Step {
	case newModuleConnectStep, "":
		h.newModuleConnect(w, r)
	case newModuleRepoStep:
		h.newModuleRepo(w, r)
	case newModuleConfirmStep:
		h.newModuleConfirm(w, r)
	}
}

func (h *webHandlers) newModuleConnect(w http.ResponseWriter, r *http.Request) {
	org, err := decode.Param("organization_name", r)
	if err != nil {
		html.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	providers, err := h.ListVCSProviders(r.Context(), org)
	if err != nil {
		html.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.Render("module_new.tmpl", w, r, struct {
		Items        []*otf.VCSProvider
		Organization string
		Step         newModuleStep
	}{
		Items:        providers,
		Organization: org,
		Step:         newModuleConnectStep,
	})
}

func (h *webHandlers) newModuleRepo(w http.ResponseWriter, r *http.Request) {
	var params struct {
		Organization  string `schema:"organization_name,required"`
		VCSProviderID string `schema:"vcs_provider_id,required"`
		// TODO: filters, public/private, etc
	}
	if err := decode.All(&params, r); err != nil {
		html.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	client, err := h.GetVCSClient(r.Context(), params.VCSProviderID)
	if err != nil {
		html.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Retrieve repos and filter according to required naming format
	// '<something>-<name>-<provider>'
	results, err := client.ListRepositories(r.Context(), cloud.ListRepositoriesOptions{
		PageSize: otf.MaxPageSize,
	})
	if err != nil {
		html.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var filtered []string
	for _, res := range results {
		_, _, err := repo(res).Split()
		if err == ErrInvalidModuleRepo {
			continue // skip repo
		} else if err != nil {
			html.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		filtered = append(filtered, res)
	}

	h.Render("module_new.tmpl", w, r, struct {
		Repos         []string
		Organization  string
		VCSProviderID string
		Step          newModuleStep
	}{
		Repos:         filtered,
		Organization:  params.Organization,
		VCSProviderID: params.VCSProviderID,
		Step:          newModuleRepoStep,
	})
}

func (h *webHandlers) newModuleConfirm(w http.ResponseWriter, r *http.Request) {
	var params struct {
		Organization  string `schema:"organization_name,required"`
		VCSProviderID string `schema:"vcs_provider_id,required"`
		Repo          string `schema:"identifier,required"`
	}
	if err := decode.All(&params, r); err != nil {
		html.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	vcsprov, err := h.GetVCSProvider(r.Context(), params.VCSProviderID)
	if err != nil {
		html.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.Render("module_new.tmpl", w, r, struct {
		Organization string
		Step         newModuleStep
		Repo         string
		*otf.VCSProvider
	}{
		Organization: params.Organization,
		Step:         newModuleConfirmStep,
		Repo:         params.Repo,
		VCSProvider:  vcsprov,
	})
}

func (h *webHandlers) publish(w http.ResponseWriter, r *http.Request) {
	var params struct {
		VCSProviderID string `schema:"vcs_provider_id,required"`
		Repo          repo   `schema:"identifier,required"`
	}
	if err := decode.All(&params, r); err != nil {
		html.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	module, err := h.svc.PublishModule(r.Context(), PublishModuleOptions{
		Repo:          params.Repo,
		VCSProviderID: params.VCSProviderID,
	})
	if err != nil && errors.Is(err, otf.ErrInvalidRepo) || errors.Is(err, ErrInvalidModuleRepo) {
		html.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	} else if err != nil && errors.Is(err, ErrInvalidModuleRepo) {
		html.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	html.FlashSuccess(w, "published module: "+module.Name)
	http.Redirect(w, r, paths.Module(module.ID), http.StatusFound)
}

func (h *webHandlers) delete(w http.ResponseWriter, r *http.Request) {
	id, err := decode.Param("module_id", r)
	if err != nil {
		html.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	deleted, err := h.svc.DeleteModule(r.Context(), id)
	if err != nil {
		html.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	html.FlashSuccess(w, "deleted module: "+deleted.Name)
	http.Redirect(w, r, paths.Modules(deleted.Organization), http.StatusFound)
}
