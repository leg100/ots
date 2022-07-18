package html

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"

	term2html "github.com/buildkite/terminal-to-html"
	"github.com/gorilla/mux"
	"github.com/leg100/otf"
	"github.com/leg100/otf/http/decode"
	"github.com/r3labs/sse/v2"
)

func (app *Application) listRuns(w http.ResponseWriter, r *http.Request) {
	opts := otf.RunListOptions{
		// We don't list speculative runs on the UI
		Speculative: otf.Bool(false),
	}
	if err := decode.Query(&opts, r.URL.Query()); err != nil {
		writeError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := decode.Route(&opts, r); err != nil {
		writeError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	runs, err := app.RunService().List(r.Context(), opts)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	app.render("run_list.tmpl", w, r, runList{runs, opts})
}

func (app *Application) newRun(w http.ResponseWriter, r *http.Request) {
	app.render("run_new.tmpl", w, r, struct {
		Organization string
		Workspace    string
	}{
		Organization: mux.Vars(r)["organization_name"],
		Workspace:    mux.Vars(r)["workspace_name"],
	})
}

func (app *Application) createRun(w http.ResponseWriter, r *http.Request) {
	var opts otf.RunCreateOptions
	if err := decode.Route(&opts, r); err != nil {
		writeError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := decode.Form(&opts, r); err != nil {
		writeError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	ws := workspaceRequest{r}.Spec()
	created, err := app.RunService().Create(r.Context(), ws, opts)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, getRunPath(created), http.StatusFound)
}

func (app *Application) getRun(w http.ResponseWriter, r *http.Request) {
	run, err := app.RunService().Get(r.Context(), mux.Vars(r)["run_id"])
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	app.render("run_get.tmpl", w, r, run)
}

func (app *Application) watchRun(w http.ResponseWriter, r *http.Request) {
	server := sse.New()
	server.CreateStream("messages")

	sub, err := app.EventService().Subscribe("watch-run-")
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	go func() {
		for {
			select {
			case ev := <-sub.C():
				run, ok := ev.Payload.(*otf.Run)
				if !ok {
					continue
				}
				if run.ID() != mux.Vars(r)["run_id"] {
					continue
				}
				buf := new(bytes.Buffer)
				if err := app.renderTemplate("run_item.tmpl", buf, run); err != nil {
					app.Error(err, "rendering template for watched run")
					continue
				}
				server.Publish("messages", &sse.Event{Data: buf.Bytes()})
			case <-r.Context().Done():
				return
			}
		}
	}()
	server.ServeHTTP(w, r)
}

func (app *Application) getPlan(w http.ResponseWriter, r *http.Request) {
	run, err := app.RunService().Get(r.Context(), mux.Vars(r)["run_id"])
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	chunk, err := app.RunService().GetChunk(r.Context(), run.ID(), otf.PlanPhase, otf.GetChunkOptions{})
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// convert to string
	logs := string(chunk.Data)
	// trim leading and trailing white space
	logs = strings.TrimSpace(logs)
	// convert ANSI escape sequences to HTML
	logs = string(term2html.Render([]byte(logs)))
	// trim leading and trailing white space
	logs = strings.TrimSpace(logs)
	app.render("plan_get.tmpl", w, r, struct {
		Run  *otf.Run
		Logs template.HTML
	}{
		Run:  run,
		Logs: template.HTML(logs),
	})
}

func (app *Application) getApply(w http.ResponseWriter, r *http.Request) {
	run, err := app.RunService().Get(r.Context(), mux.Vars(r)["run_id"])
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	chunk, err := app.RunService().GetChunk(r.Context(), run.ID(), otf.ApplyPhase, otf.GetChunkOptions{})
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// convert to string
	logs := string(chunk.Data)
	// trim leading and trailing white space
	logs = strings.TrimSpace(logs)
	// convert ANSI escape sequences to HTML
	logs = string(term2html.Render([]byte(logs)))
	// trim leading and trailing white space
	logs = strings.TrimSpace(logs)
	app.render("apply_get.tmpl", w, r, struct {
		Run  *otf.Run
		Logs template.HTML
	}{
		Run:  run,
		Logs: template.HTML(logs),
	})
}

func (app *Application) deleteRun(w http.ResponseWriter, r *http.Request) {
	err := app.RunService().Delete(r.Context(), mux.Vars(r)["run_id"])
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, getWorkspacePath(workspaceRequest{r}), http.StatusFound)
}

func (app *Application) cancelRun(w http.ResponseWriter, r *http.Request) {
	err := app.RunService().Cancel(r.Context(), mux.Vars(r)["run_id"], otf.RunCancelOptions{})
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, listRunPath(workspaceRequest{r}), http.StatusFound)
}
