package configversion

import (
	"bytes"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/leg100/otf"
	otfhttp "github.com/leg100/otf/http"
	"github.com/leg100/otf/http/decode"
	"github.com/leg100/otf/http/jsonapi"
	"github.com/leg100/surl"
)

type handlers struct {
	Application  app
	otf.Verifier // for verifying upload url

	jsonapiMarshaler

	max int64 // Maximum permitted config upload size in bytes
}

func newHandlers(opts handlersOptions) *handlers {
	return &handlers{
		Application:      opts.app,
		max:              opts.max,
		jsonapiMarshaler: jsonapiMarshaler{opts.Signer},
		Verifier:         opts.Signer,
	}
}

type handlersOptions struct {
	app
	max int64
	*surl.Signer
}

func (s *handlers) AddHandlers(r *mux.Router) {
	// ConfigurationVersion routes
	r.HandleFunc("/workspaces/{workspace_id}/configuration-versions", s.CreateConfigurationVersion)
	r.HandleFunc("/configuration-versions/{id}", s.GetConfigurationVersion)
	r.HandleFunc("/workspaces/{workspace_id}/configuration-versions", s.ListConfigurationVersions)
	r.HandleFunc("/configuration-versions/{id}/download", s.DownloadConfigurationVersion)

	signed := r.PathPrefix("/signed/{signature.expiry}").Subrouter()
	signed.Use((&otfhttp.SignatureVerifier{s.Verifier}).Handler)
	signed.HandleFunc("/configuration-versions/{id}/upload", s.UploadConfigurationVersion()).Methods("PUT")
}

func (s *handlers) CreateConfigurationVersion(w http.ResponseWriter, r *http.Request) {
	workspaceID, err := decode.Param("workspace_id", r)
	if err != nil {
		jsonapi.Error(w, http.StatusUnprocessableEntity, err)
		return
	}

	opts := jsonapi.ConfigurationVersionCreateOptions{}
	if err := jsonapi.UnmarshalPayload(r.Body, &opts); err != nil {
		jsonapi.Error(w, http.StatusUnprocessableEntity, err)
		return
	}
	cv, err := s.Application.CreateConfigurationVersion(r.Context(), workspaceID, otf.ConfigurationVersionCreateOptions{
		AutoQueueRuns: opts.AutoQueueRuns,
		Speculative:   opts.Speculative,
	})
	if err != nil {
		jsonapi.Error(w, http.StatusNotFound, err)
		return
	}

	jsonapi.WriteResponse(w, r, s.toMarshalable(cv), jsonapi.WithCode(http.StatusCreated))
}

func (s *handlers) GetConfigurationVersion(w http.ResponseWriter, r *http.Request) {
	id, err := decode.Param("id", r)
	if err != nil {
		jsonapi.Error(w, http.StatusUnprocessableEntity, err)
		return
	}

	cv, err := s.Application.GetConfigurationVersion(r.Context(), id)
	if err != nil {
		jsonapi.Error(w, http.StatusNotFound, err)
		return
	}
	jsonapi.WriteResponse(w, r, s.toMarshalable(cv))
}

func (s *handlers) ListConfigurationVersions(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		WorkspaceID     string `schema:"workspace_id,required"`
		otf.ListOptions        // Pagination
	}
	var params parameters
	if err := decode.All(&params, r); err != nil {
		jsonapi.Error(w, http.StatusUnprocessableEntity, err)
		return
	}

	cvl, err := s.Application.ListConfigurationVersions(r.Context(), params.WorkspaceID, ConfigurationVersionListOptions{
		ListOptions: params.ListOptions,
	})
	if err != nil {
		jsonapi.Error(w, http.StatusNotFound, err)
		return
	}

	jsonapi.WriteResponse(w, r, s.toMarshableList(cvl))
}

func (s *handlers) UploadConfigurationVersion() http.HandlerFunc {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := decode.Param("id", r)
		if err != nil {
			jsonapi.Error(w, http.StatusUnprocessableEntity, err)
			return
		}

		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, r.Body); err != nil {
			jsonapi.Error(w, http.StatusUnprocessableEntity, err)
			return
		}
		if err := s.Application.UploadConfig(r.Context(), id, buf.Bytes()); err != nil {
			jsonapi.Error(w, http.StatusNotFound, err)
			return
		}
	})
	return http.MaxBytesHandler(h, s.max).ServeHTTP
}

func (s *handlers) DownloadConfigurationVersion(w http.ResponseWriter, r *http.Request) {
	id, err := decode.Param("id", r)
	if err != nil {
		jsonapi.Error(w, http.StatusUnprocessableEntity, err)
		return
	}

	resp, err := s.Application.DownloadConfig(r.Context(), id)
	if err != nil {
		jsonapi.Error(w, http.StatusNotFound, err)
		return
	}

	w.Write(resp)
}
