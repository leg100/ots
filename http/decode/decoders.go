// Package decode contains decoders for various HTTP artefacts
package decode

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
)

// Query schema decoder: caches structs, and safe for sharing.
var decoder = schema.NewDecoder()

// Form decodes an HTTP request's POST form contents into dst.
func Form(dst interface{}, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	if err := decoder.Decode(dst, r.PostForm); err != nil {
		return err
	}
	return nil
}

// Query unmarshals a query string (k1=v1&k2=v2...) into dst.
func Query(dst interface{}, query url.Values) error {
	if err := decoder.Decode(dst, query); err != nil {
		return fmt.Errorf("unable to decode query string: %w", err)
	}
	return nil
}

// Route decodes a mux route parameters (e.g. /foo/{bar}) into dst.
func Route(dst interface{}, r *http.Request) error {
	// decoder only takes map[string][]string, not map[string]string
	vars := convertStrMapToStrSliceMap(mux.Vars(r))
	if err := decoder.Decode(dst, vars); err != nil {
		return err
	}
	return nil
}

// All populates the struct pointed to by dst with query params, req body params
// and request path variables, respectively, with path variables taking
// precedence over body params, and body params over query params.
func All(dst interface{}, r *http.Request) error {
	// Parses both query and req body if POST/PUT/PATCH
	if err := r.ParseForm(); err != nil {
		return err
	}
	vars := make(map[string][]string, len(r.Form))
	for k, v := range r.Form {
		vars[k] = v
	}
	// Merge in request path variables
	for k, v := range mux.Vars(r) {
		vars[k] = []string{v}
	}
	if err := decoder.Decode(dst, vars); err != nil {
		return err
	}
	return nil
}

func convertStrMapToStrSliceMap(m map[string]string) map[string][]string {
	mm := make(map[string][]string, len(m))
	for k, v := range m {
		mm[k] = []string{v}
	}
	return mm
}
