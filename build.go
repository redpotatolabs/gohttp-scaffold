package scaffold

import (
	"encoding/json"
	"net/http"
)

// BuildInfo controls what RegisterBuildRoutes exposes at /__build_id.
type BuildInfo struct {
	// BuildID is reported by /__build_id. Defaults to "dev" when empty.
	BuildID string
}

// RegisterBuildRoutes wires GET /healthz and GET /__build_id onto mux.
// Both return JSON.
func RegisterBuildRoutes(mux *http.ServeMux, info BuildInfo) {
	id := info.BuildID
	if id == "" {
		id = "dev"
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			OK bool `json:"ok"`
		}{OK: true})
	})
	mux.HandleFunc("GET /__build_id", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			ID string `json:"id"`
		}{ID: id})
	})
}
