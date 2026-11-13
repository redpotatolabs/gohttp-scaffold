package share

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	scaffold "github.com/redpotatolabs/gohttp-scaffold"
	"github.com/redpotatolabs/gohttp-scaffold/changelog"
)

// Resolver turns a target into the JSON payload a link shows. It returns
// ErrNotFound when the target does not exist (any error wrapping it counts).
type Resolver func(ctx context.Context, target string) (json.RawMessage, error)

// Identify returns the signed-in person for a request. The auth package
// provides it; ok is false when nobody is signed in.
type Identify func(r *http.Request) (actor changelog.Actor, ok bool)

// Handlers serves the share routes. The app mounts them itself, so it decides
// the paths and which ones sit behind its edit-role check:
//
//	mux.Handle("POST /api/shares", requireEdit(h.Create))
//	mux.Handle("GET /api/shares", requireEdit(h.List))
//	mux.Handle("DELETE /api/shares/{token}", requireEdit(h.Revoke))
//	mux.Handle("GET /api/s/{token}", h.Public) // no sign-in
//
// Revoke and Public read the token from the {token} path value.
type Handlers struct {
	Store    *Store
	Resolve  Resolver
	Identify Identify
}

type createRequest struct {
	Target string `json:"target"`
}

// Create makes a link. Body: {"target": "..."}. 201 with the link; 404 when
// the target does not resolve; 401 when nobody is signed in.
func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	by, ok := h.Identify(r)
	if !ok {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	var req createRequest
	if !scaffold.ReadJSON(w, r, &req, 4<<10) {
		return
	}
	if req.Target == "" || len(req.Target) > MaxTargetLen {
		http.Error(w, "bad target", http.StatusBadRequest)
		return
	}
	if _, err := h.Resolve(r.Context(), req.Target); err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		log.Printf("share: resolve %q: %v", req.Target, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	l, err := h.Store.Create(req.Target, by)
	if err != nil {
		log.Printf("share: create: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	scaffold.WriteJSON(w, l)
}

// List returns the links, newest first. ?target= narrows it to one target.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.Identify(r); !ok {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	scaffold.WriteJSON(w, h.Store.List(r.URL.Query().Get("target")))
}

// Revoke turns the {token} link off. 204, or 404 for an unknown token.
func (h *Handlers) Revoke(w http.ResponseWriter, r *http.Request) {
	by, ok := h.Identify(r)
	if !ok {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	switch err := h.Store.Revoke(r.PathValue("token"), by); {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	default:
		log.Printf("share: revoke: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// publicResponse leaves the target out on purpose: a visitor only needs what
// the link shows, not the app's internal id for it.
type publicResponse struct {
	Payload json.RawMessage `json:"payload"`
}

// Public serves the payload behind the {token} link to anyone. Unknown,
// revoked and dangling links all answer the same 404, so a visitor cannot
// tell them apart. Responses are not cached and not indexed.
func (h *Handlers) Public(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	l, ok := h.Store.Lookup(r.PathValue("token"))
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	payload, err := h.Resolve(r.Context(), l.Target)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		log.Printf("share: resolve %q: %v", l.Target, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	scaffold.WriteJSON(w, publicResponse{Payload: payload})
}
