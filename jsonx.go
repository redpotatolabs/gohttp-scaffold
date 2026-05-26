package scaffold

import (
	"encoding/json"
	"io"
	"net/http"
)

// DefaultMaxJSONBytes is the request body size limit when ReadJSON is
// called with maxBytes <= 0. Matches map's original 4 MB ceiling.
const DefaultMaxJSONBytes int64 = 4 << 20

// ReadJSON decodes r.Body into dst, limited to maxBytes
// (DefaultMaxJSONBytes when ≤ 0). On failure, writes a 400 to w and
// returns false. Callers should early-return on false without writing
// further headers.
func ReadJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) bool {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxJSONBytes
	}
	body := io.LimitReader(r.Body, maxBytes+1)
	dec := json.NewDecoder(body)
	if err := dec.Decode(dst); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

// WriteJSON encodes v as JSON with Content-Type: application/json. Errors
// from encoding are silently dropped (matches the existing map+mud
// behavior).
func WriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
