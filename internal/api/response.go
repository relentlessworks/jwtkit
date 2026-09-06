package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// wantsJSON reports whether the client requested JSON output.
func wantsJSON(r *http.Request) bool {
	if r.URL.Query().Get("format") == "json" {
		return true
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json")
}

// respondText writes a plain-text response (one labeled, grepable line).
func respondText(w http.ResponseWriter, line string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, line)
}

// respondJSON writes a JSON response.
func respondJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(v)
}

// respond writes either text or JSON depending on the request.
func respond(w http.ResponseWriter, r *http.Request, textLine string, jsonData interface{}) {
	if wantsJSON(r) {
		respondJSON(w, jsonData)
		return
	}
	respondText(w, textLine)
}

// respondError writes an instructive error response.
// The hint tells the agent what to do next.
func respondError(w http.ResponseWriter, r *http.Request, status int, code, hint string) {
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{
			"error": code,
			"hint":  hint,
		})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, "error  %s  hint=%s\n", code, hint)
}

// respondOK writes a simple success response.
func respondOK(w http.ResponseWriter, r *http.Request, textLine string, jsonData interface{}) {
	respond(w, r, textLine, jsonData)
}

// formatClaims converts a claims map to a grepable string.
func formatClaims(claims map[string]interface{}) string {
	var parts []string
	for k, v := range claims {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return strings.Join(parts, " ")
}
