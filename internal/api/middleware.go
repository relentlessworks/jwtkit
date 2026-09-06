package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/relentlessworks/jwtkit/internal/auth"
	"github.com/relentlessworks/jwtkit/internal/config"
	"github.com/relentlessworks/jwtkit/internal/store"
)

type ctxKey struct{}

// Handler holds all dependencies for the HTTP API.
type Handler struct {
	store *store.Store
	cfg   *config.Config
	auth  *auth.Auth
}

// New creates a new API Handler.
func New(s *store.Store, cfg *config.Config) *Handler {
	return &Handler{
		store: s,
		cfg:   cfg,
		auth:  auth.New(s, cfg),
	}
}

// Register wires all routes onto the given mux.
func (h *Handler) Register(mux *http.ServeMux) {
	// Auth (no token required)
	mux.HandleFunc("/auth/otp", h.handleOTP)
	mux.HandleFunc("/auth/verify", h.handleVerify)

	// Keys (token required)
	mux.HandleFunc("/keys", h.requireAuth(h.handleKeys))
	mux.HandleFunc("/keys/", h.requireAuth(h.handleKeyByHandle))

	// JWT operations (token required)
	mux.HandleFunc("/create", h.requireAuth(h.handleCreateJWT))
	mux.HandleFunc("/verify", h.requireAuth(h.handleVerifyJWT))
	mux.HandleFunc("/decode", h.requireAuth(h.handleDecodeJWT))

	// System
	mux.HandleFunc("/help", h.handleHelp)
	mux.HandleFunc("/.well-known/agent.md", h.handleHelp)
	mux.HandleFunc("/health", h.handleHealth)
	mux.HandleFunc("/mcp", h.handleMCP)

	// Root
	mux.HandleFunc("/", h.handleRoot)
}

// requireAuth wraps a handler with bearer-token authentication.
func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractBearer(r)
		if token == "" {
			respondError(w, r, http.StatusUnauthorized, "missing_token",
				"include an Authorization: Bearer <token> header; get a token via POST /auth/verify")
			return
		}
		wsID, err := h.auth.ValidateToken(token)
		if err != nil {
			respondError(w, r, http.StatusUnauthorized, "invalid_token",
				"your token is invalid or expired; request a new one via POST /auth/otp then POST /auth/verify")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, wsID)
		next(w, r.WithContext(ctx))
	}
}

func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func (h *Handler) workspaceID(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKey{}).(string); ok {
		return v
	}
	return ""
}
