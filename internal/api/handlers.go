package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const helpText = `# jwtkit — Agentic-first JWT service

Create, sign, verify, and decode JSON Web Tokens over plain HTTP.
The agent IS the interface. No SDK, no UI.

## Quick Start
1. Request OTP:   POST /auth/otp     {"email":"you@example.com"}
2. Verify OTP:    POST /auth/verify   {"email":"you@example.com","code":"123456"}
3. Use the returned token as: Authorization: Bearer <token>

## Endpoints

### Auth
POST /auth/otp      Request a one-time password   {"email":"..."}
POST /auth/verify    Verify OTP, get bearer token  {"email":"...","code":"..."}

### Keys
POST   /keys          Create a signing key  {"alg":"HS256","secret":"..."}
GET    /keys          List your signing keys
GET    /keys/{handle} Get key details
DELETE /keys/{handle} Delete a key

### JWT Operations
POST /create   Create/sign a JWT   {"key":"key_...","claims":{"sub":"user123","exp":1735689600}}
POST /verify    Verify a JWT       {"token":"eyJ...","key":"key_..."}
POST /decode    Decode a JWT       {"token":"eyJ..."}

### System
GET  /help                    This manual
GET  /.well-known/agent.md    Same as /help
GET  /health                  Health check
POST /mcp                     MCP protocol endpoint

## Response Format
Plain text by default — one labeled, grepable line per record.
Add Accept: application/json or ?format=json for JSON.

## Supported Algorithms
HS256, HS384, HS512 (HMAC)
RS256, RS384, RS512 (RSA)

## Auth
Bearer token in Authorization header.
Get a token via POST /auth/otp then POST /auth/verify.
In dev mode (no SMTP configured), the OTP code is returned in the /auth/otp response.
`

// handleRoot provides a brief service description at /.
func (h *Handler) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		respondError(w, r, http.StatusNotFound, "not_found",
			fmt.Sprintf("unknown path %s; GET /help for the full manual", r.URL.Path))
		return
	}
	respondText(w, "jwtkit  status=ok  hint=GET /help for the operating manual")
}

// handleHelp returns the one-page operating manual.
func (h *Handler) handleHelp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, helpText)
}

// handleHealth returns a simple health check.
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondText(w, "ok  service=jwtkit  status=healthy")
}

// handleOTP handles POST /auth/otp.
func (h *Handler) handleOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, r, http.StatusMethodNotAllowed, "method_not_allowed",
			"use POST to request an OTP")
		return
	}

	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, r, http.StatusBadRequest, "invalid_body",
			"send a JSON body like {\"email\":\"you@example.com\"}")
		return
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	if body.Email == "" {
		respondError(w, r, http.StatusBadRequest, "missing_email",
			"include an email field, e.g. {\"email\":\"you@example.com\"}")
		return
	}

	code, err := h.auth.RequestOTP(body.Email)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "otp_failed", err.Error())
		return
	}

	if h.cfg.DevMode && code != "" {
		respond(w, r,
			fmt.Sprintf("otp_sent  email=%s  code=%s  hint=use this code with POST /auth/verify", body.Email, code),
			map[string]string{"email": body.Email, "code": code, "hint": "use this code with POST /auth/verify"},
		)
		return
	}

	respond(w, r,
		fmt.Sprintf("otp_sent  email=%s  hint=check your email for the 6-digit code", body.Email),
		map[string]string{"email": body.Email, "hint": "check your email for the 6-digit code"},
	)
}

// handleVerify handles POST /auth/verify.
func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, r, http.StatusMethodNotAllowed, "method_not_allowed",
			"use POST to verify an OTP")
		return
	}

	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, r, http.StatusBadRequest, "invalid_body",
			"send a JSON body like {\"email\":\"you@example.com\",\"code\":\"123456\"}")
		return
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	if body.Email == "" {
		respondError(w, r, http.StatusBadRequest, "missing_email",
			"include an email field")
		return
	}
	if body.Code == "" {
		respondError(w, r, http.StatusBadRequest, "missing_code",
			"include the 6-digit code from your email")
		return
	}

	token, err := h.auth.VerifyOTP(body.Email, body.Code)
	if err != nil {
		respondError(w, r, http.StatusUnauthorized, "verification_failed", err.Error())
		return
	}

	respond(w, r,
		fmt.Sprintf("token  %s  hint=use this as: Authorization: Bearer %s", token, token),
		map[string]string{"token": token, "hint": "use this as: Authorization: Bearer " + token},
	)
}
