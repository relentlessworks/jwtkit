package api

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/relentlessworks/jwtkit/internal/jwt"
	"github.com/relentlessworks/jwtkit/internal/model"
)

// --- Keys ---

// handleKeys handles POST /keys (create) and GET /keys (list).
func (h *Handler) handleKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createKey(w, r)
	case http.MethodGet:
		h.listKeys(w, r)
	default:
		respondError(w, r, http.StatusMethodNotAllowed, "method_not_allowed",
			"use POST to create a key or GET to list keys")
	}
}

func (h *Handler) createKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Alg    string `json:"alg"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, r, http.StatusBadRequest, "invalid_body",
			`send JSON like {"alg":"HS256","secret":"mysecret"} or {"alg":"RS256"} for auto-generated RSA`)
		return
	}

	alg := strings.ToUpper(strings.TrimSpace(body.Alg))
	if !jwt.ValidAlgorithm(alg) {
		respondError(w, r, http.StatusBadRequest, "invalid_algorithm",
			"alg must be one of: HS256, HS384, HS512, RS256, RS384, RS512")
		return
	}

	wsID := h.workspaceID(r)
	key := &model.Key{
		Handle:      generateHandle("key"),
		WorkspaceID: wsID,
		Algorithm:   alg,
		CreatedAt:   time.Now(),
	}

	if jwt.IsHMAC(jwt.Algorithm(alg)) {
		if body.Secret == "" {
			respondError(w, r, http.StatusBadRequest, "missing_secret",
				"HMAC algorithms require a secret field, e.g. {\"alg\":\"HS256\",\"secret\":\"mysecret\"}")
			return
		}
		key.Secret = body.Secret
	} else if jwt.IsRSA(jwt.Algorithm(alg)) {
		privKey, err := jwt.GenerateRSAKeyPair(2048)
		if err != nil {
			respondError(w, r, http.StatusInternalServerError, "key_generation_failed", "failed to generate RSA key pair")
			return
		}
		key.PrivateKey = jwt.EncodePrivateKeyPEM(privKey)
		key.PublicKey = jwt.EncodePublicKeyPEM(&privKey.PublicKey)
	}

	if err := h.store.CreateKey(key); err != nil {
		respondError(w, r, http.StatusInternalServerError, "store_error", "failed to save key")
		return
	}

	respond(w, r,
		fmt.Sprintf("key  %s  alg=%s  created=%s", key.Handle, key.Algorithm, key.CreatedAt.Format(time.RFC3339)),
		map[string]interface{}{
			"handle":    key.Handle,
			"algorithm": key.Algorithm,
			"created":   key.CreatedAt.Format(time.RFC3339),
		},
	)
}

func (h *Handler) listKeys(w http.ResponseWriter, r *http.Request) {
	wsID := h.workspaceID(r)
	keys := h.store.ListKeys(wsID)

	if wantsJSON(r) {
		var out []map[string]interface{}
		for _, k := range keys {
			out = append(out, map[string]interface{}{
				"handle":    k.Handle,
				"algorithm": k.Algorithm,
				"created":   k.CreatedAt.Format(time.RFC3339),
			})
		}
		respondJSON(w, map[string]interface{}{"keys": out})
		return
	}

	if len(keys) == 0 {
		respondText(w, "info  no_keys  hint=create a key with POST /keys")
		return
	}

	for _, k := range keys {
		fmt.Fprintf(w, "key  %s  alg=%s  created=%s\n", k.Handle, k.Algorithm, k.CreatedAt.Format(time.RFC3339))
	}
}

// handleKeyByHandle handles GET /keys/{handle} and DELETE /keys/{handle}.
func (h *Handler) handleKeyByHandle(w http.ResponseWriter, r *http.Request) {
	handle := strings.TrimPrefix(r.URL.Path, "/keys/")
	if handle == "" {
		respondError(w, r, http.StatusBadRequest, "missing_handle",
			"provide a key handle, e.g. GET /keys/key_abc12")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getKey(w, r, handle)
	case http.MethodDelete:
		h.deleteKey(w, r, handle)
	default:
		respondError(w, r, http.StatusMethodNotAllowed, "method_not_allowed",
			"use GET to view a key or DELETE to remove it")
	}
}

func (h *Handler) getKey(w http.ResponseWriter, r *http.Request, handle string) {
	wsID := h.workspaceID(r)
	key, ok := h.store.GetKey(handle)
	if !ok || key.WorkspaceID != wsID {
		respondError(w, r, http.StatusNotFound, "key_not_found",
			"this key does not exist or belongs to another workspace; GET /keys to list your keys")
		return
	}

	respond(w, r,
		fmt.Sprintf("key  %s  alg=%s  created=%s", key.Handle, key.Algorithm, key.CreatedAt.Format(time.RFC3339)),
		map[string]interface{}{
			"handle":     key.Handle,
			"algorithm":  key.Algorithm,
			"created":    key.CreatedAt.Format(time.RFC3339),
			"public_key": key.PublicKey,
		},
	)
}

func (h *Handler) deleteKey(w http.ResponseWriter, r *http.Request, handle string) {
	wsID := h.workspaceID(r)
	if !h.store.DeleteKey(handle, wsID) {
		respondError(w, r, http.StatusNotFound, "key_not_found",
			"this key does not exist or belongs to another workspace")
		return
	}
	respondOK(w, r,
		fmt.Sprintf("deleted  key  %s", handle),
		map[string]string{"deleted": handle},
	)
}

// --- JWT Operations ---

// handleCreateJWT handles POST /create.
func (h *Handler) handleCreateJWT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "use POST to create a JWT")
		return
	}

	var body struct {
		Key     string                 `json:"key"`
		Claims  map[string]interface{} `json:"claims"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, r, http.StatusBadRequest, "invalid_body",
			`send JSON like {"key":"key_abc12","claims":{"sub":"user123","exp":1735689600}}`)
		return
	}
	if body.Key == "" {
		respondError(w, r, http.StatusBadRequest, "missing_key",
			"include a key handle, e.g. {\"key\":\"key_abc12\",\"claims\":{...}}; create a key with POST /keys")
		return
	}
	if body.Claims == nil {
		body.Claims = make(map[string]interface{})
	}

	wsID := h.workspaceID(r)
	key, ok := h.store.GetKey(body.Key)
	if !ok || key.WorkspaceID != wsID {
		respondError(w, r, http.StatusNotFound, "key_not_found",
			"this key does not exist or belongs to another workspace; GET /keys to list your keys")
		return
	}

	alg := jwt.Algorithm(key.Algorithm)
	var signingKey interface{}
	if jwt.IsHMAC(alg) {
		signingKey = []byte(key.Secret)
	} else if jwt.IsRSA(alg) {
		privKey, err := jwt.ParsePrivateKeyPEM(key.PrivateKey)
		if err != nil {
			respondError(w, r, http.StatusInternalServerError, "key_parse_error", "failed to parse stored private key")
			return
		}
		signingKey = privKey
	}

	token, err := jwt.Sign(alg, body.Claims, signingKey)
	if err != nil {
		respondError(w, r, http.StatusBadRequest, "sign_error", err.Error())
		return
	}

	respond(w, r,
		fmt.Sprintf("jwt  %s", token),
		map[string]string{"jwt": token},
	)
}

// handleVerifyJWT handles POST /verify.
func (h *Handler) handleVerifyJWT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "use POST to verify a JWT")
		return
	}

	var body struct {
		Token string `json:"token"`
		Key   string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, r, http.StatusBadRequest, "invalid_body",
			`send JSON like {"token":"eyJ...","key":"key_abc12"}`)
		return
	}
	if body.Token == "" {
		respondError(w, r, http.StatusBadRequest, "missing_token",
			"include a JWT token to verify")
		return
	}
	if body.Key == "" {
		respondError(w, r, http.StatusBadRequest, "missing_key",
			"include a key handle for verification, e.g. {\"token\":\"eyJ...\",\"key\":\"key_abc12\"}")
		return
	}

	wsID := h.workspaceID(r)
	key, ok := h.store.GetKey(body.Key)
	if !ok || key.WorkspaceID != wsID {
		respondError(w, r, http.StatusNotFound, "key_not_found",
			"this key does not exist or belongs to another workspace")
		return
	}

	alg := jwt.Algorithm(key.Algorithm)
	var verifyKey interface{}
	if jwt.IsHMAC(alg) {
		verifyKey = []byte(key.Secret)
	} else if jwt.IsRSA(alg) {
		pubKey, err := jwt.ParsePublicKeyPEM(key.PublicKey)
		if err != nil {
			respondError(w, r, http.StatusInternalServerError, "key_parse_error", "failed to parse stored public key")
			return
		}
		verifyKey = pubKey
	}

	claims, err := jwt.Verify(body.Token, alg, verifyKey)
	if err != nil {
		respondError(w, r, http.StatusUnauthorized, "verification_failed", err.Error())
		return
	}

	respond(w, r,
		fmt.Sprintf("valid  true  alg=%s  claims=%s", key.Algorithm, formatClaims(claims)),
		map[string]interface{}{
			"valid":   true,
			"alg":     key.Algorithm,
			"claims":  claims,
		},
	)
}

// handleDecodeJWT handles POST /decode.
func (h *Handler) handleDecodeJWT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "use POST to decode a JWT")
		return
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, r, http.StatusBadRequest, "invalid_body",
			`send JSON like {"token":"eyJ..."}`)
		return
	}
	if body.Token == "" {
		respondError(w, r, http.StatusBadRequest, "missing_token",
			"include a JWT token to decode")
		return
	}

	header, payload, err := jwt.Decode(body.Token)
	if err != nil {
		respondError(w, r, http.StatusBadRequest, "decode_error", err.Error())
		return
	}

	alg, _ := header["alg"].(string)
	respond(w, r,
		fmt.Sprintf("decoded  alg=%s  claims=%s", alg, formatClaims(payload)),
		map[string]interface{}{
			"header":  header,
			"payload": payload,
		},
	)
}

// generateHandle creates a short workspace-scoped handle like key_k7m2q.
func generateHandle(prefix string) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return prefix + "_00000"
	}
	for i := range b {
		b[i] = chars[b[i]%byte(len(chars))]
	}
	return prefix + "_" + string(b)
}
