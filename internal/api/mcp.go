package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/relentlessworks/jwtkit/internal/jwt"
	"github.com/relentlessworks/jwtkit/internal/model"
)

// JSONRPCRequest is a JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse is a JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCPTool describes a tool available via MCP.
type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// MCPContent is a content item in an MCP tool result.
type MCPContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// handleMCP implements a minimal MCP (Model Context Protocol) server.
func (h *Handler) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "use POST for MCP")
		return
	}

	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(JSONRPCResponse{
			JSONRPC: "2.0",
			Error:  &RPCError{Code: -32700, Message: "parse error: " + err.Error()},
		})
		return
	}

	resp := h.handleMCPMethod(&req)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleMCPMethod(req *JSONRPCRequest) JSONRPCResponse {
	switch req.Method {
	case "initialize":
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{},
				},
				"serverInfo": map[string]interface{}{
					"name":    "jwtkit",
					"version": "1.0.0",
				},
			},
		}

	case "tools/list":
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"tools": h.mcpTools(),
			},
		}

	case "tools/call":
		return h.handleMCPToolCall(req)

	default:
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:  &RPCError{Code: -32601, Message: "method not found: " + req.Method},
		}
	}
}

func (h *Handler) mcpTools() []MCPTool {
	return []MCPTool{
		{
			Name:        "create_key",
			Description: "Create a JWT signing key. For HMAC algorithms, provide a secret. For RSA, a key pair is auto-generated.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"alg":    map[string]interface{}{"type": "string", "description": "Algorithm: HS256, HS384, HS512, RS256, RS384, RS512"},
					"secret": map[string]interface{}{"type": "string", "description": "Secret for HMAC algorithms"},
				},
				"required": []string{"alg"},
			},
		},
		{
			Name:        "list_keys",
			Description: "List all signing keys in your workspace.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "create_jwt",
			Description: "Create and sign a JWT with the given claims using a stored key.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"key":     map[string]interface{}{"type": "string", "description": "Key handle (e.g. key_abc12)"},
					"claims":  map[string]interface{}{"type": "object", "description": "JWT claims (e.g. {\"sub\":\"user123\",\"exp\":1735689600})"},
				},
				"required": []string{"key", "claims"},
			},
		},
		{
			Name:        "verify_jwt",
			Description: "Verify a JWT signature and return its claims.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"token": map[string]interface{}{"type": "string", "description": "The JWT to verify"},
					"key":   map[string]interface{}{"type": "string", "description": "Key handle for verification"},
				},
				"required": []string{"token", "key"},
			},
		},
		{
			Name:        "decode_jwt",
			Description: "Decode a JWT header and payload without verifying the signature.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"token": map[string]interface{}{"type": "string", "description": "The JWT to decode"},
				},
				"required": []string{"token"},
			},
		},
	}
}

func (h *Handler) handleMCPToolCall(req *JSONRPCRequest) JSONRPCResponse {
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: &RPCError{Code: -32602, Message: "invalid params"}}
	}

	// MCP tool calls require auth — extract token from arguments or return instructions
	token, _ := params.Arguments["_token"].(string)
	if token == "" {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"content": []MCPContent{{
					Type: "text",
					Text: "error  auth_required  hint=first authenticate via POST /auth/otp then POST /auth/verify, then pass the token as _token in arguments",
				}},
				"isError": true,
			},
		}
	}

	wsID, err := h.auth.ValidateToken(token)
	if err != nil {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"content": []MCPContent{{
					Type: "text",
					Text: "error  invalid_token  hint=your token is invalid or expired; request a new one via POST /auth/otp",
				}},
				"isError": true,
			},
		}
	}

	var text string
	switch params.Name {
	case "create_key":
		text = h.mcpCreateKey(wsID, params.Arguments)
	case "list_keys":
		text = h.mcpListKeys(wsID)
	case "create_jwt":
		text = h.mcpCreateJWT(wsID, params.Arguments)
	case "verify_jwt":
		text = h.mcpVerifyJWT(wsID, params.Arguments)
	case "decode_jwt":
		text = h.mcpDecodeJWT(params.Arguments)
	default:
		return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: &RPCError{Code: -32601, Message: "unknown tool: " + params.Name}}
	}

	return JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []MCPContent{{Type: "text", Text: text}},
		},
	}
}

func (h *Handler) mcpCreateKey(wsID string, args map[string]interface{}) string {
	alg, _ := args["alg"].(string)
	alg = strings.ToUpper(strings.TrimSpace(alg))
	if !jwt.ValidAlgorithm(alg) {
		return "error  invalid_algorithm  hint=alg must be one of: HS256, HS384, HS512, RS256, RS384, RS512"
	}

	key := &model.Key{
		Handle:      generateHandle("key"),
		WorkspaceID: wsID,
		Algorithm:   alg,
		CreatedAt:   time.Now(),
	}

	if jwt.IsHMAC(jwt.Algorithm(alg)) {
		secret, _ := args["secret"].(string)
		if secret == "" {
			return "error  missing_secret  hint=HMAC algorithms require a secret"
		}
		key.Secret = secret
	} else if jwt.IsRSA(jwt.Algorithm(alg)) {
		privKey, err := jwt.GenerateRSAKeyPair(2048)
		if err != nil {
			return "error  key_generation_failed  hint=failed to generate RSA key pair"
		}
		key.PrivateKey = jwt.EncodePrivateKeyPEM(privKey)
		key.PublicKey = jwt.EncodePublicKeyPEM(&privKey.PublicKey)
	}

	if err := h.store.CreateKey(key); err != nil {
		return "error  store_error  hint=failed to save key"
	}

	return fmt.Sprintf("key  %s  alg=%s  created=%s", key.Handle, key.Algorithm, key.CreatedAt.Format(time.RFC3339))
}

func (h *Handler) mcpListKeys(wsID string) string {
	keys := h.store.ListKeys(wsID)
	if len(keys) == 0 {
		return "info  no_keys  hint=create a key with the create_key tool"
	}
	var lines []string
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("key  %s  alg=%s  created=%s", k.Handle, k.Algorithm, k.CreatedAt.Format(time.RFC3339)))
	}
	return strings.Join(lines, "\n")
}

func (h *Handler) mcpCreateJWT(wsID string, args map[string]interface{}) string {
	keyHandle, _ := args["key"].(string)
	claimsRaw, ok := args["claims"]
	if !ok {
		return "error  missing_claims  hint=include claims, e.g. {\"sub\":\"user123\",\"exp\":1735689600}"
	}

	claims, ok := claimsRaw.(map[string]interface{})
	if !ok {
		return "error  invalid_claims  hint=claims must be a JSON object"
	}

	key, ok := h.store.GetKey(keyHandle)
	if !ok || key.WorkspaceID != wsID {
		return "error  key_not_found  hint=this key does not exist; use list_keys to see your keys"
	}

	alg := jwt.Algorithm(key.Algorithm)
	var signingKey interface{}
	if jwt.IsHMAC(alg) {
		signingKey = []byte(key.Secret)
	} else if jwt.IsRSA(alg) {
		privKey, err := jwt.ParsePrivateKeyPEM(key.PrivateKey)
		if err != nil {
			return "error  key_parse_error  hint=failed to parse stored private key"
		}
		signingKey = privKey
	}

	token, err := jwt.Sign(alg, claims, signingKey)
	if err != nil {
		return fmt.Sprintf("error  sign_error  hint=%s", err.Error())
	}

	return fmt.Sprintf("jwt  %s", token)
}

func (h *Handler) mcpVerifyJWT(wsID string, args map[string]interface{}) string {
	token, _ := args["token"].(string)
	keyHandle, _ := args["key"].(string)

	key, ok := h.store.GetKey(keyHandle)
	if !ok || key.WorkspaceID != wsID {
		return "error  key_not_found  hint=this key does not exist"
	}

	alg := jwt.Algorithm(key.Algorithm)
	var verifyKey interface{}
	if jwt.IsHMAC(alg) {
		verifyKey = []byte(key.Secret)
	} else if jwt.IsRSA(alg) {
		pubKey, err := jwt.ParsePublicKeyPEM(key.PublicKey)
		if err != nil {
			return "error  key_parse_error  hint=failed to parse stored public key"
		}
		verifyKey = pubKey
	}

	claims, err := jwt.Verify(token, alg, verifyKey)
	if err != nil {
		return fmt.Sprintf("error  verification_failed  hint=%s", err.Error())
	}

	return fmt.Sprintf("valid  true  alg=%s  claims=%s", key.Algorithm, formatClaims(claims))
}

func (h *Handler) mcpDecodeJWT(args map[string]interface{}) string {
	token, _ := args["token"].(string)
	header, payload, err := jwt.Decode(token)
	if err != nil {
		return fmt.Sprintf("error  decode_error  hint=%s", err.Error())
	}
	alg, _ := header["alg"].(string)
	return fmt.Sprintf("decoded  alg=%s  claims=%s", alg, formatClaims(payload))
}
