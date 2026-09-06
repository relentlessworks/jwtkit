# jwtkit

Agentic-first JWT creation, verification, and decoding service. Create, sign, verify, and decode JSON Web Tokens. Plain text API, agent-driven, single Go binary with JSON file storage.

## Philosophy

- **The agent IS the interface** — No UI, no SDK. The AI agent is the user. The API is the product.
- **Plain text by default** — One labeled, grepable line per record. JSON on demand via `Accept: application/json` or `?format=json`.
- **Instructive errors** — Every 4xx includes a hint telling the agent what to do next.
- **Self-documenting** — `GET /help` returns a one-page operating manual.
- **Simple auth** — OTP via email → long-lived bearer token.
- **Single static binary** — Pure Go, zero external dependencies.
- **Zero config defaults** — Runs out of the box. Config: defaults < env < flags.
- **MCP connector** — Speaks Model Context Protocol at `/mcp`.

## Quick Start

```bash
# Build and run
make build
./jwtkit

# Or with Go directly
go run ./cmd/jwtkit
```

The server starts on port 8470 by default.

## Usage

### 1. Request an OTP

```bash
curl -X POST http://localhost:8470/auth/otp \
  -d '{"email":"you@example.com"}'
```

In dev mode (default, no SMTP configured), the response includes the code:
```
otp_sent  email=you@example.com  code=482910  hint=use this code with POST /auth/verify
```

### 2. Verify the OTP to get a token

```bash
curl -X POST http://localhost:8470/auth/verify \
  -d '{"email":"you@example.com","code":"482910"}'
```
```
token  a1b2c3d4...  hint=use this as: Authorization: Bearer a1b2c3d4...
```

### 3. Create a signing key

```bash
curl -X POST http://localhost:8470/keys \
  -H "Authorization: Bearer <token>" \
  -d '{"alg":"HS256","secret":"mysecret"}'
```
```
key  key_k7m2q  alg=HS256  created=2026-09-06T10:17:42Z
```

### 4. Create a JWT

```bash
curl -X POST http://localhost:8470/create \
  -H "Authorization: Bearer <token>" \
  -d '{"key":"key_k7m2q","claims":{"sub":"user123","exp":1735689600}}'
```
```
jwt  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 5. Verify a JWT

```bash
curl -X POST http://localhost:8470/verify \
  -H "Authorization: Bearer <token>" \
  -d '{"token":"eyJ...","key":"key_k7m2q"}'
```
```
valid  true  alg=HS256  claims=sub=user123 exp=1735689600
```

### 6. Decode a JWT (no verification)

```bash
curl -X POST http://localhost:8470/decode \
  -H "Authorization: Bearer <token>" \
  -d '{"token":"eyJ..."}'
```
```
decoded  alg=HS256  claims=sub=user123 exp=1735689600
```

## Supported Algorithms

| Algorithm | Type | Key |
|-----------|------|-----|
| HS256     | HMAC | Shared secret |
| HS384     | HMAC | Shared secret |
| HS512     | HMAC | Shared secret |
| RS256     | RSA  | Auto-generated 2048-bit key pair |
| RS384     | RSA  | Auto-generated 2048-bit key pair |
| RS512     | RSA  | Auto-generated 2048-bit key pair |

## Configuration

| Flag  | Env | Default | Description |
|-------|-----|---------|-------------|
| -port | JWTKIT_PORT | 8470 | HTTP port |
| -data | JWTKIT_DATA_FILE | jwtkit.json | Data file path |
| -dev  | — | true | Dev mode (returns OTP in response) |
| —     | JWTKIT_SMTP_HOST | (empty) | SMTP server for email |
| —     | JWTKIT_SMTP_PORT | 587 | SMTP port |
| —     | JWTKIT_SMTP_USER | (empty) | SMTP username |
| —     | JWTKIT_SMTP_PASS | (empty) | SMTP password |
| —     | JWTKIT_SMTP_FROM | noreply@jwtkit.local | From address |

## MCP Integration

The service speaks Model Context Protocol at `POST /mcp`:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"create_jwt","arguments":{"_token":"<token>","key":"key_abc12","claims":{"sub":"user123"}}}}
```

## License

MIT
