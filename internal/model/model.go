package model

import "time"

// Workspace represents a tenant in the system.
type Workspace struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Plan      string    `json:"plan"`
	CreatedAt time.Time `json:"created_at"`
}

// Key is a signing key used to create or verify JWTs.
type Key struct {
	Handle      string    `json:"handle"`
	WorkspaceID string    `json:"workspace_id"`
	Algorithm   string    `json:"algorithm"`
	Secret      string    `json:"secret,omitempty"`
	PrivateKey  string    `json:"private_key,omitempty"`
	PublicKey   string    `json:"public_key,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Token is an auth bearer token issued via OTP verification.
type Token struct {
	Handle      string     `json:"handle"`
	WorkspaceID string     `json:"workspace_id"`
	TokenHash   string     `json:"token_hash"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// OTP is a one-time password sent to an email address.
type OTP struct {
	Email     string    `json:"email"`
	Code      string    `json:"code"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}
