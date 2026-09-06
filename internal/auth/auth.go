package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/smtp"
	"strings"
	"time"

	"github.com/relentlessworks/jwtkit/internal/config"
	"github.com/relentlessworks/jwtkit/internal/model"
	"github.com/relentlessworks/jwtkit/internal/store"
)

// Auth handles OTP generation, email delivery, and bearer token management.
type Auth struct {
	store *store.Store
	cfg   *config.Config
}

// New creates a new Auth instance.
func New(s *store.Store, cfg *config.Config) *Auth {
	return &Auth{store: s, cfg: cfg}
}

// RequestOTP generates a one-time password and sends it to the email.
// In dev mode, the code is returned instead of being emailed.
func (a *Auth) RequestOTP(email string) (string, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return "", fmt.Errorf("email is required")
	}

	code := generateOTPCode()
	otp := &model.OTP{
		Email:     email,
		Code:      code,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := a.store.SaveOTP(otp); err != nil {
		return "", fmt.Errorf("failed to save OTP: %w", err)
	}

	if a.cfg.DevMode {
		// In dev mode, return the code so the agent can use it directly
		return code, nil
	}

	if a.cfg.SMTPHost != "" {
		if err := a.sendEmail(email, code); err != nil {
			return "", fmt.Errorf("failed to send email: %w", err)
		}
	}

	return "", nil
}

// VerifyOTP validates the OTP code and returns a new bearer token.
func (a *Auth) VerifyOTP(email, code string) (string, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return "", fmt.Errorf("email is required")
	}
	if code == "" {
		return "", fmt.Errorf("code is required")
	}

	otp, ok := a.store.GetOTP(email)
	if !ok {
		return "", fmt.Errorf("no OTP found for this email; request one via POST /auth/otp")
	}
	if otp.Used {
		return "", fmt.Errorf("OTP already used; request a new one via POST /auth/otp")
	}
	if time.Now().After(otp.ExpiresAt) {
		return "", fmt.Errorf("OTP expired; request a new one via POST /auth/otp")
	}
	if otp.Code != code {
		return "", fmt.Errorf("invalid OTP code; check the 6-digit code from your email")
	}

	a.store.MarkOTPUsed(email)

	// Create or reuse workspace
	wsID := generateHandle("ws")
	ws := &model.Workspace{
		ID:        wsID,
		Name:      email,
		Plan:      "free",
		CreatedAt: time.Now(),
	}
	if err := a.store.CreateWorkspace(ws); err != nil {
		return "", fmt.Errorf("failed to create workspace: %w", err)
	}

	// Create bearer token
	tokenStr := generateToken()
	token := &model.Token{
		Handle:      generateHandle("tok"),
		WorkspaceID: wsID,
		TokenHash:   hashToken(tokenStr),
		CreatedAt:   time.Now(),
	}
	if err := a.store.CreateToken(token); err != nil {
		return "", fmt.Errorf("failed to create token: %w", err)
	}

	return tokenStr, nil
}

// ValidateToken checks a bearer token and returns the workspace ID.
func (a *Auth) ValidateToken(token string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("missing token")
	}
	hash := hashToken(token)
	t, ok := a.store.GetTokenByHash(hash)
	if !ok {
		return "", fmt.Errorf("invalid token")
	}
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return "", fmt.Errorf("token expired")
	}
	return t.WorkspaceID, nil
}

func (a *Auth) sendEmail(to, code string) error {
	subject := "Your jwtkit verification code"
	body := fmt.Sprintf("Your verification code is: %s\n\nThis code expires in 10 minutes.", code)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		a.cfg.SMTPFrom, to, subject, body)

	addr := fmt.Sprintf("%s:%d", a.cfg.SMTPHost, a.cfg.SMTPPort)
	var auth smtp.Auth
	if a.cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", a.cfg.SMTPUser, a.cfg.SMTPPass, a.cfg.SMTPHost)
	}
	if err := smtp.SendMail(addr, auth, a.cfg.SMTPFrom, []string{to}, []byte(msg)); err != nil {
		log.Printf("SMTP error: %v", err)
		return err
	}
	return nil
}

func generateOTPCode() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "000000"
	}
	code := make([]byte, 6)
	for i := range b {
		code[i] = '0' + (b[i] % 10)
	}
	return string(code)
}

func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString(b) // fallback
	}
	return hex.EncodeToString(b)
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

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
