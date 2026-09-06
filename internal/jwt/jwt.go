package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Algorithm is a JWT signing algorithm.
type Algorithm string

const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
)

// ValidAlgorithm reports whether alg is a supported algorithm.
func ValidAlgorithm(alg string) bool {
	switch Algorithm(alg) {
	case HS256, HS384, HS512, RS256, RS384, RS512:
		return true
	}
	return false
}

// IsHMAC returns true for HMAC-based algorithms.
func IsHMAC(alg Algorithm) bool {
	switch alg {
	case HS256, HS384, HS512:
		return true
	}
	return false
}

// IsRSA returns true for RSA-based algorithms.
func IsRSA(alg Algorithm) bool {
	switch alg {
	case RS256, RS384, RS512:
		return true
	}
	return false
}

func b64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func b64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func hashFor(alg Algorithm) (crypto.Hash, error) {
	switch alg {
	case HS256, RS256:
		return crypto.SHA256, nil
	case HS384, RS384:
		return crypto.SHA384, nil
	case HS512, RS512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// Sign creates a signed JWT from the given claims.
// For HMAC algorithms, key must be []byte.
// For RSA algorithms, key must be *rsa.PrivateKey.
func Sign(alg Algorithm, claims map[string]interface{}, key interface{}) (string, error) {
	header := map[string]interface{}{
		"alg": string(alg),
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	signingInput := b64Encode(headerJSON) + "." + b64Encode(payloadJSON)

	var sig []byte
	switch alg {
	case HS256:
		secret, ok := key.([]byte)
		if !ok {
			return "", errors.New("HS256 requires a []byte secret")
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(signingInput))
		sig = mac.Sum(nil)
	case HS384:
		secret, ok := key.([]byte)
		if !ok {
			return "", errors.New("HS384 requires a []byte secret")
		}
		mac := hmac.New(sha512.New384, secret)
		mac.Write([]byte(signingInput))
		sig = mac.Sum(nil)
	case HS512:
		secret, ok := key.([]byte)
		if !ok {
			return "", errors.New("HS512 requires a []byte secret")
		}
		mac := hmac.New(sha512.New, secret)
		mac.Write([]byte(signingInput))
		sig = mac.Sum(nil)
	case RS256, RS384, RS512:
		privKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("%s requires an *rsa.PrivateKey", alg)
		}
		h, err := hashFor(alg)
		if err != nil {
			return "", err
		}
		hasher := h.New()
		hasher.Write([]byte(signingInput))
		sig, err = rsa.SignPKCS1v15(rand.Reader, privKey, h, hasher.Sum(nil))
		if err != nil {
			return "", fmt.Errorf("rsa sign: %w", err)
		}
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}

	return signingInput + "." + b64Encode(sig), nil
}

// Verify checks the signature of a JWT and returns its claims.
// For HMAC algorithms, key must be []byte.
// For RSA algorithms, key must be *rsa.PublicKey.
// It also validates the exp, nbf, and iat claims if present.
func Verify(token string, alg Algorithm, key interface{}) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token must have exactly 3 parts separated by dots")
	}

	signingInput := parts[0] + "." + parts[1]
	sig, err := b64Decode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Decode header to verify algorithm
	headerBytes, err := b64Decode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid header encoding: %w", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid header JSON: %w", err)
	}
	headerAlg, _ := header["alg"].(string)
	if headerAlg != string(alg) {
		return nil, fmt.Errorf("algorithm mismatch: header says %s, expected %s", headerAlg, alg)
	}

	// Verify signature
	switch alg {
	case HS256:
		secret, ok := key.([]byte)
		if !ok {
			return nil, errors.New("HS256 requires a []byte secret")
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(signingInput))
		if !hmac.Equal(sig, mac.Sum(nil)) {
			return nil, errors.New("signature mismatch")
		}
	case HS384:
		secret, ok := key.([]byte)
		if !ok {
			return nil, errors.New("HS384 requires a []byte secret")
		}
		mac := hmac.New(sha512.New384, secret)
		mac.Write([]byte(signingInput))
		if !hmac.Equal(sig, mac.Sum(nil)) {
			return nil, errors.New("signature mismatch")
		}
	case HS512:
		secret, ok := key.([]byte)
		if !ok {
			return nil, errors.New("HS512 requires a []byte secret")
		}
		mac := hmac.New(sha512.New, secret)
		mac.Write([]byte(signingInput))
		if !hmac.Equal(sig, mac.Sum(nil)) {
			return nil, errors.New("signature mismatch")
		}
	case RS256, RS384, RS512:
		pubKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%s requires an *rsa.PublicKey", alg)
		}
		h, err := hashFor(alg)
		if err != nil {
			return nil, err
		}
		hasher := h.New()
		hasher.Write([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(pubKey, h, hasher.Sum(nil), sig); err != nil {
			return nil, fmt.Errorf("signature verification failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}

	// Decode payload
	payloadBytes, err := b64Decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("invalid payload JSON: %w", err)
	}

	// Validate time-based claims
	now := time.Now()
	if exp, ok := claims["exp"]; ok {
		if t, err := parseTimeClaim(exp); err == nil && now.After(t) {
			return nil, errors.New("token is expired")
		}
	}
	if nbf, ok := claims["nbf"]; ok {
		if t, err := parseTimeClaim(nbf); err == nil && now.Before(t) {
			return nil, errors.New("token is not yet valid")
		}
	}

	return claims, nil
}

// Decode reads the header and payload of a JWT without verifying the signature.
func Decode(token string) (header, payload map[string]interface{}, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("token must have exactly 3 parts separated by dots")
	}

	headerBytes, err := b64Decode(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid header encoding: %w", err)
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("invalid header JSON: %w", err)
	}

	payloadBytes, err := b64Decode(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid payload encoding: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, fmt.Errorf("invalid payload JSON: %w", err)
	}

	return header, payload, nil
}

// GenerateRSAKeyPair creates a new RSA private/public key pair.
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// EncodePrivateKeyPEM converts an RSA private key to PEM format.
func EncodePrivateKeyPEM(key *rsa.PrivateKey) string {
	der := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}))
}

// EncodePublicKeyPEM converts an RSA public key to PEM format.
func EncodePublicKeyPEM(key *rsa.PublicKey) string {
	der := x509.MarshalPKCS1PublicKey(key)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: der,
	}))
}

// ParsePrivateKeyPEM parses a PEM-encoded RSA private key.
func ParsePrivateKeyPEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ParsePublicKeyPEM parses a PEM-encoded RSA public key.
func ParsePublicKeyPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func parseTimeClaim(v interface{}) (time.Time, error) {
	switch t := v.(type) {
	case float64:
		return time.Unix(int64(t), 0), nil
	case int64:
		return time.Unix(t, 0), nil
	case int:
		return time.Unix(int64(t), 0), nil
	case string:
		// Try numeric string
		var n float64
		if _, err := fmt.Sscanf(t, "%f", &n); err == nil {
			return time.Unix(int64(n), 0), nil
		}
		// Try RFC3339
		return time.Parse(time.RFC3339, t)
	}
	return time.Time{}, fmt.Errorf("cannot parse time claim: %v", v)
}
