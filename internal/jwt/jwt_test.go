package jwt

import (
	"testing"
	"time"
)

func TestHMACSignVerify(t *testing.T) {
	secret := []byte("mysecret")
	claims := map[string]interface{}{
		"sub": "user123",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat": float64(time.Now().Unix()),
	}

	for _, alg := range []Algorithm{HS256, HS384, HS512} {
		token, err := Sign(alg, claims, secret)
		if err != nil {
			t.Fatalf("%s: Sign failed: %v", alg, err)
		}
		if token == "" {
			t.Fatalf("%s: token is empty", alg)
		}

		verified, err := Verify(token, alg, secret)
		if err != nil {
			t.Fatalf("%s: Verify failed: %v", alg, err)
		}
		if verified["sub"] != "user123" {
			t.Fatalf("%s: expected sub=user123, got %v", alg, verified["sub"])
		}
	}
}

func TestRSASignVerify(t *testing.T) {
	privKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}

	claims := map[string]interface{}{
		"sub": "user456",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	for _, alg := range []Algorithm{RS256, RS384, RS512} {
		token, err := Sign(alg, claims, privKey)
		if err != nil {
			t.Fatalf("%s: Sign failed: %v", alg, err)
		}

		verified, err := Verify(token, alg, &privKey.PublicKey)
		if err != nil {
			t.Fatalf("%s: Verify failed: %v", alg, err)
		}
		if verified["sub"] != "user456" {
			t.Fatalf("%s: expected sub=user456, got %v", alg, verified["sub"])
		}
	}
}

func TestVerifyExpired(t *testing.T) {
	secret := []byte("mysecret")
	claims := map[string]interface{}{
		"sub": "user789",
		"exp": float64(time.Now().Add(-1 * time.Hour).Unix()),
	}

	token, err := Sign(HS256, claims, secret)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	_, err = Verify(token, HS256, secret)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestVerifyWrongSecret(t *testing.T) {
	secret := []byte("mysecret")
	wrongSecret := []byte("wrongsecret")
	claims := map[string]interface{}{
		"sub": "user000",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	token, err := Sign(HS256, claims, secret)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	_, err = Verify(token, HS256, wrongSecret)
	if err == nil {
		t.Fatal("expected error for wrong secret, got nil")
	}
}

func TestDecode(t *testing.T) {
	secret := []byte("mysecret")
	claims := map[string]interface{}{
		"sub": "decode_test",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	token, err := Sign(HS256, claims, secret)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	header, payload, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if header["alg"] != "HS256" {
		t.Fatalf("expected alg=HS256, got %v", header["alg"])
	}
	if payload["sub"] != "decode_test" {
		t.Fatalf("expected sub=decode_test, got %v", payload["sub"])
	}
}

func TestValidAlgorithm(t *testing.T) {
	if !ValidAlgorithm("HS256") {
		t.Error("HS256 should be valid")
	}
	if !ValidAlgorithm("RS512") {
		t.Error("RS512 should be valid")
	}
	if ValidAlgorithm("none") {
		t.Error("none should be invalid")
	}
}

func TestRSAKeyPairPEM(t *testing.T) {
	privKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}

	privPEM := EncodePrivateKeyPEM(privKey)
	pubPEM := EncodePublicKeyPEM(&privKey.PublicKey)

	if privPEM == "" || pubPEM == "" {
		t.Fatal("PEM strings should not be empty")
	}

	parsedPriv, err := ParsePrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM failed: %v", err)
	}
	if parsedPriv.N.Cmp(privKey.N) != 0 {
		t.Error("parsed private key does not match original")
	}

	parsedPub, err := ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM failed: %v", err)
	}
	if parsedPub.N.Cmp(privKey.N) != 0 {
		t.Error("parsed public key does not match original")
	}
}

func TestVerifyNotYetValid(t *testing.T) {
	secret := []byte("mysecret")
	claims := map[string]interface{}{
		"sub": "future_user",
		"nbf": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	token, err := Sign(HS256, claims, secret)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	_, err = Verify(token, HS256, secret)
	if err == nil {
		t.Fatal("expected error for not-yet-valid token, got nil")
	}
}

func TestAlgorithmMismatch(t *testing.T) {
	secret := []byte("mysecret")
	claims := map[string]interface{}{
		"sub": "mismatch_test",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	token, err := Sign(HS256, claims, secret)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Try to verify with HS384 — should fail due to algorithm mismatch
	_, err = Verify(token, HS384, secret)
	if err == nil {
		t.Fatal("expected error for algorithm mismatch, got nil")
	}
}
