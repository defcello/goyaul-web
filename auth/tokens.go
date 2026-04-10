package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// GenerateToken creates a cryptographically random 32-byte token.
//
// It returns:
//   - plaintext: base64url-encoded (no padding) form safe for use in URLs.
//   - hash: SHA-256 of the raw bytes, intended for storage in the database.
//     The raw plaintext is never persisted; storing only the hash means a
//     database read does not hand an attacker a working token.
func GenerateToken() (plaintext string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("auth: generate token: %w", err)
	}
	pt := base64.RawURLEncoding.EncodeToString(raw)
	h := sha256.Sum256(raw)
	return pt, h[:], nil
}

// HashToken returns the SHA-256 hash of a base64url-encoded plaintext token.
// Use this when verifying a token presented by the user against a stored hash.
func HashToken(plaintext string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(plaintext)
	if err != nil {
		return nil, fmt.Errorf("auth: hash token: %w", err)
	}
	h := sha256.Sum256(raw)
	return h[:], nil
}
