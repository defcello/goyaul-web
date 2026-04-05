package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
)

// SetFlash stores a one-time HMAC-SHA256-signed message in a short-lived cookie.
// The cookie value is formatted as base64url(msg).base64url(hmac).
// key is the HMAC signing key. secure controls the Secure cookie flag.
func SetFlash(w http.ResponseWriter, key []byte, msg string, secure bool) {
	signed := signFlash(key, msg)
	http.SetCookie(w, &http.Cookie{
		Name:     "flash",
		Value:    signed,
		Path:     "/",
		MaxAge:   10,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ConsumeFlash reads the flash cookie, verifies its HMAC, clears the cookie,
// and returns the message. Returns "" if the cookie is absent or its HMAC is invalid.
func ConsumeFlash(w http.ResponseWriter, r *http.Request, key []byte) string {
	cookie, err := r.Cookie("flash")
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "flash",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	return verifyFlash(key, cookie.Value)
}

// signFlash returns base64url(msg).base64url(hmac-sha256(msg)).
func signFlash(key []byte, msg string) string {
	mac := computeHMAC(key, msg)
	b64msg := base64.RawURLEncoding.EncodeToString([]byte(msg))
	b64mac := base64.RawURLEncoding.EncodeToString(mac)
	return b64msg + "." + b64mac
}

// verifyFlash parses and verifies a signed flash value, returning the original
// message on success or "" if the value is malformed or the HMAC does not match.
func verifyFlash(key []byte, signed string) string {
	dot := strings.LastIndex(signed, ".")
	if dot < 0 {
		return ""
	}
	rawMsg, err := base64.RawURLEncoding.DecodeString(signed[:dot])
	if err != nil {
		return ""
	}
	gotMAC, err := base64.RawURLEncoding.DecodeString(signed[dot+1:])
	if err != nil {
		return ""
	}
	expected := computeHMAC(key, string(rawMsg))
	if !hmac.Equal(gotMAC, expected) {
		return ""
	}
	return string(rawMsg)
}

func computeHMAC(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}
