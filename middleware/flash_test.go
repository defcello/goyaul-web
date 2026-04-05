package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetAndConsumeFlash(t *testing.T) {
	key := []byte("test-signing-key")
	msg := "Display name updated."

	// Set the flash cookie in a response.
	w := httptest.NewRecorder()
	SetFlash(w, key, msg, false)

	// Extract the cookie from the response and build a request that carries it.
	resp := w.Result()
	cookies := resp.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "flash" {
		t.Fatalf("expected one flash cookie, got %v", cookies)
	}
	if cookies[0].Value == msg {
		t.Error("cookie value should be signed, not plain-text")
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookies[0])

	// Consume the flash in a new response.
	w2 := httptest.NewRecorder()
	got := ConsumeFlash(w2, r, key)
	if got != msg {
		t.Errorf("ConsumeFlash = %q, want %q", got, msg)
	}

	// Consuming again (no cookie) returns "".
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	w3 := httptest.NewRecorder()
	if ConsumeFlash(w3, r2, key) != "" {
		t.Error("expected empty string when no flash cookie")
	}
}

func TestConsumeFlash_TamperedValue(t *testing.T) {
	key := []byte("test-signing-key")

	w := httptest.NewRecorder()
	ConsumeFlash(w, requestWithFlashCookie("tampered.invalidsig"), key)

	r := requestWithFlashCookie("tampered.invalidsig")
	w2 := httptest.NewRecorder()
	got := ConsumeFlash(w2, r, key)
	if got != "" {
		t.Errorf("expected empty string for tampered cookie, got %q", got)
	}
}

func TestConsumeFlash_WrongKey(t *testing.T) {
	key1 := []byte("key-one")
	key2 := []byte("key-two")
	msg := "hello"

	w := httptest.NewRecorder()
	SetFlash(w, key1, msg, false)
	cookie := w.Result().Cookies()[0]

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookie)
	w2 := httptest.NewRecorder()
	got := ConsumeFlash(w2, r, key2)
	if got != "" {
		t.Errorf("expected empty string when verifying with wrong key, got %q", got)
	}
}

func TestConsumeFlash_NoCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	if ConsumeFlash(w, r, []byte("key")) != "" {
		t.Error("expected empty string with no cookie")
	}
}

func requestWithFlashCookie(value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "flash", Value: value})
	return r
}
