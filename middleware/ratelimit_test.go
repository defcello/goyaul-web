package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defcello/goyaul-web/auth"
)

// okHandler is a trivial handler that returns 200.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// postWithSession builds a POST request with the given userID in the context.
func postWithSession(userID int) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/account/displayname", nil)
	return r.WithContext(WithSession(r.Context(), &auth.SessionRecord{UserID: userID}))
}

func getWithSession(userID int) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/account", nil)
	return r.WithContext(WithSession(r.Context(), &auth.SessionRecord{UserID: userID}))
}

func TestNewUserRateLimit_AllowsUnderLimit(t *testing.T) {
	mw := NewUserRateLimit(3, time.Minute)
	h := mw(okHandler)

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, postWithSession(1))
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, w.Code)
		}
	}
}

func TestNewUserRateLimit_BlocksOverLimit(t *testing.T) {
	mw := NewUserRateLimit(3, time.Minute)
	h := mw(okHandler)

	for i := 0; i < 3; i++ {
		h.ServeHTTP(httptest.NewRecorder(), postWithSession(1))
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, postWithSession(1))
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("got %d, want 429", w.Code)
	}
}

func TestNewUserRateLimit_SeparatesUsers(t *testing.T) {
	mw := NewUserRateLimit(1, time.Minute)
	h := mw(okHandler)

	// Exhaust user 1.
	h.ServeHTTP(httptest.NewRecorder(), postWithSession(1))

	// User 2 should still be allowed.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, postWithSession(2))
	if w.Code != http.StatusOK {
		t.Errorf("user 2 got %d, want 200", w.Code)
	}

	// User 1 should be blocked.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, postWithSession(1))
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("user 1 got %d, want 429", w.Code)
	}
}

func TestNewUserRateLimit_GetNotRateLimited(t *testing.T) {
	mw := NewUserRateLimit(0, time.Minute) // max=0 would block any POST
	h := mw(okHandler)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, getWithSession(1))
	if w.Code != http.StatusOK {
		t.Errorf("GET got %d, want 200 (GET should never be rate limited)", w.Code)
	}
}

func TestNewUserRateLimit_WindowExpiry(t *testing.T) {
	mw := NewUserRateLimit(1, 50*time.Millisecond)
	h := mw(okHandler)

	// Use up the single slot.
	h.ServeHTTP(httptest.NewRecorder(), postWithSession(1))

	// Wait for the window to expire.
	time.Sleep(60 * time.Millisecond)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, postWithSession(1))
	if w.Code != http.StatusOK {
		t.Errorf("after window expiry got %d, want 200", w.Code)
	}
}

func TestNewUserRateLimit_NoSessionPassesThrough(t *testing.T) {
	mw := NewUserRateLimit(0, time.Minute)
	h := mw(okHandler)

	r := httptest.NewRequest(http.MethodPost, "/account/displayname", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	// No session → pass through (RequireAuth handles the redirect elsewhere).
	if w.Code != http.StatusOK {
		t.Errorf("unauthenticated POST got %d, want 200 (middleware should pass through)", w.Code)
	}
}
