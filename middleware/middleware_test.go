package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders_SetsHSTSForHTTPSRequests(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/account", nil)
	req.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()

	SecurityHeaders(okHandler).ServeHTTP(w, req)

	if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=63072000; includeSubDomains" {
		t.Fatalf("Strict-Transport-Security = %q, want HSTS header", got)
	}
}

func TestSecurityHeaders_SetsHSTSForForwardedHTTPSRequests(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/account", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	SecurityHeaders(okHandler).ServeHTTP(w, req)

	if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=63072000; includeSubDomains" {
		t.Fatalf("Strict-Transport-Security = %q, want HSTS header", got)
	}
}

func TestSecurityHeaders_SkipsHSTSForPlainHTTP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/account", nil)
	w := httptest.NewRecorder()

	SecurityHeaders(okHandler).ServeHTTP(w, req)

	if got := w.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("Strict-Transport-Security = %q, want empty", got)
	}
}

func TestEnforceHTTPS_RedirectsPlainHTTPRequests(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/account?tab=sessions", nil)
	w := httptest.NewRecorder()

	EnforceHTTPS(true)(okHandler).ServeHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusMovedPermanently)
	}
	if got := w.Header().Get("Location"); got != "https://example.com/account?tab=sessions" {
		t.Fatalf("Location = %q, want redirected https URL", got)
	}
}

func TestEnforceHTTPS_AllowsForwardedHTTPSRequests(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/account", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	EnforceHTTPS(true)(okHandler).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestEnforceHTTPS_SkipsLocalhost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/account", nil)
	w := httptest.NewRecorder()

	EnforceHTTPS(true)(okHandler).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}
