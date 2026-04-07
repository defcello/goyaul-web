package middleware

import (
	"context"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/defcello/goyaul-web/auth"
)

// contextKey is a private type to avoid context key collisions.
type contextKey int

const ctxKeySession contextKey = iota

// SessionDB is the subset of the database required by LoadSession.
type SessionDB interface {
	GetSessionByCookieID(ctx context.Context, cookieID int64) (*auth.SessionRecord, error)
	TouchSession(ctx context.Context, sessionID int) error
}

// SecurityHeaders sets defensive HTTP response headers on every request.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if isHTTPSRequest(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// EnforceHTTPS redirects plaintext requests to HTTPS when enabled.
// Local development hosts such as localhost and loopback addresses are excluded.
func EnforceHTTPS(enabled bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if !enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isHTTPSRequest(r) || isLocalhostHost(r.Host) {
				next.ServeHTTP(w, r)
				return
			}
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})
	}
}

func isHTTPSRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	forwardedProto := r.Header.Get("X-Forwarded-Proto")
	if forwardedProto == "" {
		return false
	}
	firstValue := strings.TrimSpace(strings.ToLower(strings.Split(forwardedProto, ",")[0]))
	return firstValue == "https"
}

func isLocalhostHost(hostport string) bool {
	host := hostport
	if parsedHost, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsedHost
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	host = strings.ToLower(host)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// responseRecorder wraps http.ResponseWriter to capture the written status code.
type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.status = code
	rr.ResponseWriter.WriteHeader(code)
}

func (rr *responseRecorder) statusOrDefault() int {
	if rr.status == 0 {
		return http.StatusOK
	}
	return rr.status
}

// RequestLogger logs each request with method, path, status, and duration.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.statusOrDefault(), time.Since(start))
	})
}

// LoadSession reads the session cookie, validates it against the DB, and
// attaches the SessionRecord to the request context when valid.
// cookieName is the name of the session cookie to read.
func LoadSession(cookieName string, d SessionDB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cookieName)
			if err == nil {
				cookieID, err := strconv.ParseInt(cookie.Value, 10, 64)
				if err == nil {
					session, err := d.GetSessionByCookieID(r.Context(), cookieID)
					if err == nil {
						r = r.WithContext(context.WithValue(r.Context(), ctxKeySession, session))
						_ = d.TouchSession(r.Context(), session.SessionID)
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAuth redirects to /login if no valid session is present in the context.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if SessionFromContext(r.Context()) == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePrivilege returns a middleware that checks whether the authenticated
// session holds the given privilege. If no session is present or the privilege
// is denied, the request is redirected to redirectURL.
// It calls auth.CheckPrivilege, which logs the decision to the audit log.
func RequirePrivilege(d auth.PrivilegeDB, privilegePath []string, redirectURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session := SessionFromContext(r.Context())
			if session == nil {
				http.Redirect(w, r, redirectURL, http.StatusFound)
				return
			}
			allowed, err := auth.CheckPrivilege(r.Context(), d, session, privilegePath, func(logErr error) {
				log.Printf("privilege log write failed: %v", logErr)
			})
			if err != nil || !allowed {
				http.Redirect(w, r, redirectURL, http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SessionFromContext retrieves the SessionRecord from the request context, or nil.
func SessionFromContext(ctx context.Context) *auth.SessionRecord {
	v, _ := ctx.Value(ctxKeySession).(*auth.SessionRecord)
	return v
}

// WithSession returns a copy of ctx with the session attached. Intended for tests.
func WithSession(ctx context.Context, s *auth.SessionRecord) context.Context {
	return context.WithValue(ctx, ctxKeySession, s)
}
