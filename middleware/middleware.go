package middleware

import (
	"context"
	"log"
	"net/http"
	"strconv"
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
		next.ServeHTTP(w, r)
	})
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

// SessionFromContext retrieves the SessionRecord from the request context, or nil.
func SessionFromContext(ctx context.Context) *auth.SessionRecord {
	v, _ := ctx.Value(ctxKeySession).(*auth.SessionRecord)
	return v
}

// WithSession returns a copy of ctx with the session attached. Intended for tests.
func WithSession(ctx context.Context, s *auth.SessionRecord) context.Context {
	return context.WithValue(ctx, ctxKeySession, s)
}
