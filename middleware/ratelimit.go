package middleware

import (
	"net/http"
	"sync"
	"time"
)

type userRateLimiter struct {
	mu      sync.Mutex
	records map[int][]time.Time
	max     int
	window  time.Duration
}

// allow returns true if the user is within the rate limit and records the attempt.
func (l *userRateLimiter) allow(userID int) bool {
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	times := l.records[userID]
	// Evict timestamps outside the window.
	j := 0
	for _, t := range times {
		if t.After(cutoff) {
			times[j] = t
			j++
		}
	}
	times = times[:j]

	if len(times) >= l.max {
		l.records[userID] = times
		return false
	}

	l.records[userID] = append(times, now)
	return true
}

// NewUserRateLimit returns a middleware that limits POST requests from authenticated
// users to maxRequests within window. GET requests and unauthenticated requests pass
// through unchanged (apply RequireAuth before this middleware to block unauthenticated
// users). Returns 429 Too Many Requests when the limit is exceeded.
func NewUserRateLimit(maxRequests int, window time.Duration) func(http.Handler) http.Handler {
	l := &userRateLimiter{
		records: make(map[int][]time.Time),
		max:     maxRequests,
		window:  window,
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				session := SessionFromContext(r.Context())
				if session != nil && !l.allow(session.UserID) {
					http.Error(w, "Too many requests. Please try again later.", http.StatusTooManyRequests)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
