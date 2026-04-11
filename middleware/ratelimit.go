package middleware

import (
	"net"
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

func newUserRateLimiter(maxRequests int, window time.Duration) *userRateLimiter {
	l := &userRateLimiter{
		records: make(map[int][]time.Time),
		max:     maxRequests,
		window:  window,
	}
	go l.pruneLoop()
	return l
}

func (l *userRateLimiter) pruneLoop() {
	ticker := time.NewTicker(l.window)
	defer ticker.Stop()

	for range ticker.C {
		l.pruneStale(time.Now().Add(-l.window))
	}
}

func (l *userRateLimiter) pruneStale(cutoff time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for userID, times := range l.records {
		if len(times) == 0 || times[len(times)-1].Before(cutoff) {
			delete(l.records, userID)
		}
	}
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

type ipRateLimiter struct {
	mu      sync.Mutex
	records map[string][]time.Time
	max     int
	window  time.Duration
}

func newIPRateLimiter(maxRequests int, window time.Duration) *ipRateLimiter {
	l := &ipRateLimiter{
		records: make(map[string][]time.Time),
		max:     maxRequests,
		window:  window,
	}
	go l.pruneLoop()
	return l
}

func (l *ipRateLimiter) pruneLoop() {
	ticker := time.NewTicker(l.window)
	defer ticker.Stop()

	for range ticker.C {
		l.pruneStale(time.Now().Add(-l.window))
	}
}

func (l *ipRateLimiter) pruneStale(cutoff time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for ip, times := range l.records {
		if len(times) == 0 || times[len(times)-1].Before(cutoff) {
			delete(l.records, ip)
		}
	}
}

// allow returns true if the IP is within the rate limit and records the attempt.
func (l *ipRateLimiter) allow(ip string) bool {
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	times := l.records[ip]
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
		l.records[ip] = times
		return false
	}

	l.records[ip] = append(times, now)
	return true
}

// ipFromAddr strips the port from a host:port address, returning just the host.
func ipFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// NewIPRateLimit returns a middleware that limits POST requests from a given remote IP
// to maxRequests within window. GET requests pass through unchanged.
// Returns 429 Too Many Requests when the limit is exceeded.
// Note: uses r.RemoteAddr — place behind a trusted reverse proxy if X-Forwarded-For handling is needed.
func NewIPRateLimit(maxRequests int, window time.Duration) func(http.Handler) http.Handler {
	l := newIPRateLimiter(maxRequests, window)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				ip := ipFromAddr(r.RemoteAddr)
				if !l.allow(ip) {
					http.Error(w, "Too many requests. Please try again later.", http.StatusTooManyRequests)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// NewUserRateLimit returns a middleware that limits POST requests from authenticated
// users to maxRequests within window. GET requests and unauthenticated requests pass
// through unchanged (apply RequireAuth before this middleware to block unauthenticated
// users). Returns 429 Too Many Requests when the limit is exceeded.
func NewUserRateLimit(maxRequests int, window time.Duration) func(http.Handler) http.Handler {
	l := newUserRateLimiter(maxRequests, window)
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
