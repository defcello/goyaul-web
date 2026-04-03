package auth

import (
	"context"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("db: not found")

// SessionRecord holds the data attached to an authenticated request context.
type SessionRecord struct {
	SessionID   int
	CookieID    int64
	UserID      int
	Username    string
	NameDisplay string
	RememberMe  bool
	LastActive  *time.Time
}

// UserLookupResult is the result of FindUserByEmailOrUsername.
type UserLookupResult struct {
	ID             int
	IsLoginEnabled bool
	IsDisabled     bool
	Unlocked       *time.Time
}

// LogLoginParams is the input to LogLoginAttempt.
type LogLoginParams struct {
	UserID        *int
	LoginMethodID int
	IsSuccess     bool
	SessionID     *int
	LockedUntil   *time.Time
	IP            string
	UserAgent     string
}

const (
	loginMaxConsecutiveFailures = 5
	loginFailureDelay           = 500 * time.Millisecond
	ipRateWindowSeconds         = 300 // 5-minute sliding window
	ipRateMaxAttempts           = 20
)

// lockoutDurationsMinutes mirrors the escalating durations in PyYAUL.Web.
var lockoutDurationsMinutes = []int{5, 30, 120, 1440}

// LoginResult is the outcome of a Login() call.
type LoginResult struct {
	Session     *SessionRecord
	ErrMessage  string
	RateLimited bool
}

// LoginDB is the subset of database methods required by Login.
// Implement this interface against any database to use the login flow.
type LoginDB interface {
	CountIPLoginAttemptsInWindow(ctx context.Context, ip string, windowSeconds int64) (int, error)
	FindUserByEmailOrUsername(ctx context.Context, input string) (*UserLookupResult, error)
	LogLoginAttempt(ctx context.Context, params LogLoginParams) error
	LoginMethodIDPassword() int
	GetPasswordHash(ctx context.Context, userID int) (string, error)
	CountConsecutiveFailures(ctx context.Context, userID int) (int, error)
	CountLockouts(ctx context.Context, userID int) (int, error)
	SetUserUnlocked(ctx context.Context, userID int, unlockAt *time.Time) error
	CreateSession(ctx context.Context, userID int, rememberMe bool) (*SessionRecord, error)
}

// Login validates credentials against the database and returns a session on success.
// It mirrors the full login flow in PyYAUL.Web including lockout escalation
// and the 0.5s failure delay.
func Login(
	ctx context.Context,
	d LoginDB,
	ip, userAgent, usernameOrEmail, password string,
	rememberMe bool,
) LoginResult {
	// 1. IP rate limit.
	ipCount, err := d.CountIPLoginAttemptsInWindow(ctx, ip, ipRateWindowSeconds)
	if err != nil || ipCount >= ipRateMaxAttempts {
		return LoginResult{
			RateLimited: true,
			ErrMessage:  "Too many login attempts from your network. Please wait a few minutes before trying again.",
		}
	}

	// 2. User lookup.
	user, lookupErr := d.FindUserByEmailOrUsername(ctx, usernameOrEmail)

	// 3. Pre-flight checks (only when user found).
	var preflightFailed bool
	if lookupErr == nil {
		switch {
		case !user.IsLoginEnabled:
			preflightFailed = true
		case user.IsDisabled:
			preflightFailed = true
		case user.Unlocked != nil && user.Unlocked.After(time.Now().UTC()):
			preflightFailed = true
		}
	}

	if lookupErr != nil || preflightFailed {
		// Log a failed attempt (no user_id when lookup failed).
		var uid *int
		if lookupErr == nil {
			id := user.ID
			uid = &id
		}
		_ = d.LogLoginAttempt(ctx, LogLoginParams{
			UserID:        uid,
			LoginMethodID: d.LoginMethodIDPassword(),
			IsSuccess:     false,
			IP:            ip,
			UserAgent:     userAgent,
		})
		time.Sleep(loginFailureDelay)
		return failResult()
	}

	// 4. Password check.
	hash, err := d.GetPasswordHash(ctx, user.ID)
	if err != nil {
		time.Sleep(loginFailureDelay)
		return failResult()
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		// Password wrong — apply lockout logic.
		var lockoutTime *time.Time
		alreadyLocked := user.Unlocked != nil && user.Unlocked.After(time.Now().UTC())
		if !alreadyLocked {
			consecutive, _ := d.CountConsecutiveFailures(ctx, user.ID)
			// +1 to account for the attempt we are about to log.
			if consecutive+1 >= loginMaxConsecutiveFailures {
				priorLockouts, _ := d.CountLockouts(ctx, user.ID)
				idx := priorLockouts
				if idx >= len(lockoutDurationsMinutes) {
					idx = len(lockoutDurationsMinutes) - 1
				}
				t := time.Now().UTC().Add(time.Duration(lockoutDurationsMinutes[idx]) * time.Minute)
				lockoutTime = &t
				_ = d.SetUserUnlocked(ctx, user.ID, lockoutTime)
			}
		}
		uid := user.ID
		_ = d.LogLoginAttempt(ctx, LogLoginParams{
			UserID:        &uid,
			LoginMethodID: d.LoginMethodIDPassword(),
			IsSuccess:     false,
			LockedUntil:   lockoutTime,
			IP:            ip,
			UserAgent:     userAgent,
		})
		time.Sleep(loginFailureDelay)
		return failResult()
	}

	// 5. Success — create session.
	session, err := d.CreateSession(ctx, user.ID, rememberMe)
	if err != nil {
		return LoginResult{ErrMessage: "An internal error occurred. Please try again."}
	}
	sessionID := session.SessionID
	uid := user.ID
	_ = d.LogLoginAttempt(ctx, LogLoginParams{
		UserID:        &uid,
		LoginMethodID: d.LoginMethodIDPassword(),
		IsSuccess:     true,
		SessionID:     &sessionID,
		IP:            ip,
		UserAgent:     userAgent,
	})
	return LoginResult{Session: session}
}

func failResult() LoginResult {
	return LoginResult{
		ErrMessage: "The provided login details could not be verified. Please check your details and try again.",
	}
}
