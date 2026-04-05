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

// PrivilegeLogParams is the input to LogPrivilegeCheck.
type PrivilegeLogParams struct {
	SessionID   int
	PrivilegeID int
	// AllowRuleID is the table_privilege_group_allow.id of the winning rule,
	// or nil when the deny was implicit (no matching rule existed).
	AllowRuleID *int
	Allowed     bool
}

// PrivilegeDB is the subset of database methods required by CheckPrivilege.
type PrivilegeDB interface {
	// FindPrivilegeID returns the database ID for the privilege at the given path.
	// The path is ordered from root to leaf, e.g. ["sudo", "users", "read"].
	// Returns ErrNotFound when no matching privilege exists.
	FindPrivilegeID(ctx context.Context, path []string) (int, error)
	// UserHasPrivilegeWithRule reports whether userID holds the privilege identified
	// by privilegeID, and returns the table_privilege_group_allow.id of the winning
	// rule (nil when the deny is implicit — no rule matched).
	UserHasPrivilegeWithRule(ctx context.Context, userID, privilegeID int) (bool, *int, error)
	// LogPrivilegeCheck writes a privilege check event to the audit log.
	LogPrivilegeCheck(ctx context.Context, params PrivilegeLogParams) error
}

// CheckPrivilege reports whether the session user holds the privilege at
// privilegePath and writes an audit-log entry. It mirrors PyYAUL.Web's
// ancestor fallback: if the exact path is not found it retries with
// progressively shorter ancestor paths until a match is found or the
// path is exhausted (in which case it returns false without logging).
//
// onLogErr, if provided, is called when the audit-log write fails. The
// privilege decision is returned regardless — a log failure never blocks
// the request. Pass a function that routes the error to your own logger
// or monitoring system (e.g. log.Printf).
func CheckPrivilege(ctx context.Context, d PrivilegeDB, session *SessionRecord, privilegePath []string, onLogErr ...func(error)) (bool, error) {
	// Find the most-specific matching privilege, falling back to ancestors.
	privilegeID := 0
	for i := len(privilegePath); i > 0; i-- {
		id, err := d.FindPrivilegeID(ctx, privilegePath[:i])
		if err == nil {
			privilegeID = id
			break
		}
		if !errors.Is(err, ErrNotFound) {
			return false, err
		}
	}
	if privilegeID == 0 {
		// No matching privilege at any level — deny silently (nothing to log).
		return false, nil
	}

	allowed, ruleID, err := d.UserHasPrivilegeWithRule(ctx, session.UserID, privilegeID)
	if err != nil {
		return false, err
	}
	if logErr := d.LogPrivilegeCheck(ctx, PrivilegeLogParams{
		SessionID:   session.SessionID,
		PrivilegeID: privilegeID,
		AllowRuleID: ruleID,
		Allowed:     allowed,
	}); logErr != nil && len(onLogErr) > 0 {
		onLogErr[0](logErr)
	}
	return allowed, nil
}
