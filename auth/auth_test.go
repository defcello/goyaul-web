package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// stubDB implements LoginDB using function fields.
// A nil field panics if unexpectedly called — this flags surprising code paths.
type stubDB struct {
	countIPFn         func(ctx context.Context, ip string, windowSeconds int64) (int, error)
	findUserFn        func(ctx context.Context, input string) (*UserLookupResult, error)
	logAttemptFn      func(ctx context.Context, params LogLoginParams) error
	loginMethodIDFn   func() int
	getPasswordHashFn func(ctx context.Context, userID int) (string, error)
	countConsecFn     func(ctx context.Context, userID int) (int, error)
	countLockoutsFn   func(ctx context.Context, userID int) (int, error)
	setUnlockedFn     func(ctx context.Context, userID int, unlockAt *time.Time) error
	createSessionFn   func(ctx context.Context, userID int, rememberMe bool) (*SessionRecord, error)
}

func (s *stubDB) CountIPLoginAttemptsInWindow(ctx context.Context, ip string, windowSeconds int64) (int, error) {
	return s.countIPFn(ctx, ip, windowSeconds)
}
func (s *stubDB) FindUserByEmailOrUsername(ctx context.Context, input string) (*UserLookupResult, error) {
	return s.findUserFn(ctx, input)
}
func (s *stubDB) LogLoginAttempt(ctx context.Context, params LogLoginParams) error {
	if s.logAttemptFn != nil {
		return s.logAttemptFn(ctx, params)
	}
	return nil
}
func (s *stubDB) LoginMethodIDPassword() int {
	if s.loginMethodIDFn != nil {
		return s.loginMethodIDFn()
	}
	return 1
}
func (s *stubDB) GetPasswordHash(ctx context.Context, userID int) (string, error) {
	return s.getPasswordHashFn(ctx, userID)
}
func (s *stubDB) CountConsecutiveFailures(ctx context.Context, userID int) (int, error) {
	return s.countConsecFn(ctx, userID)
}
func (s *stubDB) CountLockouts(ctx context.Context, userID int) (int, error) {
	return s.countLockoutsFn(ctx, userID)
}
func (s *stubDB) SetUserUnlocked(ctx context.Context, userID int, unlockAt *time.Time) error {
	return s.setUnlockedFn(ctx, userID, unlockAt)
}
func (s *stubDB) CreateSession(ctx context.Context, userID int, rememberMe bool) (*SessionRecord, error) {
	return s.createSessionFn(ctx, userID, rememberMe)
}

// ipOK returns a countIPFn that reports zero attempts — under the rate limit.
func ipOK() func(context.Context, string, int64) (int, error) {
	return func(_ context.Context, _ string, _ int64) (int, error) { return 0, nil }
}

// validUser returns a UserLookupResult for a normal, unlocked user.
func validUser() *UserLookupResult {
	return &UserLookupResult{ID: 42, IsLoginEnabled: true, IsDisabled: false}
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

// --- IP rate-limiting tests ---

func TestLogin_IPRateLimited_CountAtMax(t *testing.T) {
	d := &stubDB{
		countIPFn: func(_ context.Context, _ string, _ int64) (int, error) {
			return ipRateMaxAttempts, nil
		},
	}
	result := Login(context.Background(), d, "1.2.3.4", "ua", "user", "pass", false)
	if !result.RateLimited {
		t.Error("expected RateLimited=true when count == ipRateMaxAttempts")
	}
}

func TestLogin_IPRateLimited_CountBelowMax(t *testing.T) {
	d := &stubDB{
		countIPFn: func(_ context.Context, _ string, _ int64) (int, error) {
			return ipRateMaxAttempts - 1, nil
		},
		findUserFn: func(_ context.Context, _ string) (*UserLookupResult, error) {
			return nil, ErrNotFound
		},
	}
	result := Login(context.Background(), d, "1.2.3.4", "ua", "user", "pass", false)
	if result.RateLimited {
		t.Error("expected RateLimited=false when count < ipRateMaxAttempts")
	}
}

func TestLogin_IPRateLimited_DBError(t *testing.T) {
	d := &stubDB{
		countIPFn: func(_ context.Context, _ string, _ int64) (int, error) {
			return 0, errors.New("db: connection refused")
		},
	}
	result := Login(context.Background(), d, "1.2.3.4", "ua", "user", "pass", false)
	if !result.RateLimited {
		t.Error("expected RateLimited=true when CountIPLoginAttemptsInWindow returns an error")
	}
}

// --- User lookup / preflight tests ---

func TestLogin_UserNotFound(t *testing.T) {
	d := &stubDB{
		countIPFn: ipOK(),
		findUserFn: func(_ context.Context, _ string) (*UserLookupResult, error) {
			return nil, ErrNotFound
		},
	}
	result := Login(context.Background(), d, "1.2.3.4", "ua", "noone", "pass", false)
	if result.RateLimited {
		t.Error("expected RateLimited=false")
	}
	if result.Session != nil {
		t.Error("expected no session on not-found")
	}
	if result.ErrMessage == "" {
		t.Error("expected non-empty ErrMessage")
	}
}

func TestLogin_UserLoginDisabled(t *testing.T) {
	d := &stubDB{
		countIPFn: ipOK(),
		findUserFn: func(_ context.Context, _ string) (*UserLookupResult, error) {
			return &UserLookupResult{ID: 1, IsLoginEnabled: false, IsDisabled: false}, nil
		},
	}
	result := Login(context.Background(), d, "1.2.3.4", "ua", "user", "pass", false)
	if result.Session != nil || result.ErrMessage == "" {
		t.Error("expected failure result for disabled login")
	}
}

func TestLogin_UserDisabled(t *testing.T) {
	d := &stubDB{
		countIPFn: ipOK(),
		findUserFn: func(_ context.Context, _ string) (*UserLookupResult, error) {
			return &UserLookupResult{ID: 1, IsLoginEnabled: true, IsDisabled: true}, nil
		},
	}
	result := Login(context.Background(), d, "1.2.3.4", "ua", "user", "pass", false)
	if result.Session != nil || result.ErrMessage == "" {
		t.Error("expected failure result for disabled user")
	}
}

func TestLogin_UserLocked(t *testing.T) {
	future := time.Now().UTC().Add(10 * time.Minute)
	d := &stubDB{
		countIPFn: ipOK(),
		findUserFn: func(_ context.Context, _ string) (*UserLookupResult, error) {
			return &UserLookupResult{ID: 1, IsLoginEnabled: true, IsDisabled: false, Unlocked: &future}, nil
		},
	}
	result := Login(context.Background(), d, "1.2.3.4", "ua", "user", "pass", false)
	if result.Session != nil || result.ErrMessage == "" {
		t.Error("expected failure result for locked user")
	}
}

// --- Wrong password / lockout escalation tests ---

func TestLogin_WrongPassword_NoLockout(t *testing.T) {
	const wrongPass = "wrong"
	d := &stubDB{
		countIPFn:  ipOK(),
		findUserFn: func(_ context.Context, _ string) (*UserLookupResult, error) { return validUser(), nil },
		getPasswordHashFn: func(_ context.Context, _ int) (string, error) {
			h, _ := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
			return string(h), nil
		},
		// consecutive failures = 3 → 3+1=4 < loginMaxConsecutiveFailures(5) → no lockout
		countConsecFn: func(_ context.Context, _ int) (int, error) { return 3, nil },
		// setUnlockedFn intentionally nil — panics if called unexpectedly
	}
	result := Login(context.Background(), d, "1.2.3.4", "ua", "user", wrongPass, false)
	if result.Session != nil || result.ErrMessage == "" {
		t.Error("expected failure result for wrong password")
	}
}

func TestLogin_WrongPassword_TriggersFirstLockout(t *testing.T) {
	var capturedLockout *time.Time
	d := &stubDB{
		countIPFn:  ipOK(),
		findUserFn: func(_ context.Context, _ string) (*UserLookupResult, error) { return validUser(), nil },
		getPasswordHashFn: func(_ context.Context, _ int) (string, error) {
			h, _ := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
			return string(h), nil
		},
		// consecutive = 4 → 4+1=5 >= loginMaxConsecutiveFailures(5) → lockout triggered
		countConsecFn:   func(_ context.Context, _ int) (int, error) { return 4, nil },
		countLockoutsFn: func(_ context.Context, _ int) (int, error) { return 0, nil }, // 0 prior → idx=0 → 5 min
		setUnlockedFn: func(_ context.Context, _ int, unlockAt *time.Time) error {
			capturedLockout = unlockAt
			return nil
		},
	}
	before := time.Now().UTC()
	Login(context.Background(), d, "1.2.3.4", "ua", "user", "wrong", false)
	if capturedLockout == nil {
		t.Fatal("expected SetUserUnlocked to be called for first lockout")
	}
	want := time.Duration(lockoutDurationsMinutes[0]) * time.Minute
	got := capturedLockout.Sub(before)
	if got < want-5*time.Second || got > want+5*time.Second {
		t.Errorf("lockout duration = %v, want ~%v", got, want)
	}
}

func TestLogin_WrongPassword_LockoutEscalation(t *testing.T) {
	var capturedLockout *time.Time
	d := &stubDB{
		countIPFn:  ipOK(),
		findUserFn: func(_ context.Context, _ string) (*UserLookupResult, error) { return validUser(), nil },
		getPasswordHashFn: func(_ context.Context, _ int) (string, error) {
			h, _ := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
			return string(h), nil
		},
		countConsecFn:   func(_ context.Context, _ int) (int, error) { return 4, nil },
		countLockoutsFn: func(_ context.Context, _ int) (int, error) { return 1, nil }, // 1 prior → idx=1 → 30 min
		setUnlockedFn: func(_ context.Context, _ int, unlockAt *time.Time) error {
			capturedLockout = unlockAt
			return nil
		},
	}
	before := time.Now().UTC()
	Login(context.Background(), d, "1.2.3.4", "ua", "user", "wrong", false)
	if capturedLockout == nil {
		t.Fatal("expected SetUserUnlocked to be called")
	}
	want := time.Duration(lockoutDurationsMinutes[1]) * time.Minute
	got := capturedLockout.Sub(before)
	if got < want-5*time.Second || got > want+5*time.Second {
		t.Errorf("lockout duration = %v, want ~%v", got, want)
	}
}

func TestLogin_WrongPassword_LockoutCapped(t *testing.T) {
	var capturedLockout *time.Time
	d := &stubDB{
		countIPFn:  ipOK(),
		findUserFn: func(_ context.Context, _ string) (*UserLookupResult, error) { return validUser(), nil },
		getPasswordHashFn: func(_ context.Context, _ int) (string, error) {
			h, _ := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
			return string(h), nil
		},
		countConsecFn:   func(_ context.Context, _ int) (int, error) { return 4, nil },
		countLockoutsFn: func(_ context.Context, _ int) (int, error) { return 10, nil }, // >= 4 → capped at idx=3 → 1440 min
		setUnlockedFn: func(_ context.Context, _ int, unlockAt *time.Time) error {
			capturedLockout = unlockAt
			return nil
		},
	}
	before := time.Now().UTC()
	Login(context.Background(), d, "1.2.3.4", "ua", "user", "wrong", false)
	if capturedLockout == nil {
		t.Fatal("expected SetUserUnlocked to be called")
	}
	want := time.Duration(lockoutDurationsMinutes[len(lockoutDurationsMinutes)-1]) * time.Minute
	got := capturedLockout.Sub(before)
	if got < want-5*time.Second || got > want+5*time.Second {
		t.Errorf("lockout duration = %v, want ~%v", got, want)
	}
}

// --- Success tests ---

func TestLogin_Success(t *testing.T) {
	const password = "correct-horse-battery-staple"
	hash := mustHash(t, password)
	var rememberMeGot bool
	d := &stubDB{
		countIPFn:         ipOK(),
		findUserFn:        func(_ context.Context, _ string) (*UserLookupResult, error) { return validUser(), nil },
		getPasswordHashFn: func(_ context.Context, _ int) (string, error) { return hash, nil },
		createSessionFn: func(_ context.Context, _ int, rm bool) (*SessionRecord, error) {
			rememberMeGot = rm
			return &SessionRecord{SessionID: 99, UserID: 42}, nil
		},
	}
	result := Login(context.Background(), d, "1.2.3.4", "ua", "user", password, false)
	if result.Session == nil {
		t.Fatal("expected non-nil Session on success")
	}
	if result.ErrMessage != "" {
		t.Errorf("expected empty ErrMessage, got %q", result.ErrMessage)
	}
	if result.RateLimited {
		t.Error("expected RateLimited=false")
	}
	if rememberMeGot {
		t.Error("expected rememberMe=false to be passed to CreateSession")
	}
}

func TestLogin_Success_RememberMe(t *testing.T) {
	const password = "correct-horse-battery-staple"
	hash := mustHash(t, password)
	var rememberMeGot bool
	d := &stubDB{
		countIPFn:         ipOK(),
		findUserFn:        func(_ context.Context, _ string) (*UserLookupResult, error) { return validUser(), nil },
		getPasswordHashFn: func(_ context.Context, _ int) (string, error) { return hash, nil },
		createSessionFn: func(_ context.Context, _ int, rm bool) (*SessionRecord, error) {
			rememberMeGot = rm
			return &SessionRecord{SessionID: 99, UserID: 42}, nil
		},
	}
	result := Login(context.Background(), d, "1.2.3.4", "ua", "user", password, true)
	if result.Session == nil {
		t.Fatal("expected non-nil Session")
	}
	if !rememberMeGot {
		t.Error("expected rememberMe=true to be passed to CreateSession")
	}
}

func TestLogin_CreateSessionError(t *testing.T) {
	const password = "correct-horse-battery-staple"
	hash := mustHash(t, password)
	d := &stubDB{
		countIPFn:         ipOK(),
		findUserFn:        func(_ context.Context, _ string) (*UserLookupResult, error) { return validUser(), nil },
		getPasswordHashFn: func(_ context.Context, _ int) (string, error) { return hash, nil },
		createSessionFn: func(_ context.Context, _ int, _ bool) (*SessionRecord, error) {
			return nil, errors.New("db: connection lost")
		},
	}
	result := Login(context.Background(), d, "1.2.3.4", "ua", "user", password, false)
	if result.Session != nil {
		t.Error("expected nil Session on CreateSession error")
	}
	if result.ErrMessage == "" {
		t.Error("expected non-empty ErrMessage on CreateSession error")
	}
}
