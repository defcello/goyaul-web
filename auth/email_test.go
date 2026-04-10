package auth

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defcello/goyaul-web/email"
)

// ---- token utilities -------------------------------------------------------

func TestGenerateToken(t *testing.T) {
	pt, hash, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if pt == "" {
		t.Error("plaintext should not be empty")
	}
	if len(hash) != 32 {
		t.Errorf("hash length = %d, want 32", len(hash))
	}
}

func TestGenerateTokenUnique(t *testing.T) {
	pt1, _, _ := GenerateToken()
	pt2, _, _ := GenerateToken()
	if pt1 == pt2 {
		t.Error("two calls returned the same token")
	}
}

func TestHashToken_RoundTrip(t *testing.T) {
	pt, want, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	got, err := HashToken(pt)
	if err != nil {
		t.Fatalf("HashToken: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Error("HashToken did not reproduce the original hash")
	}
}

func TestHashToken_Invalid(t *testing.T) {
	_, err := HashToken("not-valid-base64url!!!")
	if err == nil {
		t.Error("expected error for invalid base64url input")
	}
}

// ---- password reset --------------------------------------------------------

type stubResetDB struct {
	findUserFn          func(ctx context.Context, email string) (*UserLookupResult, error)
	createTokenFn       func(ctx context.Context, userID int, tokenHash []byte, expiresAt time.Time) error
	getTokenFn          func(ctx context.Context, tokenHash []byte) (*PasswordResetToken, error)
	markUsedFn          func(ctx context.Context, tokenHash []byte) error
	updatePasswordFn    func(ctx context.Context, userID int, newHash string) error
}

func (s *stubResetDB) FindUserByEmail(ctx context.Context, e string) (*UserLookupResult, error) {
	return s.findUserFn(ctx, e)
}
func (s *stubResetDB) CreatePasswordResetToken(ctx context.Context, userID int, tokenHash []byte, expiresAt time.Time) error {
	return s.createTokenFn(ctx, userID, tokenHash, expiresAt)
}
func (s *stubResetDB) GetPasswordResetToken(ctx context.Context, tokenHash []byte) (*PasswordResetToken, error) {
	return s.getTokenFn(ctx, tokenHash)
}
func (s *stubResetDB) MarkPasswordResetTokenUsed(ctx context.Context, tokenHash []byte) error {
	return s.markUsedFn(ctx, tokenHash)
}
func (s *stubResetDB) UpdatePassword(ctx context.Context, userID int, newHash string) error {
	return s.updatePasswordFn(ctx, userID, newHash)
}

type captureMailer struct{ sent []email.Message }

func (c *captureMailer) Send(_ context.Context, msg email.Message) error {
	c.sent = append(c.sent, msg)
	return nil
}

func TestRequestPasswordReset_SendsEmail(t *testing.T) {
	var storedHash []byte
	db := &stubResetDB{
		findUserFn: func(_ context.Context, _ string) (*UserLookupResult, error) {
			return &UserLookupResult{ID: 7, IsLoginEnabled: true}, nil
		},
		createTokenFn: func(_ context.Context, _ int, tokenHash []byte, _ time.Time) error {
			storedHash = tokenHash
			return nil
		},
	}
	m := &captureMailer{}

	err := RequestPasswordReset(context.Background(), db, m, "TestSite", "user@example.com", "https://example.com")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if len(m.sent) != 1 {
		t.Fatalf("expected 1 email sent, got %d", len(m.sent))
	}
	if storedHash == nil {
		t.Fatal("token hash was not stored")
	}
	msg := m.sent[0]
	if !strings.Contains(msg.Text, "https://example.com/reset-password?token=") {
		t.Errorf("email text missing reset link; got: %s", msg.Text)
	}
}

func TestRequestPasswordReset_UnknownEmail_Silent(t *testing.T) {
	db := &stubResetDB{
		findUserFn: func(_ context.Context, _ string) (*UserLookupResult, error) {
			return nil, ErrNotFound
		},
	}
	m := &captureMailer{}

	err := RequestPasswordReset(context.Background(), db, m, "TestSite", "nobody@example.com", "https://example.com")
	if err != nil {
		t.Fatalf("expected nil error for unknown email, got: %v", err)
	}
	if len(m.sent) != 0 {
		t.Errorf("expected no email sent, got %d", len(m.sent))
	}
}

func TestCompletePasswordReset_Success(t *testing.T) {
	pt, hash, _ := GenerateToken()
	var updatedHash string
	var markedUsed bool

	db := &stubResetDB{
		getTokenFn: func(_ context.Context, tokenHash []byte) (*PasswordResetToken, error) {
			if !bytes.Equal(tokenHash, hash) {
				return nil, ErrNotFound
			}
			return &PasswordResetToken{UserID: 7, ExpiresAt: time.Now().UTC().Add(time.Hour)}, nil
		},
		updatePasswordFn: func(_ context.Context, _ int, newHash string) error {
			updatedHash = newHash
			return nil
		},
		markUsedFn: func(_ context.Context, _ []byte) error {
			markedUsed = true
			return nil
		},
	}

	if err := CompletePasswordReset(context.Background(), db, pt, "newpassword123"); err != nil {
		t.Fatalf("CompletePasswordReset: %v", err)
	}
	if updatedHash == "" {
		t.Error("UpdatePassword was not called")
	}
	if !markedUsed {
		t.Error("MarkPasswordResetTokenUsed was not called")
	}
}

func TestCompletePasswordReset_ExpiredToken(t *testing.T) {
	pt, hash, _ := GenerateToken()
	db := &stubResetDB{
		getTokenFn: func(_ context.Context, tokenHash []byte) (*PasswordResetToken, error) {
			if !bytes.Equal(tokenHash, hash) {
				return nil, ErrNotFound
			}
			return &PasswordResetToken{UserID: 7, ExpiresAt: time.Now().UTC().Add(-time.Hour)}, nil
		},
	}
	err := CompletePasswordReset(context.Background(), db, pt, "newpassword123")
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid, got: %v", err)
	}
}

func TestCompletePasswordReset_BadToken(t *testing.T) {
	err := CompletePasswordReset(context.Background(), &stubResetDB{}, "not-a-token!!!", "newpassword123")
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid for bad token, got: %v", err)
	}
}

// ---- email confirmation ----------------------------------------------------

type stubConfirmDB struct {
	createFn  func(ctx context.Context, userID int, newEmail string, tokenHash []byte, expiresAt time.Time) error
	getFn     func(ctx context.Context, tokenHash []byte) (*EmailConfirmToken, error)
	confirmFn func(ctx context.Context, tokenHash []byte) error
}

func (s *stubConfirmDB) CreateEmailConfirmToken(ctx context.Context, userID int, newEmail string, tokenHash []byte, expiresAt time.Time) error {
	return s.createFn(ctx, userID, newEmail, tokenHash, expiresAt)
}
func (s *stubConfirmDB) GetEmailConfirmToken(ctx context.Context, tokenHash []byte) (*EmailConfirmToken, error) {
	return s.getFn(ctx, tokenHash)
}
func (s *stubConfirmDB) ConfirmEmailToken(ctx context.Context, tokenHash []byte) error {
	return s.confirmFn(ctx, tokenHash)
}

func TestRequestEmailConfirmation_SendsEmail(t *testing.T) {
	db := &stubConfirmDB{
		createFn: func(_ context.Context, _ int, _ string, _ []byte, _ time.Time) error {
			return nil
		},
	}
	m := &captureMailer{}

	err := RequestEmailConfirmation(context.Background(), db, m, "TestSite", 7, "new@example.com", "https://example.com")
	if err != nil {
		t.Fatalf("RequestEmailConfirmation: %v", err)
	}
	if len(m.sent) != 1 {
		t.Fatalf("expected 1 email, got %d", len(m.sent))
	}
	msg := m.sent[0]
	if msg.To[0] != "new@example.com" {
		t.Errorf("email sent to %q, want %q", msg.To[0], "new@example.com")
	}
	if !strings.Contains(msg.Text, "https://example.com/confirm-email?token=") {
		t.Errorf("email text missing confirm link; got: %s", msg.Text)
	}
}

func TestConfirmEmail_Success(t *testing.T) {
	pt, hash, _ := GenerateToken()
	var confirmed bool
	db := &stubConfirmDB{
		getFn: func(_ context.Context, tokenHash []byte) (*EmailConfirmToken, error) {
			if !bytes.Equal(tokenHash, hash) {
				return nil, ErrNotFound
			}
			return &EmailConfirmToken{UserID: 7, NewEmail: "new@example.com", ExpiresAt: time.Now().UTC().Add(time.Hour)}, nil
		},
		confirmFn: func(_ context.Context, _ []byte) error {
			confirmed = true
			return nil
		},
	}
	if err := ConfirmEmail(context.Background(), db, pt); err != nil {
		t.Fatalf("ConfirmEmail: %v", err)
	}
	if !confirmed {
		t.Error("ConfirmEmailToken was not called")
	}
}

func TestConfirmEmail_AlreadyConfirmed(t *testing.T) {
	pt, hash, _ := GenerateToken()
	now := time.Now().UTC()
	db := &stubConfirmDB{
		getFn: func(_ context.Context, tokenHash []byte) (*EmailConfirmToken, error) {
			if !bytes.Equal(tokenHash, hash) {
				return nil, ErrNotFound
			}
			return &EmailConfirmToken{
				UserID: 7, NewEmail: "new@example.com",
				ExpiresAt: time.Now().UTC().Add(time.Hour), ConfirmedAt: &now,
			}, nil
		},
	}
	err := ConfirmEmail(context.Background(), db, pt)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid, got: %v", err)
	}
}

// ---- signup ----------------------------------------------------------------

type stubSignupDB struct {
	usernameExistsFn func(ctx context.Context, username string) (bool, error)
	emailExistsFn    func(ctx context.Context, email string) (bool, error)
	createUserFn     func(ctx context.Context, username, email, displayName, passwordHash string) (int, error)
}

func (s *stubSignupDB) UsernameExists(ctx context.Context, username string) (bool, error) {
	return s.usernameExistsFn(ctx, username)
}
func (s *stubSignupDB) EmailExists(ctx context.Context, email string) (bool, error) {
	return s.emailExistsFn(ctx, email)
}
func (s *stubSignupDB) CreateUser(ctx context.Context, username, email, displayName, passwordHash string) (int, error) {
	return s.createUserFn(ctx, username, email, displayName, passwordHash)
}

func TestSignup_Success(t *testing.T) {
	db := &stubSignupDB{
		usernameExistsFn: func(_ context.Context, _ string) (bool, error) { return false, nil },
		emailExistsFn:    func(_ context.Context, _ string) (bool, error) { return false, nil },
		createUserFn:     func(_ context.Context, _, _, _, _ string) (int, error) { return 42, nil },
	}
	userID, err := Signup(context.Background(), db, "alice", "alice@example.com", "Alice A", "securepass")
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if userID != 42 {
		t.Errorf("userID = %d, want 42", userID)
	}
}

func TestSignup_UsernameTooShort(t *testing.T) {
	_, err := Signup(context.Background(), &stubSignupDB{}, "ab", "a@b.com", "Alice", "securepass")
	var ve *SignupValidationError
	if !errors.As(err, &ve) || ve.Field != "username" {
		t.Errorf("expected username validation error, got: %v", err)
	}
}

func TestSignup_InvalidUsername(t *testing.T) {
	_, err := Signup(context.Background(), &stubSignupDB{}, "user name!", "a@b.com", "Alice", "securepass")
	var ve *SignupValidationError
	if !errors.As(err, &ve) || ve.Field != "username" {
		t.Errorf("expected username validation error, got: %v", err)
	}
}

func TestSignup_InvalidEmail(t *testing.T) {
	_, err := Signup(context.Background(), &stubSignupDB{}, "alice", "notanemail", "Alice", "securepass")
	var ve *SignupValidationError
	if !errors.As(err, &ve) || ve.Field != "email" {
		t.Errorf("expected email validation error, got: %v", err)
	}
}

func TestSignup_PasswordTooShort(t *testing.T) {
	_, err := Signup(context.Background(), &stubSignupDB{}, "alice", "a@b.com", "Alice", "short")
	var ve *SignupValidationError
	if !errors.As(err, &ve) || ve.Field != "password" {
		t.Errorf("expected password validation error, got: %v", err)
	}
}

func TestSignup_UsernameConflict(t *testing.T) {
	db := &stubSignupDB{
		usernameExistsFn: func(_ context.Context, _ string) (bool, error) { return true, nil },
	}
	_, err := Signup(context.Background(), db, "alice", "a@b.com", "Alice", "securepass")
	var ve *SignupValidationError
	if !errors.As(err, &ve) || ve.Field != "username" {
		t.Errorf("expected username conflict error, got: %v", err)
	}
}

func TestSignup_EmailConflict(t *testing.T) {
	db := &stubSignupDB{
		usernameExistsFn: func(_ context.Context, _ string) (bool, error) { return false, nil },
		emailExistsFn:    func(_ context.Context, _ string) (bool, error) { return true, nil },
	}
	_, err := Signup(context.Background(), db, "alice", "a@b.com", "Alice", "securepass")
	var ve *SignupValidationError
	if !errors.As(err, &ve) || ve.Field != "email" {
		t.Errorf("expected email conflict error, got: %v", err)
	}
}
