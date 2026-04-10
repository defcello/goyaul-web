package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// Signup validation limits.
const (
	usernameMinLen    = 3
	usernameMaxLen    = 30
	displayNameMaxLen = 100
	passwordMinLen    = 8
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// ErrSignupConflict is returned when a username or email is already taken.
var ErrSignupConflict = errors.New("auth: signup conflict")

// SignupValidationError describes a field-level validation failure.
type SignupValidationError struct {
	Field   string
	Message string
}

func (e *SignupValidationError) Error() string {
	return fmt.Sprintf("signup: %s: %s", e.Field, e.Message)
}

// SignupDB is the subset of DB methods required by the signup flow.
type SignupDB interface {
	// UsernameExists reports whether username is already in use (case-insensitive).
	UsernameExists(ctx context.Context, username string) (bool, error)

	// EmailExists reports whether email is already registered (case-insensitive).
	EmailExists(ctx context.Context, email string) (bool, error)

	// CreateUser inserts a new user row and returns the new user's ID.
	CreateUser(ctx context.Context, username, email, displayName, passwordHash string) (userID int, err error)
}

// Signup validates the provided fields, checks uniqueness, hashes the password
// with bcrypt, and creates a new user via db.CreateUser.
//
// Returns *SignupValidationError for field-level validation failures or
// ErrSignupConflict when the username/email is already taken.
func Signup(ctx context.Context, db SignupDB, username, emailAddr, displayName, password string) (userID int, err error) {
	username = strings.TrimSpace(username)
	emailAddr = strings.TrimSpace(emailAddr)
	displayName = strings.TrimSpace(displayName)

	// --- Validate username ---
	switch {
	case utf8.RuneCountInString(username) < usernameMinLen:
		return 0, &SignupValidationError{Field: "username",
			Message: fmt.Sprintf("must be at least %d characters", usernameMinLen)}
	case utf8.RuneCountInString(username) > usernameMaxLen:
		return 0, &SignupValidationError{Field: "username",
			Message: fmt.Sprintf("must be at most %d characters", usernameMaxLen)}
	case !usernameRe.MatchString(username):
		return 0, &SignupValidationError{Field: "username",
			Message: "may only contain letters, numbers, underscores, hyphens, and dots"}
	}

	// --- Validate email ---
	if !strings.Contains(emailAddr, "@") || strings.HasPrefix(emailAddr, "@") || strings.HasSuffix(emailAddr, "@") {
		return 0, &SignupValidationError{Field: "email", Message: "must be a valid email address"}
	}

	// --- Validate display name ---
	if utf8.RuneCountInString(displayName) == 0 {
		return 0, &SignupValidationError{Field: "display_name", Message: "cannot be blank"}
	}
	if utf8.RuneCountInString(displayName) > displayNameMaxLen {
		return 0, &SignupValidationError{Field: "display_name",
			Message: fmt.Sprintf("must be at most %d characters", displayNameMaxLen)}
	}

	// --- Validate password ---
	if utf8.RuneCountInString(password) < passwordMinLen {
		return 0, &SignupValidationError{Field: "password",
			Message: fmt.Sprintf("must be at least %d characters", passwordMinLen)}
	}

	// --- Uniqueness checks ---
	taken, err := db.UsernameExists(ctx, username)
	if err != nil {
		return 0, fmt.Errorf("auth: signup: check username: %w", err)
	}
	if taken {
		return 0, &SignupValidationError{Field: "username", Message: "is already taken"}
	}

	taken, err = db.EmailExists(ctx, emailAddr)
	if err != nil {
		return 0, fmt.Errorf("auth: signup: check email: %w", err)
	}
	if taken {
		return 0, &SignupValidationError{Field: "email", Message: "is already registered"}
	}

	// --- Hash password ---
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, fmt.Errorf("auth: signup: hash password: %w", err)
	}

	// --- Create user ---
	userID, err = db.CreateUser(ctx, username, emailAddr, displayName, string(hash))
	if err != nil {
		return 0, fmt.Errorf("auth: signup: create user: %w", err)
	}

	return userID, nil
}
