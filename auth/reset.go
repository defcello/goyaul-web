package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"text/template"
	"time"

	"github.com/defcello/goyaul-web/email"
	"golang.org/x/crypto/bcrypt"
)

// passwordResetExpiry is how long a reset token remains valid.
const passwordResetExpiry = time.Hour

// ErrTokenInvalid is returned when a presented token is not found, already
// used, or expired.
var ErrTokenInvalid = errors.New("auth: token invalid or expired")

// PasswordResetToken is the data associated with a stored reset token.
type PasswordResetToken struct {
	UserID    int
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// PasswordResetDB is the subset of DB methods required by the password-reset flow.
// Consumers implement this against their database.
type PasswordResetDB interface {
	// FindUserByEmail returns the user whose email matches exactly, or
	// ErrNotFound when no such user exists.
	FindUserByEmail(ctx context.Context, email string) (*UserLookupResult, error)

	// CreatePasswordResetToken stores a hashed token for userID, valid until expiresAt.
	// Implementations should delete or invalidate any prior unused tokens for the
	// same user before inserting the new one.
	CreatePasswordResetToken(ctx context.Context, userID int, tokenHash []byte, expiresAt time.Time) error

	// GetPasswordResetToken looks up the token whose SHA-256 hash matches tokenHash.
	// Returns ErrNotFound when no row exists.
	GetPasswordResetToken(ctx context.Context, tokenHash []byte) (*PasswordResetToken, error)

	// MarkPasswordResetTokenUsed records that the token has been consumed.
	MarkPasswordResetTokenUsed(ctx context.Context, tokenHash []byte) error

	// UpdatePassword replaces the stored password hash for userID.
	UpdatePassword(ctx context.Context, userID int, newHash string) error
}

// passwordResetEmailData is passed to the email templates.
type passwordResetEmailData struct {
	SiteName string
	ResetURL string
}

// RequestPasswordReset initiates the password-reset flow for the given email address.
//
// A time-limited token is stored in the database and an email containing a
// reset link (baseURL + "/reset-password?token=<plaintext>") is dispatched.
//
// The function always returns nil to the caller, even when the email address is
// not registered — this prevents user-enumeration via the response.
//
// siteName is used in the email subject and body.
func RequestPasswordReset(ctx context.Context, d PasswordResetDB, m email.Mailer, siteName, emailAddr, baseURL string) error {
	user, err := d.FindUserByEmail(ctx, emailAddr)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil // silent no-op — don't reveal whether the address is registered
		}
		return fmt.Errorf("auth: request password reset: lookup: %w", err)
	}

	plaintext, hash, err := GenerateToken()
	if err != nil {
		return fmt.Errorf("auth: request password reset: generate token: %w", err)
	}

	expiresAt := time.Now().UTC().Add(passwordResetExpiry)
	if err := d.CreatePasswordResetToken(ctx, user.ID, hash, expiresAt); err != nil {
		return fmt.Errorf("auth: request password reset: store token: %w", err)
	}

	resetURL := baseURL + "/reset-password?token=" + plaintext
	data := passwordResetEmailData{SiteName: siteName, ResetURL: resetURL}

	textBody, htmlBody, err := renderPasswordResetEmail(data)
	if err != nil {
		return fmt.Errorf("auth: request password reset: render email: %w", err)
	}

	return m.Send(ctx, email.Message{
		To:      []string{emailAddr},
		Subject: "Reset your " + siteName + " password",
		Text:    textBody,
		HTML:    htmlBody,
	})
}

// CompletePasswordReset validates tokenPlaintext, hashes newPassword with bcrypt,
// and updates the user's password, then marks the token used.
//
// Returns ErrTokenInvalid when the token is unknown, expired, or already used.
func CompletePasswordReset(ctx context.Context, d PasswordResetDB, tokenPlaintext, newPassword string) error {
	hash, err := HashToken(tokenPlaintext)
	if err != nil {
		return ErrTokenInvalid
	}

	rec, err := d.GetPasswordResetToken(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrTokenInvalid
		}
		return fmt.Errorf("auth: complete password reset: lookup token: %w", err)
	}

	if rec.UsedAt != nil || time.Now().UTC().After(rec.ExpiresAt) {
		return ErrTokenInvalid
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("auth: complete password reset: hash password: %w", err)
	}

	if err := d.UpdatePassword(ctx, rec.UserID, string(newHash)); err != nil {
		return fmt.Errorf("auth: complete password reset: update password: %w", err)
	}

	if err := d.MarkPasswordResetTokenUsed(ctx, hash); err != nil {
		// Non-fatal: password is already updated. Log but don't surface.
		_ = err
	}

	return nil
}

// ---- email rendering -------------------------------------------------------

var passwordResetTextTmpl = template.Must(template.New("pwreset-text").Parse(`Hi,

Someone requested a password reset for your {{.SiteName}} account.

Click the link below within 1 hour to choose a new password:

  {{.ResetURL}}

If you did not request a password reset, you can safely ignore this email.

— {{.SiteName}}
`))

var passwordResetHTMLTmpl = template.Must(template.New("pwreset-html").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Reset your {{.SiteName}} password</title></head>
<body style="font-family:sans-serif;color:#1a1a1a;max-width:560px;margin:0 auto;padding:32px 16px">
  <h1 style="font-size:1.25rem;margin-bottom:8px">{{.SiteName}}</h1>
  <h2 style="font-size:1rem;font-weight:normal;margin-bottom:24px;color:#555">Password Reset</h2>
  <p>Someone requested a password reset for your account.</p>
  <p>Click the button below within <strong>1 hour</strong> to choose a new password:</p>
  <p style="margin:24px 0">
    <a href="{{.ResetURL}}"
       style="background:#2563eb;color:#fff;text-decoration:none;padding:12px 24px;border-radius:6px;display:inline-block">
      Reset Password
    </a>
  </p>
  <p style="color:#666;font-size:0.875rem">
    If you did not request a password reset, you can safely ignore this email.
  </p>
  <hr style="border:none;border-top:1px solid #e5e7eb;margin:32px 0">
  <p style="color:#aaa;font-size:0.75rem">{{.SiteName}}</p>
</body>
</html>
`))

func renderPasswordResetEmail(data passwordResetEmailData) (textBody, htmlBody string, err error) {
	var tb, hb bytes.Buffer
	if err := passwordResetTextTmpl.Execute(&tb, data); err != nil {
		return "", "", err
	}
	if err := passwordResetHTMLTmpl.Execute(&hb, data); err != nil {
		return "", "", err
	}
	return tb.String(), hb.String(), nil
}
