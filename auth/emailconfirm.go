package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"text/template"
	"time"

	"github.com/defcello/goyaul-web/email"
)

// emailConfirmExpiry is how long an email-confirmation token remains valid.
const emailConfirmExpiry = 24 * time.Hour

// EmailConfirmToken is the data associated with a stored confirmation token.
type EmailConfirmToken struct {
	UserID      int
	NewEmail    string
	ExpiresAt   time.Time
	ConfirmedAt *time.Time
}

// EmailConfirmDB is the subset of DB methods required by the email-confirmation flow.
type EmailConfirmDB interface {
	// CreateEmailConfirmToken stores a hashed token that, when presented, should
	// update userID's email address to newEmail.
	// Implementations should delete or invalidate any prior unconfirmed tokens
	// for the same user before inserting the new one.
	CreateEmailConfirmToken(ctx context.Context, userID int, newEmail string, tokenHash []byte, expiresAt time.Time) error

	// GetEmailConfirmToken returns the record whose SHA-256 hash matches tokenHash.
	// Returns ErrNotFound when no row exists.
	GetEmailConfirmToken(ctx context.Context, tokenHash []byte) (*EmailConfirmToken, error)

	// ConfirmEmailToken atomically marks the token confirmed and updates the
	// user's email address to EmailConfirmToken.NewEmail.
	ConfirmEmailToken(ctx context.Context, tokenHash []byte) error
}

// emailConfirmEmailData is passed to the email templates.
type emailConfirmEmailData struct {
	SiteName   string
	ConfirmURL string
}

// RequestEmailConfirmation stores a confirmation token and sends an email to
// newEmail asking the user to verify ownership.
//
// After the user clicks the link (GET /confirm-email?token=<plaintext>), the
// caller should invoke ConfirmEmail to complete the change.
func RequestEmailConfirmation(ctx context.Context, d EmailConfirmDB, m email.Mailer, siteName string, userID int, newEmail, baseURL string) error {
	plaintext, hash, err := GenerateToken()
	if err != nil {
		return fmt.Errorf("auth: request email confirmation: generate token: %w", err)
	}

	expiresAt := time.Now().UTC().Add(emailConfirmExpiry)
	if err := d.CreateEmailConfirmToken(ctx, userID, newEmail, hash, expiresAt); err != nil {
		return fmt.Errorf("auth: request email confirmation: store token: %w", err)
	}

	confirmURL := baseURL + "/confirm-email?token=" + plaintext
	data := emailConfirmEmailData{SiteName: siteName, ConfirmURL: confirmURL}

	textBody, htmlBody, err := renderEmailConfirmEmail(data)
	if err != nil {
		return fmt.Errorf("auth: request email confirmation: render email: %w", err)
	}

	return m.Send(ctx, email.Message{
		To:      []string{newEmail},
		Subject: "Confirm your " + siteName + " email address",
		Text:    textBody,
		HTML:    htmlBody,
	})
}

// ConfirmEmail validates tokenPlaintext and, if valid, finalises the email change.
//
// Returns ErrTokenInvalid when the token is unknown, expired, or already confirmed.
func ConfirmEmail(ctx context.Context, d EmailConfirmDB, tokenPlaintext string) error {
	hash, err := HashToken(tokenPlaintext)
	if err != nil {
		return ErrTokenInvalid
	}

	rec, err := d.GetEmailConfirmToken(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrTokenInvalid
		}
		return fmt.Errorf("auth: confirm email: lookup token: %w", err)
	}

	if rec.ConfirmedAt != nil || time.Now().UTC().After(rec.ExpiresAt) {
		return ErrTokenInvalid
	}

	if err := d.ConfirmEmailToken(ctx, hash); err != nil {
		return fmt.Errorf("auth: confirm email: finalize: %w", err)
	}

	return nil
}

// ---- email rendering -------------------------------------------------------

var emailConfirmTextTmpl = template.Must(template.New("emailconfirm-text").Parse(`Hi,

Please confirm your new email address for {{.SiteName}} by clicking the link below within 24 hours:

  {{.ConfirmURL}}

If you did not request this change, you can safely ignore this email.

— {{.SiteName}}
`))

var emailConfirmHTMLTmpl = template.Must(template.New("emailconfirm-html").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Confirm your {{.SiteName}} email address</title></head>
<body style="font-family:sans-serif;color:#1a1a1a;max-width:560px;margin:0 auto;padding:32px 16px">
  <h1 style="font-size:1.25rem;margin-bottom:8px">{{.SiteName}}</h1>
  <h2 style="font-size:1rem;font-weight:normal;margin-bottom:24px;color:#555">Confirm Email Address</h2>
  <p>Please confirm your new email address by clicking the button below within <strong>24 hours</strong>:</p>
  <p style="margin:24px 0">
    <a href="{{.ConfirmURL}}"
       style="background:#2563eb;color:#fff;text-decoration:none;padding:12px 24px;border-radius:6px;display:inline-block">
      Confirm Email Address
    </a>
  </p>
  <p style="color:#666;font-size:0.875rem">
    If you did not request this change, you can safely ignore this email.
  </p>
  <hr style="border:none;border-top:1px solid #e5e7eb;margin:32px 0">
  <p style="color:#aaa;font-size:0.75rem">{{.SiteName}}</p>
</body>
</html>
`))

func renderEmailConfirmEmail(data emailConfirmEmailData) (textBody, htmlBody string, err error) {
	var tb, hb bytes.Buffer
	if err := emailConfirmTextTmpl.Execute(&tb, data); err != nil {
		return "", "", err
	}
	if err := emailConfirmHTMLTmpl.Execute(&hb, data); err != nil {
		return "", "", err
	}
	return tb.String(), hb.String(), nil
}
