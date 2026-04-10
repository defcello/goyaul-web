// Package email provides the Mailer interface and related types used by
// goyaul-web auth flows to send transactional email.
//
// Consumers construct a concrete implementation (e.g. NewSMTPMailer) at
// startup and pass it to the auth functions that need it.
package email

import "context"

// Message is an outbound email.
type Message struct {
	To      []string // recipient addresses
	Subject string
	Text    string // plain-text body (fallback)
	HTML    string // HTML body (optional; empty = send text only)
}

// Mailer sends a single transactional message.
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}
