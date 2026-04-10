package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// SMTPMailer sends email via an SMTP server.
//
// Port 465 uses implicit TLS (SMTPS). All other ports use STARTTLS.
// No external dependencies — stdlib only.
type SMTPMailer struct {
	host     string
	port     int
	auth     smtp.Auth
	from     mail.Address
	replyTo  string
}

// NewSMTPMailer creates an SMTPMailer.
//
//   - host, port: SMTP server address. Port 465 → implicit TLS; others → STARTTLS.
//   - username, password: PLAIN auth credentials. Pass empty strings to skip auth
//     (e.g. for local relay that doesn't require authentication).
//   - from: the RFC 5321 MAIL FROM address (e.g. "noreply@skilltrails.org").
//   - replyTo: optional Reply-To header address; empty = omit the header.
func NewSMTPMailer(host string, port int, username, password, from, replyTo string) *SMTPMailer {
	var auth smtp.Auth
	if username != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}
	return &SMTPMailer{
		host:    host,
		port:    port,
		auth:    auth,
		from:    mail.Address{Address: from},
		replyTo: replyTo,
	}
}

// Send delivers msg to all recipients in msg.To.
// ctx is respected for the initial TCP dial; the SMTP exchange itself runs to
// completion once the connection is established.
func (m *SMTPMailer) Send(ctx context.Context, msg Message) error {
	if len(msg.To) == 0 {
		return fmt.Errorf("smtp: no recipients")
	}

	raw, err := m.buildRaw(msg)
	if err != nil {
		return fmt.Errorf("smtp: build message: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", m.host, m.port)

	if m.port == 465 {
		return m.sendTLS(ctx, addr, raw, msg.To)
	}
	return m.sendSTARTTLS(ctx, addr, raw, msg.To)
}

// sendSTARTTLS connects on addr, upgrades to TLS, then sends.
func (m *SMTPMailer) sendSTARTTLS(ctx context.Context, addr string, raw []byte, to []string) error {
	d := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp: dial %s: %w", addr, err)
	}

	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp: new client: %w", err)
	}
	defer c.Close()

	tlsCfg := &tls.Config{ServerName: m.host}
	if err := c.StartTLS(tlsCfg); err != nil {
		return fmt.Errorf("smtp: STARTTLS: %w", err)
	}
	return m.exchange(c, raw, to)
}

// sendTLS connects directly over TLS (port 465 / SMTPS).
func (m *SMTPMailer) sendTLS(ctx context.Context, addr string, raw []byte, to []string) error {
	tlsCfg := &tls.Config{ServerName: m.host}
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 15 * time.Second},
		Config:    tlsCfg,
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp: dial TLS %s: %w", addr, err)
	}

	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp: new client (TLS): %w", err)
	}
	defer c.Close()

	return m.exchange(c, raw, to)
}

// exchange authenticates (if configured) and transmits the message.
func (m *SMTPMailer) exchange(c *smtp.Client, raw []byte, to []string) error {
	if m.auth != nil {
		if err := c.Auth(m.auth); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}
	if err := c.Mail(m.from.Address); err != nil {
		return fmt.Errorf("smtp: MAIL FROM: %w", err)
	}
	for _, r := range to {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("smtp: RCPT TO %s: %w", r, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: DATA: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return fmt.Errorf("smtp: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: close data writer: %w", err)
	}
	return c.Quit()
}

// buildRaw assembles an RFC 2822 message.
// When both Text and HTML are present a multipart/alternative payload is used.
func (m *SMTPMailer) buildRaw(msg Message) ([]byte, error) {
	var buf bytes.Buffer

	writeHeaders := func(contentType string) {
		fmt.Fprintf(&buf, "From: %s\r\n", m.from.String())
		fmt.Fprintf(&buf, "To: %s\r\n", strings.Join(msg.To, ", "))
		if m.replyTo != "" {
			fmt.Fprintf(&buf, "Reply-To: %s\r\n", m.replyTo)
		}
		fmt.Fprintf(&buf, "Subject: %s\r\n", msg.Subject)
		fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
		fmt.Fprintf(&buf, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
		fmt.Fprintf(&buf, "Content-Type: %s\r\n", contentType)
	}

	switch {
	case msg.HTML != "" && msg.Text != "":
		// Determine boundary before writing the Content-Type header.
		var bodyBuf bytes.Buffer
		mw := multipart.NewWriter(&bodyBuf)

		writeHeaders(fmt.Sprintf("multipart/alternative; boundary=%q", mw.Boundary()))
		fmt.Fprintf(&buf, "\r\n")

		// Text part (plain-text listed first; preferred alternative is listed last per RFC 2046).
		th, err := mw.CreatePart(map[string][]string{
			"Content-Type":              {"text/plain; charset=UTF-8"},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		qw := quotedprintable.NewWriter(th)
		qw.Write([]byte(msg.Text))
		qw.Close()

		// HTML part (preferred — last in the multipart).
		hh, err := mw.CreatePart(map[string][]string{
			"Content-Type":              {"text/html; charset=UTF-8"},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		qw = quotedprintable.NewWriter(hh)
		qw.Write([]byte(msg.HTML))
		qw.Close()

		mw.Close()
		buf.Write(bodyBuf.Bytes())

	case msg.HTML != "":
		writeHeaders("text/html; charset=UTF-8")
		fmt.Fprintf(&buf, "Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		qw := quotedprintable.NewWriter(&buf)
		qw.Write([]byte(msg.HTML))
		qw.Close()

	default:
		writeHeaders("text/plain; charset=UTF-8")
		fmt.Fprintf(&buf, "Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		qw := quotedprintable.NewWriter(&buf)
		qw.Write([]byte(msg.Text))
		qw.Close()
	}

	return buf.Bytes(), nil
}
