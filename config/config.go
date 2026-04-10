package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds database connection parameters loaded from cfg.json.
type Config struct {
	DBHost     string `json:"db_host"`
	DBPort     int    `json:"db_port"`
	DBName     string `json:"db_name"`
	DBUser     string `json:"db_user"`
	DBPassword string `json:"db_password"`
	DBSSLMode  string `json:"db_sslmode"`
	SiteName   string `json:"site_name"`
	FlashKey   string `json:"flash_key"`

	// Email configuration. All fields may also be supplied via environment
	// variables (EMAIL_HOST, EMAIL_PORT, EMAIL_USERNAME, EMAIL_PASSWORD,
	// EMAIL_FROM, EMAIL_REPLY_TO) which take precedence over cfg.json values.
	EmailHost     string `json:"email_host"`
	EmailPort     int    `json:"email_port"` // 587 = STARTTLS (default), 465 = TLS
	EmailUsername string `json:"email_username"`
	EmailPassword string `json:"email_password"`
	EmailFrom     string `json:"email_from"`
	EmailReplyTo  string `json:"email_reply_to"`

	// SignupEnabled controls whether the /signup page renders a real
	// registration form. When false the page shows an invitation-only notice.
	// May also be set via the SIGNUP_ENABLED environment variable ("true"/"1").
	SignupEnabled bool `json:"signup_enabled"`
}

// Load reads and parses the JSON config file at path, then applies any
// EMAIL_* / SIGNUP_ENABLED environment variable overrides.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	cfg.applyEnvOverrides()
	return &cfg, nil
}

// applyEnvOverrides replaces email/signup fields with environment variables
// when they are set, so production deployments (e.g. Heroku) can supply
// credentials without a cfg.json entry.
func (c *Config) applyEnvOverrides() {
	if v := os.Getenv("EMAIL_HOST"); v != "" {
		c.EmailHost = v
	}
	if v := os.Getenv("EMAIL_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.EmailPort = n
		}
	}
	if v := os.Getenv("EMAIL_USERNAME"); v != "" {
		c.EmailUsername = v
	}
	if v := os.Getenv("EMAIL_PASSWORD"); v != "" {
		c.EmailPassword = v
	}
	if v := os.Getenv("EMAIL_FROM"); v != "" {
		c.EmailFrom = v
	}
	if v := os.Getenv("EMAIL_REPLY_TO"); v != "" {
		c.EmailReplyTo = v
	}
	if v := os.Getenv("SIGNUP_ENABLED"); v != "" {
		c.SignupEnabled = strings.EqualFold(v, "true") || v == "1"
	}
}

// DSN returns a PostgreSQL connection string built from the config fields.
func (c *Config) DSN() string {
	sslmode := c.DBSSLMode
	if sslmode == "" {
		sslmode = "require"
	}
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		c.DBHost, c.DBPort, c.DBName, c.DBUser, c.DBPassword, sslmode,
	)
}
