# GoYAUL.Web

A Go library for building authenticated web experiences.
Part of the YAUL family alongside [PyYAUL.Web](https://github.com/defcello/PyYAUL.Web).

## What's included

**`auth`** — Login logic, session types, and the `LoginDB` interface:
- `Login()` — validates credentials, applies IP rate limiting and brute-force lockout escalation
- `LoginDB` interface — implement this against any database to use the login flow
- `SessionRecord`, `UserLookupResult`, `LogLoginParams` — shared types

**`middleware`** — Standard `net/http` compatible middlewares:
- `SecurityHeaders` — sets X-Content-Type-Options, X-Frame-Options, Referrer-Policy
- `RequestLogger` — logs method, path, status code, and duration
- `LoadSession(cookieName, db)` — reads session cookie, validates against DB, attaches to context
- `RequireAuth` — redirects to /login if no valid session in context
- `SessionFromContext` / `WithSession` — context helpers

**`config`** — JSON config loader:
- `Load(path)` — reads cfg.json into a `Config` struct
- `Config.DSN()` — builds a PostgreSQL connection string

## Requirements

- Go 1.22.4+
- `golang.org/x/crypto`

## Usage

```go
import (
    "github.com/defcello/goyaul-web/auth"
    "github.com/defcello/goyaul-web/config"
    "github.com/defcello/goyaul-web/middleware"
)

// Load config
cfg, _ := config.Load("cfg.json")

// Use middleware
r.Use(middleware.SecurityHeaders)
r.Use(middleware.LoadSession("myapp_session", database))

// Login
result := auth.Login(ctx, database, ip, userAgent, usernameOrEmail, password, rememberMe)
```

## Notes

- UPGRADE AT YOUR OWN RISK — backwards compatibility is not guaranteed between versions.

## License

MIT
