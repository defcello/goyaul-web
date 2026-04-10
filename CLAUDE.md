# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**goyaul-web** is a generic Go web authentication framework extracted from SkillTrails. It provides login logic, HTTP middleware, and configuration loading for Go web applications built with chi.

This repo is one of several sub-repos managed under `devenv-skilltrails/` via `manifest.xml`.

## Commands

> **Note:** This repo lives on a UNC network share. Always pass `-buildvcs=false` to
> `go build` and `go vet`.

```bash
# Run tests
go test -buildvcs=false ./...

# Vet
go vet -buildvcs=false ./...
```

### CSS / Frontend

Node.js is required for the Tailwind CSS build. On Windows, `node` may not be in the
bash PATH — add it first:

```bash
export PATH="/c/Program Files/nodejs:$PATH"
```

```bash
# One-time: install dev dependencies
npm install

# Build minified CSS (run after editing input.css or templates)
npm run build

# Watch mode during development
npm run watch
```

`pages/static/css/style.css` is the **compiled output** — always commit it alongside
any change to `input.css` or the templates so consumers get the updated styles via
`go get`.  Never edit `style.css` directly; edit `input.css` instead.

## Architecture

```
auth/auth.go        — Login(), lockout logic, in-memory IP rate limiter
                      Types: SessionRecord, UserLookupResult, LogLoginParams, ErrNotFound
                      Interface: LoginDB (implemented by consumers e.g. skilltrails/internal/db)
auth/auth_test.go   — Unit tests (14 tests, stub LoginDB)
middleware/         — SecurityHeaders, RequestLogger, LoadSession(cookieName, SessionDB), RequireAuth,
                      NewUserRateLimit(max, window) — in-memory per-user POST rate limiter
                      SessionFromContext / WithSession helpers
                      SetFlash(w, key, msg, secure) / ConsumeFlash(w, r, key) — HMAC-SHA256 signed cookie
config/config.go    — cfg.json parsing + DSN builder
```

## Design Principles

- No application-specific logic — consumers provide DB implementations via interfaces
- `LoginDB` interface: all methods needed for login/lockout/session creation
- `SessionDB` interface: `GetSessionByCookieID` + `TouchSession` for request middleware
- Cookie name is a `LoadSession` parameter — not hardcoded
- Only external dependency: `golang.org/x/crypto` (bcrypt)
- **Framework-agnostic layout**: `page-head` loads only the compiled Tailwind CSS. Do NOT add JS framework CDN links here. Consumers inject their stack by overriding the `page-head-extra` template (default is a no-op). See skilltrails `layout_override.html` for the pattern.

> **Tailwind JIT scope**: `tailwind.config.js` only scans `./pages/templates/**/*.html`. Consumer templates in other repos will not be scanned — consumers must either use the CDN Play script or compile Tailwind locally.

## Dependencies

- `golang.org/x/crypto` — bcrypt password hashing

## Consumers

- `github.com/defcello/skilltrails` — depends on versioned releases; use a `replace` directive in skilltrails/go.mod only during local development
