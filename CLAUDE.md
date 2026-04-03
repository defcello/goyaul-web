# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**GoYAUL.Web** is a generic Go web authentication framework extracted from SkillTrails. It provides login logic, HTTP middleware, and configuration loading for Go web applications built with chi.

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

## Architecture

```
auth/auth.go        — Login(), lockout logic, in-memory IP rate limiter
                      Types: SessionRecord, UserLookupResult, LogLoginParams, ErrNotFound
                      Interface: LoginDB (implemented by consumers e.g. skilltrails/internal/db)
auth/auth_test.go   — Unit tests (14 tests, stub LoginDB)
middleware/         — SecurityHeaders, RequestLogger, LoadSession(cookieName, SessionDB), RequireAuth,
                      NewUserRateLimit(max, window) — in-memory per-user POST rate limiter
                      SessionFromContext / WithSession helpers
config/config.go    — cfg.json parsing + DSN builder
```

## Design Principles

- No application-specific logic — consumers provide DB implementations via interfaces
- `LoginDB` interface: all methods needed for login/lockout/session creation
- `SessionDB` interface: `GetSessionByCookieID` + `TouchSession` for request middleware
- Cookie name is a `LoadSession` parameter — not hardcoded
- Only external dependency: `golang.org/x/crypto` (bcrypt)

## Dependencies

- `golang.org/x/crypto` — bcrypt password hashing

## Consumers

- `github.com/defcello/skilltrails` — uses local replace: `replace github.com/defcello/goyaul-web => ../GoYAUL.Web`
