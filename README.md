# Titan

A Go + SQLite web application with user/admin panels, deposit tracking, and activity logging.

> **Note on CI badge:** Update the badge URL with your GitHub org/repo once this project is published.

![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Quickstart](#quickstart)
- [Build & Test](#build--test)
- [Configuration](#configuration)
- [Security Notes](#security-notes)
- [API Overview](#api-overview)
- [Folder Structure](#folder-structure)
- [Deployment Notes](#deployment-notes)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features
- Server-rendered HTML pages with shared templates and styling.
- Session-based authentication with CSRF protection on form actions.
- Admin tooling for wallets, products, plans, methods, and activity logs.
- Deposit creation/verification flows backed by SQLite.
- Captcha endpoints for forms.
- Referral codes and credit tracking on purchases.

## Requirements
- Go `1.25.5` (per `go.mod`).
- CGO toolchain for `github.com/mattn/go-sqlite3` (GCC/Clang).
- SQLite (embedded via the Go driver; no external service required).

## Quickstart
```bash
export TITAN_WALLET_KEY="dev-change-me"
go run .
```

- The server listens on `:8080`.
- On first run, an `admin` user is created. If `TITAN_ADMIN_PASSWORD` is unset, a random password is generated and logged once. If `TITAN_ADMIN_API_TOKEN` is set (and not `titan_root`), it is used to seed/rotate the admin API token.

## Build & Test
```bash
go test -v -timeout 10m ./... -count=1
go build ./...
```

Makefile shortcuts:
- `make fmt`
- `make test`
- `make build`
- `make run`

## Configuration

| Environment Variable | Required | Description |
| --- | --- | --- |
| `TITAN_WALLET_KEY` | Yes (for encrypted wallet keys) | Secret used to derive the AES-GCM key for encrypting wallet private keys at rest. If unset, encrypted keys cannot be decrypted. |
| `TITAN_ADMIN_PASSWORD` | No | Seeds the initial admin password on first run. If unset, a random password is generated and logged. |
| `TITAN_ADMIN_API_TOKEN` | No | Seeds or rotates the admin API token if set to a non-default value (not `titan_root`). |
| `TRUST_PROXY` | No | If `true`, honors `X-Forwarded-Proto`/`Forwarded` headers for Secure cookie decisions. |
| `FORCE_SECURE_COOKIES` | No | If `true`, always sets Secure cookies regardless of TLS or proxy headers. |
| `TITAN_DEBUG` | No | Enables deposit debug logging when used by diagnostics helpers. |
| `DEBUG` | No | Alias for `TITAN_DEBUG` (same behavior). |

## Security Notes
- Session and CSRF cookies are `HttpOnly`, `SameSite=Lax`, and set as `Secure` when TLS is in use or when `TRUST_PROXY`/`FORCE_SECURE_COOKIES` are enabled.
- CSRF tokens are stored in a cookie and validated against form fields or the `X-CSRF-Token` header.
- If TLS is terminated upstream, enable `TRUST_PROXY=true` only when the reverse proxy overwrites forwarded headers to prevent spoofing.

## API Overview

### Public & Auth Pages
- `GET /` (landing)
- `GET /login`, `POST /login`
- `GET /register`, `POST /register`
- `GET /logout`
- `GET /token-login`, `POST /token-login`
- `GET /redeem-login`, `POST /redeem-login`
- `GET /captcha/` (captcha image)

### User Pages
- `GET /dashboard`
- `GET /panel`
- `GET /panel/l4`
- `GET /panel/l7`
- `GET /deposit`
- `GET /market`
- `GET /support`
- `GET /documentation`
- `GET /profile`
- `GET /status`
- `GET /invoice`
- `GET /deposit/pay`
- `GET /receipt`
- `GET /receipt/download`

### Admin Pages
- `GET /admin`

### JSON APIs
- Deposits: `POST /api/deposit/create`, `GET /api/deposit/check`
- Wallets (admin): `POST /api/admin/add-wallet`, `POST /api/admin/del-wallet`
- Market: `POST /api/market/purchase`
- User: `GET /api/user/info`, `POST /api/user/change-password`, `POST /api/user/token/rotate`
- Sessions: `GET /api/user/sessions`, `POST /api/user/sessions/revoke`, `POST /api/user/sessions/revoke-all`
- Captcha: `GET /api/captcha/new`
- Panel operations: `POST /api/attack`, `GET /api/attack/list`, `POST /api/attack/stop`, `POST /api/attack/stopAll`
- Admin config: `POST /api/admin/gen-code`, `POST /api/admin/config-plans`, `POST /api/admin/add-product`, `POST /api/admin/del-product`
- Admin moderation: `POST /api/admin/blacklist`, `POST /api/admin/upload-method`, `POST /api/admin/deposit/action`
- Tickets: `POST /api/ticket/create`, `POST /api/ticket/reply`
- Public token: `POST /api/launch`
- Activity logs (admin): `GET /api/admin/activity/search`, `GET /api/admin/activity/export`, `GET /api/admin/activity/actions`, `GET /api/admin/activity/download`

## Folder Structure
```
.
├── .github/                 # GitHub workflows and templates
├── templates/               # HTML templates
├── main.go                  # Server entrypoint + route setup
├── handlers.go              # HTTP handlers
├── db.go                    # SQLite schema + migrations
├── session.go               # Session and cookie helpers
├── activity_log.go          # Activity logging
└── utils.go                 # Shared helpers and utilities
```

## Deployment Notes
- Run from the repository root so templates resolve correctly.
- Use a reverse proxy (nginx/Caddy) for TLS termination.
- If TLS is terminated upstream, set `TRUST_PROXY=true` or `FORCE_SECURE_COOKIES=true` to ensure Secure cookies.

## Troubleshooting
- **SQLite build failures:** `github.com/mattn/go-sqlite3` requires CGO and a C compiler. Install GCC/Clang.
- **Template errors on startup:** ensure you run from the repo root so `templates/` is available.
- **Wallet decryption errors:** set `TITAN_WALLET_KEY` to the same value used to encrypt existing wallet keys.

## License
MIT. See [LICENSE](LICENSE).
