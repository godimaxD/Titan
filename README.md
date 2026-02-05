# Titan
run:
go run main.go types.go db.go handlers.go session.go utils.go

Environment:
- `TITAN_ADMIN_PASSWORD`: optional. If set on first run, seeds the admin password with this value. Otherwise a random password is generated and logged once.
- `TITAN_WALLET_KEY`: required to encrypt wallet private keys at rest (set to any strong secret).
- `TRUST_PROXY`: optional. If true, honor `X-Forwarded-Proto`/`Forwarded` headers from a trusted reverse proxy to decide Secure cookies.
- `FORCE_SECURE_COOKIES`: optional. If true, always set Secure cookies regardless of TLS or proxy headers.

Reverse proxy TLS termination:
- If TLS is terminated upstream, set `TRUST_PROXY=true` and ensure your proxy strips/spoofs forwarded headers from untrusted clients.
- Alternatively, set `FORCE_SECURE_COOKIES=true` to always mark CSRF/session cookies as Secure.
- Only enable `TRUST_PROXY` when the app is behind a trusted proxy that overwrites `X-Forwarded-Proto`/`Forwarded` headers to prevent spoofing.
