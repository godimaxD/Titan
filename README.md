# Titan
run:
go run main.go types.go db.go handlers.go session.go utils.go

Environment:
- `TITAN_ADMIN_PASSWORD`: optional. If set on first run, seeds the admin password with this value. Otherwise a random password is generated and logged once.
