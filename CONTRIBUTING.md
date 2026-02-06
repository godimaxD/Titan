# Contributing to Titan

Thanks for your interest in improving Titan! This project welcomes issues and pull requests.

## Development setup

### Requirements
- Go (see `go.mod` for the required version)
- CGO toolchain for `github.com/mattn/go-sqlite3` (e.g., GCC/Clang)

### Local commands
```bash
go test -v -timeout 10m ./...
go build ./...
```

### Formatting
```bash
gofmt -w ./...
```

## Pull request guidelines
- Keep changes focused and minimal.
- Add or update tests when changing behavior.
- Update documentation when adding or changing features.
- Ensure `go test` and `go build` pass locally.

## Reporting issues
Please include:
- Steps to reproduce
- Expected vs. actual behavior
- Go version and OS details
- Logs or stack traces (redact secrets)
