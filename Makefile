# ═══════════════════════════════════════════════════════════════
# SambaGuard — Makefile
# Control, Secure, Monitor — All in One.
# ═══════════════════════════════════════════════════════════════

BINARY      := sambaguard
BUILD_DIR   := ./bin
CMD_PATH    := ./cmd/server
MODULE      := github.com/buadamlaz/sambaguard
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS     := -ldflags="-w -s -X main.version=$(VERSION)"
BUILD_FLAGS := -trimpath $(LDFLAGS)

.PHONY: all build run test lint fmt vet tidy docker docker-run docker-stop docker-logs clean setup-env generate-secrets install-tools help

## all: Tidy, format, vet, build
all: tidy fmt vet build

## build: Compile Linux binary (deployment target)
build:
	@echo "▶ Building $(BINARY) for linux/amd64..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD_PATH)
	@echo "✓ $(BUILD_DIR)/$(BINARY)"

## build-local: Compile for current OS (for local testing only)
build-local:
	@echo "▶ Building $(BINARY) for local OS..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD_PATH)
	@echo "✓ $(BUILD_DIR)/$(BINARY)"

## run: Run in development mode (requires .env)
run:
	@if [ ! -f .env ]; then echo "⚠  .env not found — run 'make setup-env' first"; exit 1; fi
	set -a; source .env; set +a; ENVIRONMENT=development go run $(CMD_PATH)

## test: Run all tests with race detector
test:
	go test -race -count=1 ./...

## test-coverage: Run tests and generate HTML coverage report
test-coverage:
	go test -race -count=1 -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✓ coverage.html"

## lint: Run golangci-lint
lint:
	@which golangci-lint > /dev/null 2>&1 || \
		(echo "⚠  golangci-lint not installed. See: https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

## fmt: Format all Go source files
fmt:
	gofmt -w -s .
	@which goimports > /dev/null 2>&1 && goimports -w . || true

## vet: Run go vet
vet:
	go vet ./...

## tidy: Tidy and verify Go modules
tidy:
	go mod tidy
	go mod verify

## generate-secrets: Print new JWT_SECRET and CSRF_SECRET to stdout
generate-secrets:
	@echo "JWT_SECRET=$$(openssl rand -hex 32)"
	@echo "CSRF_SECRET=$$(openssl rand -hex 32)"

## setup-env: Create .env from .env.example with auto-generated secrets
setup-env:
	@if [ -f .env ]; then echo "ℹ  .env already exists — delete it first to regenerate"; exit 0; fi
	@cp .env.example .env
	@JWT_SECRET=$$(openssl rand -hex 32); \
	 CSRF_SECRET=$$(openssl rand -hex 32); \
	 sed -i "s|^JWT_SECRET=.*|JWT_SECRET=$$JWT_SECRET|" .env; \
	 sed -i "s|^CSRF_SECRET=.*|CSRF_SECRET=$$CSRF_SECRET|" .env
	@echo "✓ .env created with auto-generated secrets"

## docker: Build Docker image tagged sambaguard:latest
docker:
	docker build -t sambaguard:latest .
	@echo "✓ Image: sambaguard:latest"

## docker-run: Start with docker compose (creates .env if missing)
docker-run:
	@if [ ! -f .env ]; then make setup-env; fi
	docker compose up -d
	@echo "✓ SambaGuard running → http://localhost:8080"
	@echo "  Check logs for admin password: make docker-logs"

## docker-stop: Stop docker compose stack
docker-stop:
	docker compose down

## docker-logs: Follow container logs
docker-logs:
	docker compose logs -f sambaguard

## install-tools: Install Go development tools
install-tools:
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

## clean: Remove build artifacts and coverage reports
clean:
	@rm -rf $(BUILD_DIR) coverage.out coverage.html
	@echo "✓ Cleaned"

## help: List all available targets
help:
	@echo ""
	@echo "  SambaGuard — Available make targets"
	@echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@grep -E '^## ' Makefile | sed 's/## /  /'
	@echo ""
