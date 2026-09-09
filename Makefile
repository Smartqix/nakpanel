.PHONY: build generate sqlc-generate templ-generate tailwind-download tailwind-build test security goose-up goose-down goose-status river-up river-down river-status

DB_DSN ?= $(if $(NAKPANEL_DATABASE_URL),$(NAKPANEL_DATABASE_URL),postgres://postgres@localhost:5432/nakpanel?sslmode=disable)
VERSION ?= $(shell cat VERSION 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X github.com/nakroteck/nakpanel/internal/version.Version=$(VERSION) -X github.com/nakroteck/nakpanel/internal/version.Commit=$(COMMIT)
TAILWIND_VERSION ?= v3.4.17
TAILWIND_BIN ?= bin/tailwindcss

generate: sqlc-generate templ-generate tailwind-build

sqlc-generate:
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.30.0 generate

templ-generate:
	go run github.com/a-h/templ/cmd/templ@v0.3.960 generate

tailwind-download:
	@mkdir -p bin
	@if [ ! -x "$(TAILWIND_BIN)" ] || ! "$(TAILWIND_BIN)" --help >/dev/null 2>&1; then \
		os="$$(uname -s | tr '[:upper:]' '[:lower:]')"; \
		arch="$$(uname -m)"; \
		case "$$os" in darwin) os="macos" ;; linux) os="linux" ;; *) echo "unsupported OS for Tailwind standalone: $$os" >&2; exit 1 ;; esac; \
		case "$$arch" in x86_64|amd64) arch="x64" ;; arm64|aarch64) arch="arm64" ;; *) echo "unsupported architecture for Tailwind standalone: $$arch" >&2; exit 1 ;; esac; \
		if curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 -o "$(TAILWIND_BIN)" "https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/tailwindcss-$$os-$$arch"; then \
			chmod +x "$(TAILWIND_BIN)"; \
		elif [ -s internal/control/web/static/app.css ]; then \
			echo "warning: Tailwind download unavailable; using committed embedded CSS" >&2; \
		else \
			exit 1; \
		fi; \
	fi

tailwind-build: tailwind-download
	@if [ -x "$(TAILWIND_BIN)" ]; then \
		BROWSERSLIST_IGNORE_OLD_DATA=1 "$(TAILWIND_BIN)" -i internal/control/web/assets/input.css -o internal/control/web/static/app.css --minify --content 'internal/control/web/**/*.{templ,js,go}'; \
	elif [ ! -s internal/control/web/static/app.css ]; then \
		echo "Tailwind compiler and committed embedded CSS are both unavailable" >&2; \
		exit 1; \
	fi

build: generate
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/panel ./cmd/panel
	go build -ldflags "$(LDFLAGS)" -o bin/agent ./cmd/agent
	go build -ldflags "$(LDFLAGS)" -o bin/panelctl ./cmd/panelctl

test:
	go test ./...

# Adversarial validation suite (the production gate). Provisions two hostile
# tenants on a throwaway Multipass VM and asserts every attack is blocked;
# exits non-zero if any attack succeeds. Requires Multipass.
security:
	./deploy/multipass/security-verify.sh

goose-up:
	go run github.com/pressly/goose/v3/cmd/goose@v3.24.0 -dir migrations postgres "$(DB_DSN)" up

goose-down:
	go run github.com/pressly/goose/v3/cmd/goose@v3.24.0 -dir migrations postgres "$(DB_DSN)" down

goose-status:
	go run github.com/pressly/goose/v3/cmd/goose@v3.24.0 -dir migrations postgres "$(DB_DSN)" status

river-up:
	go run github.com/riverqueue/river/cmd/river@v0.19.0 migrate-up --line main --database-url "$(DB_DSN)"

river-down:
	go run github.com/riverqueue/river/cmd/river@v0.19.0 migrate-down --line main --database-url "$(DB_DSN)"

river-status:
	go run github.com/riverqueue/river/cmd/river@v0.19.0 migrate-list --line main --database-url "$(DB_DSN)"
