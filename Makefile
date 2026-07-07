.PHONY: build generate sqlc-generate templ-generate tailwind-download tailwind-build test goose-up goose-down goose-status

DB_DSN ?= $(if $(NAKPANEL_DATABASE_URL),$(NAKPANEL_DATABASE_URL),postgres://postgres@localhost:5432/nakpanel?sslmode=disable)
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
		curl -fsSL -o "$(TAILWIND_BIN)" "https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/tailwindcss-$$os-$$arch"; \
		chmod +x "$(TAILWIND_BIN)"; \
	fi

tailwind-build: tailwind-download
	BROWSERSLIST_IGNORE_OLD_DATA=1 $(TAILWIND_BIN) -i internal/control/web/assets/input.css -o internal/control/web/static/app.css --minify --content internal/control/web/pages.templ

build: generate
	mkdir -p bin
	go build -o bin/panel ./cmd/panel
	go build -o bin/agent ./cmd/agent

test:
	go test ./...

goose-up:
	go run github.com/pressly/goose/v3/cmd/goose@v3.24.0 -dir migrations postgres "$(DB_DSN)" up

goose-down:
	go run github.com/pressly/goose/v3/cmd/goose@v3.24.0 -dir migrations postgres "$(DB_DSN)" down

goose-status:
	go run github.com/pressly/goose/v3/cmd/goose@v3.24.0 -dir migrations postgres "$(DB_DSN)" status
