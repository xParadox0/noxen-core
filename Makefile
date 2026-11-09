# Developer entry points for the files in this repository.

GO            ?= go
GOLANGCI_LINT ?= golangci-lint

.DEFAULT_GOAL := check

.PHONY: check vet lint test-go vuln-scan hooks-install

## check: go vet and the tests (no network)
check: vet test-go

vet:
	$(GO) vet ./...

lint:
	$(GOLANGCI_LINT) run ./...

test-go:
	$(GO) test -count=1 ./...

## vuln-scan: Go vulnerability gate (needs the network and govulncheck)
vuln-scan:
	@set -e; \
	vc=""; \
	if [ -x "$(HOME)/.local/bin/govulncheck" ]; then vc="$(HOME)/.local/bin/govulncheck"; \
	elif command -v govulncheck >/dev/null 2>&1; then vc=govulncheck; fi; \
	if [ -z "$$vc" ]; then echo "FAIL vuln-scan: govulncheck not found" >&2; exit 1; fi; \
	tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	"$$vc" -json ./... > "$$tmp/govulncheck.json" || { echo "FAIL vuln-scan: govulncheck did not complete" >&2; exit 1; }; \
	$(GO) run ./tools/depscan/cmd/depscan govulncheck "$$tmp/govulncheck.json"

## hooks-install: enforce the commit rules via .githooks/commit-msg
hooks-install:
	git config core.hooksPath .githooks
