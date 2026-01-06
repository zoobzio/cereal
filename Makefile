.DEFAULT_GOAL := help

# Run all tests with race detector
.PHONY: test
test:
	go test -race ./...

# Run unit tests only (with -short flag)
.PHONY: test-unit
test-unit:
	go test -race -short ./...

# Run integration tests
.PHONY: test-integration
test-integration:
	go test -race ./testing/integration/...

# Run benchmarks
.PHONY: test-bench
test-bench:
	go test -bench=. -benchmem ./testing/benchmarks/...

# Run golangci-lint
.PHONY: lint
lint:
	golangci-lint run ./...

# Run linter with auto-fix
.PHONY: lint-fix
lint-fix:
	golangci-lint run --fix ./...

# Generate HTML coverage report
.PHONY: coverage
coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Remove generated files
.PHONY: clean
clean:
	rm -f coverage.out coverage.html

# Quick validation (test + lint)
.PHONY: check
check: test lint

# Full CI simulation
.PHONY: ci
ci: clean lint test coverage

# Install git hooks
.PHONY: install-hooks
install-hooks:
	@echo "No hooks configured"

# Install development tools
.PHONY: install-tools
install-tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6

# Display available targets
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  test             Run all tests with race detector"
	@echo "  test-unit        Run unit tests only (with -short flag)"
	@echo "  test-integration Run integration tests"
	@echo "  test-bench       Run benchmarks"
	@echo "  lint             Run golangci-lint"
	@echo "  lint-fix         Run linter with auto-fix"
	@echo "  coverage         Generate HTML coverage report"
	@echo "  clean            Remove generated files"
	@echo "  check            Quick validation (test + lint)"
	@echo "  ci               Full CI simulation"
	@echo "  install-hooks    Install git hooks"
	@echo "  install-tools    Install development tools"
	@echo "  help             Display this help"
