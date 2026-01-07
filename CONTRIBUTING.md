# Contributing to Cereal

Thank you for considering contributing to Cereal.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/zoobzio/cereal.git
cd cereal

# Install development tools
make install-tools

# Run tests to verify setup
make test
```

## Development Workflow

### Available Commands

Run `make help` to see all available commands:

```
make test             Run all tests with race detector
make test-unit        Run unit tests only (with -short flag)
make test-integration Run integration tests
make test-bench       Run benchmarks
make lint             Run golangci-lint
make lint-fix         Run linter with auto-fix
make coverage         Generate HTML coverage report
make check            Quick validation (test + lint)
make ci               Full CI simulation
```

### Before Submitting

1. **Run the full check**: `make check`
2. **Ensure tests pass**: `make test`
3. **Check coverage**: `make coverage`

### Commit Messages

Use conventional commit format:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test additions or changes
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

Example: `feat: add TOML codec provider`

## Pull Requests

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run `make ci` to simulate CI checks
5. Submit a pull request

Please open an issue to discuss significant changes before starting work.

## Code Style

- Follow standard Go conventions
- Run `make lint` before committing
- Add tests for new functionality
- Update documentation as needed

## Testing

- Unit tests live alongside source files (`*_test.go`)
- Integration tests go in `testing/integration/`
- Benchmarks go in `testing/benchmarks/`
- Test helpers go in `testing/helpers.go`

## Questions?

Open an issue for questions or discussion.
