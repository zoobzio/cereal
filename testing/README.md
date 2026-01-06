# Testing

Test utilities and structure for codec.

## Structure

```
testing/
├── helpers.go          # Test utilities and fixtures
├── helpers_test.go     # Tests for helpers
├── integration/        # End-to-end tests
│   └── roundtrip_test.go
└── benchmarks/         # Performance tests
    └── serializer_bench_test.go
```

## Running Tests

```bash
# All tests with race detector
make test

# Unit tests only (fast)
make test-unit

# Integration tests
make test-integration

# Benchmarks
make test-bench

# Coverage report
make coverage
```

## Test Helpers

`helpers.go` provides:

- `TestKey()` - 32-byte AES key for testing
- `TestEncryptor()` - Pre-configured AES encryptor
- `SimpleUser` - Basic test type without transforms
- `SanitizedUser` - Test type with full boundary tags

## Writing Tests

Unit tests live alongside source files. Use the test helpers for consistent fixtures:

```go
func TestExample(t *testing.T) {
    enc := testing.TestEncryptor()
    proc, _ := codec.NewProcessor[testing.SanitizedUser](json.New())
    proc.SetEncryptor(codec.EncryptAES, enc)
    // ...
}
```
