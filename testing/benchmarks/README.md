# Benchmarks

Performance tests for codec operations.

## Running

```bash
make test-bench
```

Or with more detail:

```bash
go test -bench=. -benchmem -benchtime=5s ./testing/benchmarks/...
```

## Benchmarks Included

- `BenchmarkProcessor_Receive` - Unmarshal + hash transforms
- `BenchmarkProcessor_Store` - Clone + encrypt + marshal
- `BenchmarkProcessor_Load` - Unmarshal + decrypt transforms
- `BenchmarkProcessor_Send` - Clone + mask/redact + marshal

## Interpreting Results

```
BenchmarkProcessor_Store-8    500000    3200 ns/op    1024 B/op    12 allocs/op
```

- `500000` - iterations run
- `3200 ns/op` - nanoseconds per operation
- `1024 B/op` - bytes allocated per operation
- `12 allocs/op` - allocations per operation

## Adding Benchmarks

```go
func BenchmarkNewOperation(b *testing.B) {
    proc, _ := codec.NewProcessor[testing.SanitizedUser](json.New())
    proc.SetEncryptor(codec.EncryptAES, testing.TestEncryptor(b))

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        // operation under test
    }
}
```
