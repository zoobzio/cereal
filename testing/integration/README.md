# Integration Tests

End-to-end tests verifying complete workflows across boundaries.

## Running

```bash
make test-integration
```

## Coverage

Integration tests exercise:

- Full receive → store → load → send lifecycle
- All codec providers (JSON, XML, YAML, MessagePack, BSON)
- Encryption/decryption roundtrips
- Hash verification
- Mask and redact output

## Adding Tests

Place new integration tests in this directory with `_test.go` suffix. Use the test helpers from the parent `testing` package:

```go
package integration

import (
    "testing"

    helper "github.com/zoobzio/cereal/testing"
)

func TestNewWorkflow(t *testing.T) {
    enc := helper.TestEncryptor(t)
    // ...
}
```
