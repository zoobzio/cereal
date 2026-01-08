# Cereal

[![CI](https://github.com/zoobzio/cereal/actions/workflows/ci.yml/badge.svg)](https://github.com/zoobzio/cereal/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/zoobzio/cereal/branch/main/graph/badge.svg)](https://codecov.io/gh/zoobzio/cereal)
[![Go Report Card](https://goreportcard.com/badge/github.com/zoobzio/cereal)](https://goreportcard.com/report/github.com/zoobzio/cereal)
[![CodeQL](https://github.com/zoobzio/cereal/actions/workflows/codeql.yml/badge.svg)](https://github.com/zoobzio/cereal/actions/workflows/codeql.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/zoobzio/cereal.svg)](https://pkg.go.dev/github.com/zoobzio/cereal)
[![License](https://img.shields.io/github/license/zoobzio/cereal)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/zoobzio/cereal)](https://github.com/zoobzio/cereal)
[![Release](https://img.shields.io/github/v/release/zoobzio/cereal)](https://github.com/zoobzio/cereal/releases)

Boundary-aware serialization for Go. Transform data differently as it crosses system boundaries—encrypt for storage, mask for APIs, hash on receive.

## Four Boundaries, One Processor

Data crosses boundaries constantly. Each crossing demands different treatment:

```go
type User struct {
    ID       string `json:"id"`
    Email    string `json:"email" store.encrypt:"aes" load.decrypt:"aes" send.mask:"email"`
    Password string `json:"password" receive.hash:"sha256"`
    SSN      string `json:"ssn" send.mask:"ssn"`
    Token    string `json:"token" send.redact:"[REDACTED]"`
}
```

- **Receive** — Data arriving from external sources. Hash passwords, normalize inputs.
- **Load** — Data coming from storage. Decrypt sensitive fields.
- **Store** — Data going to storage. Encrypt before persisting.
- **Send** — Data going to external destinations. Mask PII, redact secrets.

The struct declares intent. The processor handles the rest.

## Install

```bash
go get github.com/zoobzio/cereal
```

Requires Go 1.24+

## Quick Start

```go
package main

import (
    "context"
    "fmt"

    "github.com/zoobzio/cereal"
    "github.com/zoobzio/cereal/json"
)

type User struct {
    ID       string `json:"id"`
    Email    string `json:"email" store.encrypt:"aes" load.decrypt:"aes" send.mask:"email"`
    Password string `json:"password" receive.hash:"sha256"`
}

func (u User) Clone() User { return u }

func main() {
    ctx := context.Background()

    // Create processor with JSON codec
    proc, _ := cereal.NewProcessor[User](json.New())

    // Configure encryption
    enc, _ := cereal.AES([]byte("32-byte-key-for-aes-256-encrypt!"))
    proc.SetEncryptor(cereal.EncryptAES, enc)

    user := &User{
        ID:       "123",
        Email:    "alice@example.com",
        Password: "secret",
    }

    // Store: encrypts email before persisting
    stored, _ := proc.Store(ctx, user)
    fmt.Println(string(stored))
    // {"id":"123","email":"<encrypted>","password":"secret"}

    // Load: decrypts email from storage
    loaded, _ := proc.Load(ctx, stored)
    fmt.Println(loaded.Email)
    // alice@example.com

    // Send: masks email for API response
    sent, _ := proc.Send(ctx, user)
    fmt.Println(string(sent))
    // {"id":"123","email":"a***@example.com","password":"secret"}
}
```

## Capabilities

| Capability | Boundaries | Description                                   | Docs                                    |
| ---------- | ---------- | --------------------------------------------- | --------------------------------------- |
| Encryption | store/load | AES-GCM, RSA-OAEP, envelope                   | [Guide](docs/3.guides/1.encryption.md)  |
| Masking    | send       | Email, SSN, phone, card, IP, UUID, IBAN, name | [Guide](docs/3.guides/2.masking.md)     |
| Hashing    | receive    | SHA-256, SHA-512, Argon2, bcrypt              | [Reference](docs/5.reference/2.tags.md) |
| Redaction  | send       | Full replacement with custom string           | [Reference](docs/5.reference/2.tags.md) |

## Why Cereal?

- **Boundary-specific transforms** — Different rules for storage vs. API responses vs. incoming data
- **Declarative via struct tags** — Security requirements live with the type definition
- **Non-destructive** — Original values never modified; processor clones before transforming
- **Type-safe generics** — `Processor[User]` only accepts `*User`
- **Thread-safe** — Processors safe for concurrent use across goroutines
- **Provider agnostic** — JSON, YAML, XML, MessagePack, BSON with identical semantics
- **Observable** — Emits signals for metrics and tracing via capitan

## Security as Structure

Cereal enables a pattern: **declare sensitivity once, enforce everywhere**.

Data sensitivity lives in the type definition, not scattered across handlers. When a field is marked for encryption or masking, every boundary crossing respects that declaration automatically. Business logic remains unaware of security transforms—it works with plain structs while the processor handles the rest.

```go
// The type declares intent
type Payment struct {
    ID     string `json:"id"`
    Card   string `json:"card" store.encrypt:"aes" send.mask:"card"`
    Amount int    `json:"amount"`
}

// Business logic stays clean
func ProcessPayment(p *Payment) error {
    // No encryption calls, no masking logic
    // Just domain operations on plain fields
    return chargeCard(p.Card, p.Amount)
}

// Boundaries handle transforms
stored, _ := proc.Store(ctx, payment)   // Card encrypted
response, _ := proc.Send(ctx, payment)  // Card masked
```

Security requirements change in one place. Every serialization path follows.

## Documentation

- [Overview](docs/1.overview.md) — Design philosophy

### Learn

- [Quick Start](docs/2.learn/1.quickstart.md) — Get started in minutes
- [Concepts](docs/2.learn/2.concepts.md) — Boundaries, processors, transforms
- [Architecture](docs/2.learn/3.architecture.md) — Internal design and components

### Guides

- [Encryption](docs/3.guides/1.encryption.md) — AES, RSA, envelope encryption
- [Masking](docs/3.guides/2.masking.md) — PII protection for API responses
- [Providers](docs/3.guides/3.providers.md) — JSON, YAML, XML, MessagePack, BSON

### Cookbook

- [Escape Hatches](docs/4.cookbook/1.escape-hatches.md) — Custom transforms and overrides
- [Key Rotation](docs/4.cookbook/2.key-rotation.md) — Zero-downtime encryption key updates
- [Code Generation](docs/4.cookbook/3.code-generation.md) — Generating processors from schemas

### Reference

- [API](docs/5.reference/1.api.md) — Complete function documentation
- [Tags](docs/5.reference/2.tags.md) — All struct tag options
- [Errors](docs/5.reference/3.errors.md) — Error types and handling

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License — see [LICENSE](LICENSE) for details.
