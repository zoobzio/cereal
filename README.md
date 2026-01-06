# Codec

[![CI](https://github.com/zoobzio/codec/actions/workflows/ci.yml/badge.svg)](https://github.com/zoobzio/codec/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/zoobzio/codec/branch/main/graph/badge.svg)](https://codecov.io/gh/zoobzio/codec)
[![Go Report Card](https://goreportcard.com/badge/github.com/zoobzio/codec)](https://goreportcard.com/report/github.com/zoobzio/codec)
[![CodeQL](https://github.com/zoobzio/codec/actions/workflows/codeql.yml/badge.svg)](https://github.com/zoobzio/codec/actions/workflows/codeql.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/zoobzio/codec.svg)](https://pkg.go.dev/github.com/zoobzio/codec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/zoobzio/codec)](https://github.com/zoobzio/codec)
[![Release](https://img.shields.io/github/v/release/zoobzio/codec)](https://github.com/zoobzio/codec/releases)

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
go get github.com/zoobzio/codec
```

Requires Go 1.24+

## Quick Start

```go
package main

import (
    "context"
    "fmt"

    "github.com/zoobzio/codec"
    "github.com/zoobzio/codec/json"
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
    proc, _ := codec.NewProcessor[User](json.New())

    // Configure encryption
    enc, _ := codec.AES([]byte("32-byte-key-for-aes-256-encrypt!"))
    proc.SetEncryptor(codec.EncryptAES, enc)

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

## Why Codec?

- **Boundary-specific transforms** — Different rules for storage vs. API responses vs. incoming data
- **Declarative via struct tags** — Security requirements live with the type definition
- **Non-destructive** — Original values never modified; processor clones before transforming
- **Type-safe generics** — `Processor[User]` only accepts `*User`
- **Thread-safe** — Processors safe for concurrent use across goroutines
- **Provider agnostic** — JSON, YAML, XML, MessagePack, BSON with identical semantics
- **Observable** — Emits signals for metrics and tracing via capitan

## Documentation

**Learn**

- [Quick Start](docs/2.learn/1.quickstart.md)
- [Concepts](docs/2.learn/2.concepts.md)

**Guides**

- [Encryption](docs/3.guides/1.encryption.md)
- [Masking](docs/3.guides/2.masking.md)
- [Providers](docs/3.guides/3.providers.md)

**Cookbook**

- [Escape Hatches](docs/4.cookbook/1.escape-hatches.md)
- [Key Rotation](docs/4.cookbook/2.key-rotation.md)
- [Code Generation](docs/4.cookbook/3.code-generation.md)

**Reference**

- [API](docs/5.reference/1.api.md)
- [Tags](docs/5.reference/2.tags.md)
- [Errors](docs/5.reference/3.errors.md)

## Contributing

Contributions welcome. Please open an issue to discuss significant changes before submitting a PR.

## License

MIT
