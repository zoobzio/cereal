package benchmarks

import (
	"testing"

	"github.com/zoobzio/codec"
	"github.com/zoobzio/codec/pkg/json"
	codectest "github.com/zoobzio/codec/testing"
)

func BenchmarkProcessor_Store_NoTransformation(b *testing.B) {
	proc, _ := codec.NewProcessor[codectest.SimpleUser](json.New())
	user := &codectest.SimpleUser{ID: "123", Name: "Alice"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = proc.Store(user)
	}
}

func BenchmarkProcessor_Store_WithEncryption(b *testing.B) {
	proc, _ := codec.NewProcessor[codectest.SanitizedUser](
		json.New(),
		codec.WithKey(codec.EncryptAES, codectest.TestKey()),
	)

	user := &codectest.SanitizedUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "secret",
		SSN:      "123-45-6789",
		Note:     "internal note",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = proc.Store(user)
	}
}

func BenchmarkProcessor_Load_WithDecryption(b *testing.B) {
	proc, _ := codec.NewProcessor[codectest.SanitizedUser](
		json.New(),
		codec.WithKey(codec.EncryptAES, codectest.TestKey()),
	)

	user := &codectest.SanitizedUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "secret",
		SSN:      "123-45-6789",
		Note:     "internal note",
	}

	data, _ := proc.Store(user)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = proc.Load(data)
	}
}

func BenchmarkProcessor_Send_WithMaskingRedaction(b *testing.B) {
	proc, _ := codec.NewProcessor[codectest.SanitizedUser](
		json.New(),
		codec.WithKey(codec.EncryptAES, codectest.TestKey()),
	)

	user := &codectest.SanitizedUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "secret",
		SSN:      "123-45-6789",
		Note:     "internal note",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = proc.Send(user)
	}
}

func BenchmarkAES_Encrypt(b *testing.B) {
	enc := codectest.TestEncryptor()
	plaintext := []byte("this is a test message for encryption benchmarking")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = enc.Encrypt(plaintext)
	}
}

func BenchmarkHasher_Argon2(b *testing.B) {
	h := codec.Argon2()
	data := []byte("password123")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Hash(data)
	}
}

func BenchmarkHasher_SHA256(b *testing.B) {
	h := codec.SHA256Hasher()
	data := []byte("this is a test message for hashing benchmarking")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Hash(data)
	}
}
