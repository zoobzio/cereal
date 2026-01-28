package benchmarks

import (
	"context"
	"testing"

	"github.com/zoobzio/cereal"
	"github.com/zoobzio/cereal/json"
	codectest "github.com/zoobzio/cereal/testing"
)

func BenchmarkProcessor_Store_NoTransformation(b *testing.B) {
	proc, _ := cereal.NewProcessor[codectest.SimpleUser]()
	proc.SetCodec(json.New())
	user := &codectest.SimpleUser{ID: "123", Name: "Alice"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = proc.Write(context.Background(), user)
	}
}

func BenchmarkProcessor_Store_WithEncryption(b *testing.B) {
	proc, _ := cereal.NewProcessor[codectest.SanitizedUser]()
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(b))
	proc.SetCodec(json.New())

	user := &codectest.SanitizedUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "secret",
		SSN:      "123-45-6789",
		Note:     "internal note",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = proc.Write(context.Background(), user)
	}
}

func BenchmarkProcessor_Load_WithDecryption(b *testing.B) {
	proc, _ := cereal.NewProcessor[codectest.SanitizedUser]()
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(b))

	proc.SetCodec(json.New())
	user := &codectest.SanitizedUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "secret",
		SSN:      "123-45-6789",
		Note:     "internal note",
	}

	data, _ := proc.Write(context.Background(), user)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = proc.Read(context.Background(), data)
	}
}

func BenchmarkProcessor_Send_WithMaskingRedaction(b *testing.B) {
	proc, _ := cereal.NewProcessor[codectest.SanitizedUser]()
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(b))

	proc.SetCodec(json.New())
	user := &codectest.SanitizedUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "secret",
		SSN:      "123-45-6789",
		Note:     "internal note",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = proc.Encode(context.Background(), user)
	}
}

func BenchmarkAES_Encrypt(b *testing.B) {
	enc := codectest.TestEncryptor(b)
	plaintext := []byte("this is a test message for encryption benchmarking")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = enc.Encrypt(plaintext)
	}
}

func BenchmarkHasher_Argon2(b *testing.B) {
	h := cereal.Argon2()
	data := []byte("password123")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Hash(data)
	}
}

func BenchmarkHasher_SHA256(b *testing.B) {
	h := cereal.SHA256Hasher()
	data := []byte("this is a test message for hashing benchmarking")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Hash(data)
	}
}
