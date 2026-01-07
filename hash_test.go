package cereal

import (
	"strings"
	"testing"
)

func TestArgon2_Hash(t *testing.T) {
	h := Argon2()
	plaintext := []byte("password123")

	hash, err := h.Hash(plaintext)
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}

	// Argon2 hash should start with $argon2id$
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("Hash() = %q, want prefix $argon2id$", hash)
	}
}

func TestArgon2_DifferentSalts(t *testing.T) {
	h := Argon2()
	plaintext := []byte("password123")

	hash1, _ := h.Hash(plaintext)
	hash2, _ := h.Hash(plaintext)

	if hash1 == hash2 {
		t.Error("same plaintext should produce different hashes (random salt)")
	}
}

func TestArgon2WithParams(t *testing.T) {
	params := Argon2Params{
		Time:    2,
		Memory:  32 * 1024,
		Threads: 2,
		KeyLen:  16,
		SaltLen: 8,
	}
	h := Argon2WithParams(params)

	hash, err := h.Hash([]byte("test"))
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("Hash() = %q, want prefix $argon2id$", hash)
	}
}

func TestDefaultArgon2Params(t *testing.T) {
	params := DefaultArgon2Params()

	if params.Time != 1 {
		t.Errorf("Time = %d, want 1", params.Time)
	}
	if params.Memory != 64*1024 {
		t.Errorf("Memory = %d, want %d", params.Memory, 64*1024)
	}
	if params.Threads != 4 {
		t.Errorf("Threads = %d, want 4", params.Threads)
	}
	if params.KeyLen != 32 {
		t.Errorf("KeyLen = %d, want 32", params.KeyLen)
	}
	if params.SaltLen != 16 {
		t.Errorf("SaltLen = %d, want 16", params.SaltLen)
	}
}

func TestBcrypt_Hash(t *testing.T) {
	h := Bcrypt()
	plaintext := []byte("password123")

	hash, err := h.Hash(plaintext)
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}

	// Bcrypt hash should start with $2a$ or $2b$
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("Hash() = %q, want prefix $2", hash)
	}
}

func TestBcrypt_DifferentSalts(t *testing.T) {
	h := Bcrypt()
	plaintext := []byte("password123")

	hash1, _ := h.Hash(plaintext)
	hash2, _ := h.Hash(plaintext)

	if hash1 == hash2 {
		t.Error("same plaintext should produce different hashes (random salt)")
	}
}

func TestBcryptWithCost(t *testing.T) {
	h := BcryptWithCost(BcryptMinCost)

	hash, err := h.Hash([]byte("test"))
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}

	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("Hash() = %q, want prefix $2", hash)
	}
}

func TestSHA256Hasher_Hash(t *testing.T) {
	h := SHA256Hasher()

	hash, err := h.Hash([]byte("hello"))
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}

	// SHA-256 produces 64 hex characters
	if len(hash) != 64 {
		t.Errorf("Hash() length = %d, want 64", len(hash))
	}

	// Known hash for "hello"
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if hash != want {
		t.Errorf("Hash() = %q, want %q", hash, want)
	}
}

func TestSHA256Hasher_Deterministic(t *testing.T) {
	h := SHA256Hasher()
	plaintext := []byte("test")

	hash1, _ := h.Hash(plaintext)
	hash2, _ := h.Hash(plaintext)

	if hash1 != hash2 {
		t.Error("SHA256 should be deterministic")
	}
}

func TestSHA512Hasher_Hash(t *testing.T) {
	h := SHA512Hasher()

	hash, err := h.Hash([]byte("hello"))
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}

	// SHA-512 produces 128 hex characters
	if len(hash) != 128 {
		t.Errorf("Hash() length = %d, want 128", len(hash))
	}
}

func TestSHA512Hasher_Deterministic(t *testing.T) {
	h := SHA512Hasher()
	plaintext := []byte("test")

	hash1, _ := h.Hash(plaintext)
	hash2, _ := h.Hash(plaintext)

	if hash1 != hash2 {
		t.Error("SHA512 should be deterministic")
	}
}

func TestBuiltinHashers(t *testing.T) {
	hashers := builtinHashers()

	algos := []HashAlgo{HashArgon2, HashBcrypt, HashSHA256, HashSHA512}
	for _, algo := range algos {
		if _, ok := hashers[algo]; !ok {
			t.Errorf("builtinHashers() missing %q", algo)
		}
	}
}
