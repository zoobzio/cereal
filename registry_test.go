package cereal_test

import (
	"testing"

	"github.com/zoobzio/cereal"
	"github.com/zoobzio/cereal/json"
)

type CacheTestUser struct {
	Name  string `json:"name"`
	Email string `json:"email" store.encrypt:"aes" load.decrypt:"aes"`
}

func (u CacheTestUser) Clone() CacheTestUser { return u }

func TestNewProcessor_CreatesSeparateInstances(t *testing.T) {
	cereal.ResetPlansCache()

	p1, err := cereal.NewProcessor[CacheTestUser](json.New())
	if err != nil {
		t.Fatalf("NewProcessor() error: %v", err)
	}

	p2, err := cereal.NewProcessor[CacheTestUser](json.New())
	if err != nil {
		t.Fatalf("NewProcessor() error: %v", err)
	}

	// Different processor instances (each has its own mutable state)
	if p1 == p2 {
		t.Error("NewProcessor() should return new instances")
	}
}

func TestNewProcessor_SeparateEncryptorState(t *testing.T) {
	cereal.ResetPlansCache()

	key1 := []byte("32-byte-key-for-aes-256-encrypt!")
	key2 := []byte("different-key-for-aes-256-enc!!")

	enc1, _ := cereal.AES(key1)
	enc2, _ := cereal.AES(key2)

	p1, _ := cereal.NewProcessor[CacheTestUser](json.New())
	p2, _ := cereal.NewProcessor[CacheTestUser](json.New())

	// Configure different encryptors
	p1.SetEncryptor(cereal.EncryptAES, enc1)
	p2.SetEncryptor(cereal.EncryptAES, enc2)

	// Each processor should maintain independent state
	if err := p1.Validate(); err != nil {
		t.Errorf("p1 validation failed: %v", err)
	}
	if err := p2.Validate(); err != nil {
		t.Errorf("p2 validation failed: %v", err)
	}
}

func TestResetPlansCache(t *testing.T) {
	// Create a processor to populate the cache
	_, err := cereal.NewProcessor[CacheTestUser](json.New())
	if err != nil {
		t.Fatalf("NewProcessor() error: %v", err)
	}

	// Reset should not cause errors on subsequent NewProcessor calls
	cereal.ResetPlansCache()

	_, err = cereal.NewProcessor[CacheTestUser](json.New())
	if err != nil {
		t.Fatalf("NewProcessor() after reset error: %v", err)
	}
}
