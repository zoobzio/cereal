package cereal_test

import (
	"encoding/json"
	"testing"

	"github.com/zoobzio/cereal"
)

// testCodec is a simple JSON codec for testing without importing cereal/json.
type registryTestCodec struct{}

func (c *registryTestCodec) ContentType() string { return "application/json" }

func (c *registryTestCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (c *registryTestCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

type CacheTestUser struct {
	Name  string `json:"name"`
	Email string `json:"email" store.encrypt:"aes" load.decrypt:"aes"`
}

func (u CacheTestUser) Clone() CacheTestUser { return u }

func TestNewProcessor_CreatesSeparateInstances(t *testing.T) {
	cereal.ResetPlansCache()

	p1, err := cereal.NewProcessor[CacheTestUser]()
	if err != nil {
		t.Fatalf("NewProcessor() error: %v", err)
	}

	p2, err := cereal.NewProcessor[CacheTestUser]()
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

	p1, _ := cereal.NewProcessor[CacheTestUser]()
	p2, _ := cereal.NewProcessor[CacheTestUser]()

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
	_, err := cereal.NewProcessor[CacheTestUser]()
	if err != nil {
		t.Fatalf("NewProcessor() error: %v", err)
	}

	// Reset should not cause errors on subsequent NewProcessor calls
	cereal.ResetPlansCache()

	_, err = cereal.NewProcessor[CacheTestUser]()
	if err != nil {
		t.Fatalf("NewProcessor() after reset error: %v", err)
	}
}

// --- Cache sharing tests ---

type CacheTestUser2 struct {
	ID     string `json:"id"`
	Secret string `json:"secret" store.encrypt:"aes" load.decrypt:"aes"`
}

func (u CacheTestUser2) Clone() CacheTestUser2 { return u }

func TestPlansCache_SharedBetweenProcessors(t *testing.T) {
	cereal.ResetPlansCache()

	// Create multiple processors for the same type
	p1, err := cereal.NewProcessor[CacheTestUser]()
	if err != nil {
		t.Fatalf("NewProcessor() error: %v", err)
	}

	p2, err := cereal.NewProcessor[CacheTestUser]()
	if err != nil {
		t.Fatalf("NewProcessor() error: %v", err)
	}

	// Both should work correctly (verifies cache is properly shared)
	key := []byte("32-byte-key-for-aes-256-encrypt!")
	enc, _ := cereal.AES(key)
	p1.SetEncryptor(cereal.EncryptAES, enc)
	p2.SetEncryptor(cereal.EncryptAES, enc)

	p1.SetCodec(&registryTestCodec{})
	p2.SetCodec(&registryTestCodec{})

	user := &CacheTestUser{Name: "test", Email: "test@example.com"}

	data1, err := p1.Write(t.Context(), user)
	if err != nil {
		t.Fatalf("p1.Write() error: %v", err)
	}

	data2, err := p2.Write(t.Context(), user)
	if err != nil {
		t.Fatalf("p2.Write() error: %v", err)
	}

	// Both should produce encrypted data (different ciphertext due to random nonce)
	// Verify both produced non-empty data
	if len(data1) == 0 || len(data2) == 0 {
		t.Error("Write() should produce non-empty encrypted data")
	}

	// Both should be loadable by either processor
	loaded1, err := p1.Read(t.Context(), data2)
	if err != nil {
		t.Fatalf("p1.Read() error: %v", err)
	}
	if loaded1.Email != user.Email {
		t.Errorf("p1.Read() Email = %q, want %q", loaded1.Email, user.Email)
	}
}

func TestPlansCache_DifferentTypes(t *testing.T) {
	cereal.ResetPlansCache()

	// Create processors for different types
	p1, err := cereal.NewProcessor[CacheTestUser]()
	if err != nil {
		t.Fatalf("NewProcessor[CacheTestUser]() error: %v", err)
	}

	p2, err := cereal.NewProcessor[CacheTestUser2]()
	if err != nil {
		t.Fatalf("NewProcessor[CacheTestUser2]() error: %v", err)
	}

	// Both should have independent state
	key := []byte("32-byte-key-for-aes-256-encrypt!")
	enc, _ := cereal.AES(key)
	p1.SetEncryptor(cereal.EncryptAES, enc)
	p2.SetEncryptor(cereal.EncryptAES, enc)

	// Validate both work independently
	if err := p1.Validate(); err != nil {
		t.Errorf("p1.Validate() error: %v", err)
	}
	if err := p2.Validate(); err != nil {
		t.Errorf("p2.Validate() error: %v", err)
	}
}

// --- Concurrent cache access tests ---

func TestPlansCache_ConcurrentAccess(t *testing.T) {
	cereal.ResetPlansCache()

	const goroutines = 100
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			_, err := cereal.NewProcessor[CacheTestUser]()
			errs <- err
		}()
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent NewProcessor() error: %v", err)
		}
	}
}

func TestPlansCache_ConcurrentResetAndCreate(t *testing.T) {
	const iterations = 50

	errs := make(chan error, iterations*2)

	for i := 0; i < iterations; i++ {
		go func() {
			cereal.ResetPlansCache()
			errs <- nil
		}()
		go func() {
			_, err := cereal.NewProcessor[CacheTestUser]()
			errs <- err
		}()
	}

	for i := 0; i < iterations*2; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent operation error: %v", err)
		}
	}
}

// --- Multiple type concurrent access ---

type CacheTestType3 struct {
	Value string `json:"value" send.redact:"***"`
}

func (ct CacheTestType3) Clone() CacheTestType3 { return ct }

type CacheTestType4 struct {
	Data string `json:"data" receive.hash:"sha256"`
}

func (ct CacheTestType4) Clone() CacheTestType4 { return ct }

func TestPlansCache_ConcurrentMultipleTypes(t *testing.T) {
	cereal.ResetPlansCache()

	const goroutines = 25
	errs := make(chan error, goroutines*4)

	for i := 0; i < goroutines; i++ {
		go func() {
			_, err := cereal.NewProcessor[CacheTestUser]()
			errs <- err
		}()
		go func() {
			_, err := cereal.NewProcessor[CacheTestUser2]()
			errs <- err
		}()
		go func() {
			_, err := cereal.NewProcessor[CacheTestType3]()
			errs <- err
		}()
		go func() {
			_, err := cereal.NewProcessor[CacheTestType4]()
			errs <- err
		}()
	}

	for i := 0; i < goroutines*4; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent NewProcessor() error: %v", err)
		}
	}
}

// --- Cache stability tests ---

func TestPlansCache_StableAfterReset(t *testing.T) {
	// Create a processor and use it
	p1, err := cereal.NewProcessor[CacheTestUser]()
	if err != nil {
		t.Fatalf("NewProcessor() error: %v", err)
	}

	key := []byte("32-byte-key-for-aes-256-encrypt!")
	enc, _ := cereal.AES(key)
	p1.SetEncryptor(cereal.EncryptAES, enc)

	p1.SetCodec(&registryTestCodec{})

	user := &CacheTestUser{Name: "test", Email: "test@example.com"}
	data1, err := p1.Write(t.Context(), user)
	if err != nil {
		t.Fatalf("p1.Write() before reset error: %v", err)
	}

	// Reset cache while processor is active
	cereal.ResetPlansCache()

	// Original processor should still work (has its own plans)
	data2, err := p1.Write(t.Context(), user)
	if err != nil {
		t.Fatalf("p1.Write() after reset error: %v", err)
	}

	// New processor should work after reset
	p2, err := cereal.NewProcessor[CacheTestUser]()
	if err != nil {
		t.Fatalf("NewProcessor() after reset error: %v", err)
	}
	p2.SetEncryptor(cereal.EncryptAES, enc)
	p2.SetCodec(&registryTestCodec{})

	data3, err := p2.Write(t.Context(), user)
	if err != nil {
		t.Fatalf("p2.Write() after reset error: %v", err)
	}

	// All should produce non-empty encrypted data
	if len(data1) == 0 || len(data2) == 0 || len(data3) == 0 {
		t.Error("Write() should produce non-empty data")
	}

	// Original processor's reads should still work
	loaded1, err := p1.Read(t.Context(), data2)
	if err != nil {
		t.Fatalf("p1.Read() after reset error: %v", err)
	}
	if loaded1.Email != user.Email {
		t.Errorf("p1.Read() Email = %q, want %q", loaded1.Email, user.Email)
	}

	// New processor should be able to read data from old processor
	loaded2, err := p2.Read(t.Context(), data1)
	if err != nil {
		t.Fatalf("p2.Read() error: %v", err)
	}
	if loaded2.Email != user.Email {
		t.Errorf("p2.Read() Email = %q, want %q", loaded2.Email, user.Email)
	}
}
