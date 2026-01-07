package testing

import (
	"testing"
)

func TestTestKey(t *testing.T) {
	key := TestKey(t)
	if len(key) != 32 {
		t.Errorf("TestKey() length = %d, want 32", len(key))
	}
}

func TestTestEncryptor(t *testing.T) {
	enc := TestEncryptor(t)
	if enc == nil {
		t.Error("TestEncryptor() should not return nil")
	}

	// Verify it works
	plaintext := []byte("test")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Errorf("Encrypt() error: %v", err)
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Errorf("Decrypt() error: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("round-trip failed")
	}
}

func TestSimpleUser_Clone(t *testing.T) {
	original := SimpleUser{ID: "1", Name: "Alice"}
	cloned := original.Clone()

	if cloned.ID != original.ID || cloned.Name != original.Name {
		t.Error("Clone() should copy all fields")
	}
}

func TestSanitizedUser_Clone(t *testing.T) {
	original := SanitizedUser{
		ID:       "1",
		Email:    "test@example.com",
		Password: "secret",
		SSN:      "123-45-6789",
		Note:     "note",
	}
	cloned := original.Clone()

	if cloned.ID != original.ID ||
		cloned.Email != original.Email ||
		cloned.Password != original.Password ||
		cloned.SSN != original.SSN ||
		cloned.Note != original.Note {
		t.Error("Clone() should copy all fields")
	}
}
