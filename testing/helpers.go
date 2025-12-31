// Package testing provides test utilities for codec.
package testing

import (
	"github.com/zoobzio/codec"
)

// TestKey returns a valid 32-byte AES key for testing.
func TestKey() []byte {
	return []byte("32-byte-key-for-aes-256-encrypt!")
}

// TestEncryptor returns an AES encryptor configured for testing.
func TestEncryptor() codec.Encryptor {
	enc, err := codec.AES(TestKey())
	if err != nil {
		panic(err)
	}
	return enc
}

// SimpleUser is a test type with no transformation tags.
type SimpleUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Clone implements Cloner[SimpleUser].
func (u SimpleUser) Clone() SimpleUser { return u }

// SanitizedUser is a test type demonstrating context-aware tags.
// Uses the new compound tag syntax: {context}.{action}:"{capability}"
type SanitizedUser struct {
	ID       string `json:"id"`
	Email    string `json:"email" store.encrypt:"aes" load.decrypt:"aes" send.mask:"email"`
	Password string `json:"password" receive.hash:"argon2" send.redact:"***"`
	SSN      string `json:"ssn" send.mask:"ssn"`
	Note     string `json:"note" send.redact:"[REDACTED]"`
}

// Clone implements Cloner[SanitizedUser].
func (u SanitizedUser) Clone() SanitizedUser {
	return SanitizedUser{
		ID:       u.ID,
		Email:    u.Email,
		Password: u.Password,
		SSN:      u.SSN,
		Note:     u.Note,
	}
}
