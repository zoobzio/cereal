package cereal_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/zoobzio/cereal"
)

// testCodec is a simple JSON codec for testing without importing cereal/json.
type testCodec struct{}

func (c *testCodec) ContentType() string { return "application/json" }

func (c *testCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (c *testCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// --- Cloner interface tests ---

type clonerTestStruct struct {
	Value   string
	Pointer *string
	Slice   []string
	Map     map[string]string
}

func (c clonerTestStruct) Clone() clonerTestStruct {
	clone := clonerTestStruct{Value: c.Value}
	if c.Pointer != nil {
		p := *c.Pointer
		clone.Pointer = &p
	}
	if c.Slice != nil {
		clone.Slice = make([]string, len(c.Slice))
		copy(clone.Slice, c.Slice)
	}
	if c.Map != nil {
		clone.Map = make(map[string]string)
		for k, v := range c.Map {
			clone.Map[k] = v
		}
	}
	return clone
}

func TestCloner_DeepCopy(t *testing.T) {
	ptr := "pointer-value"
	original := clonerTestStruct{
		Value:   "test",
		Pointer: &ptr,
		Slice:   []string{"a", "b", "c"},
		Map:     map[string]string{"key": "value"},
	}

	clone := original.Clone()

	// Verify values match
	if clone.Value != original.Value {
		t.Errorf("Clone() Value = %q, want %q", clone.Value, original.Value)
	}
	if *clone.Pointer != *original.Pointer {
		t.Errorf("Clone() Pointer = %q, want %q", *clone.Pointer, *original.Pointer)
	}

	// Verify deep copy: modifying clone should not affect original
	clone.Value = "modified"
	*clone.Pointer = "modified-pointer"
	clone.Slice[0] = "modified"
	clone.Map["key"] = "modified"

	if original.Value == "modified" {
		t.Error("Clone() did not create independent Value")
	}
	if *original.Pointer == "modified-pointer" {
		t.Error("Clone() did not create independent Pointer")
	}
	if original.Slice[0] == "modified" {
		t.Error("Clone() did not create independent Slice")
	}
	if original.Map["key"] == "modified" {
		t.Error("Clone() did not create independent Map")
	}
}

func TestCloner_NilFields(t *testing.T) {
	original := clonerTestStruct{Value: "test"}
	clone := original.Clone()

	if clone.Value != original.Value {
		t.Errorf("Clone() Value = %q, want %q", clone.Value, original.Value)
	}
	if clone.Pointer != nil {
		t.Error("Clone() should preserve nil Pointer")
	}
	if clone.Slice != nil {
		t.Error("Clone() should preserve nil Slice")
	}
	if clone.Map != nil {
		t.Error("Clone() should preserve nil Map")
	}
}

// --- Override interface tests ---

// Test that Encryptable interface is callable with correct signature
type encryptableTest struct {
	Data string
}

func (e encryptableTest) Clone() encryptableTest { return e }

func (e *encryptableTest) Encrypt(encryptors map[cereal.EncryptAlgo]cereal.Encryptor) error {
	if enc, ok := encryptors[cereal.EncryptAES]; ok {
		ciphertext, err := enc.Encrypt([]byte(e.Data))
		if err != nil {
			return err
		}
		e.Data = string(ciphertext)
	}
	return nil
}

func TestEncryptable_Interface(_ *testing.T) {
	var _ cereal.Encryptable = (*encryptableTest)(nil)
}

// Test that Decryptable interface is callable with correct signature
type decryptableTest struct {
	Data string
}

func (d decryptableTest) Clone() decryptableTest { return d }

func (d *decryptableTest) Decrypt(encryptors map[cereal.EncryptAlgo]cereal.Encryptor) error {
	if enc, ok := encryptors[cereal.EncryptAES]; ok {
		plaintext, err := enc.Decrypt([]byte(d.Data))
		if err != nil {
			return err
		}
		d.Data = string(plaintext)
	}
	return nil
}

func TestDecryptable_Interface(_ *testing.T) {
	var _ cereal.Decryptable = (*decryptableTest)(nil)
}

// Test that Hashable interface is callable with correct signature
type hashableTest struct {
	Password string
}

func (h hashableTest) Clone() hashableTest { return h }

func (h *hashableTest) Hash(hashers map[cereal.HashAlgo]cereal.Hasher) error {
	if hasher, ok := hashers[cereal.HashSHA256]; ok {
		hashed, err := hasher.Hash([]byte(h.Password))
		if err != nil {
			return err
		}
		h.Password = hashed
	}
	return nil
}

func TestHashable_Interface(_ *testing.T) {
	var _ cereal.Hashable = (*hashableTest)(nil)
}

// Test that Maskable interface is callable with correct signature
type maskableTest struct {
	Email string
}

func (m maskableTest) Clone() maskableTest { return m }

func (m *maskableTest) Mask(maskers map[cereal.MaskType]cereal.Masker) error {
	if masker, ok := maskers[cereal.MaskEmail]; ok {
		masked, err := masker.Mask(m.Email)
		if err != nil {
			return err
		}
		m.Email = masked
	}
	return nil
}

func TestMaskable_Interface(_ *testing.T) {
	var _ cereal.Maskable = (*maskableTest)(nil)
}

// Test that Redactable interface is callable with correct signature
type redactableTest struct {
	Secret string
}

func (r redactableTest) Clone() redactableTest { return r }

func (r *redactableTest) Redact() error {
	r.Secret = "***"
	return nil
}

func TestRedactable_Interface(_ *testing.T) {
	var _ cereal.Redactable = (*redactableTest)(nil)
}

// --- Override interface error propagation tests ---

type encryptErrorUser struct {
	Email string `json:"email" store.encrypt:"aes"`
}

func (u encryptErrorUser) Clone() encryptErrorUser { return u }

func (u *encryptErrorUser) Encrypt(_ map[cereal.EncryptAlgo]cereal.Encryptor) error {
	return errors.New("custom encrypt error")
}

type decryptErrorUser struct {
	Email string `json:"email" load.decrypt:"aes"`
}

func (u decryptErrorUser) Clone() decryptErrorUser { return u }

func (u *decryptErrorUser) Decrypt(_ map[cereal.EncryptAlgo]cereal.Encryptor) error {
	return errors.New("custom decrypt error")
}

type hashErrorUser struct {
	Password string `json:"password" receive.hash:"sha256"`
}

func (u hashErrorUser) Clone() hashErrorUser { return u }

func (u *hashErrorUser) Hash(_ map[cereal.HashAlgo]cereal.Hasher) error {
	return errors.New("custom hash error")
}

type maskErrorUser struct {
	Email string `json:"email" send.mask:"email"`
}

func (u maskErrorUser) Clone() maskErrorUser { return u }

func (u *maskErrorUser) Mask(_ map[cereal.MaskType]cereal.Masker) error {
	return errors.New("custom mask error")
}

type redactErrorUser struct {
	Secret string `json:"secret" send.redact:"***"`
}

func (u redactErrorUser) Clone() redactErrorUser { return u }

func (u *redactErrorUser) Redact() error {
	return errors.New("custom redact error")
}

// --- Interface error propagation integration tests ---

func TestEncryptable_ErrorPropagation(t *testing.T) {
	proc, err := cereal.NewProcessor[encryptErrorUser]()
	if err != nil {
		t.Fatalf("NewProcessor() error: %v", err)
	}
	proc.SetCodec(&testCodec{})

	user := &encryptErrorUser{Email: "test@example.com"}
	_, err = proc.Write(t.Context(), user)
	if err == nil {
		t.Error("Write() should propagate Encryptable error")
	}
	if err.Error() != "encrypt: custom encrypt error" {
		t.Errorf("Write() error = %q, want 'encrypt: custom encrypt error'", err.Error())
	}
}

func TestDecryptable_ErrorPropagation(t *testing.T) {
	proc, err := cereal.NewProcessor[decryptErrorUser]()
	if err != nil {
		t.Fatalf("NewProcessor() error: %v", err)
	}
	proc.SetCodec(&testCodec{})

	input := `{"email":"encrypted-data"}`
	_, err = proc.Read(t.Context(), []byte(input))
	if err == nil {
		t.Error("Read() should propagate Decryptable error")
	}
	if err.Error() != "decrypt: custom decrypt error" {
		t.Errorf("Read() error = %q, want 'decrypt: custom decrypt error'", err.Error())
	}
}

func TestHashable_ErrorPropagation(t *testing.T) {
	proc, err := cereal.NewProcessor[hashErrorUser]()
	if err != nil {
		t.Fatalf("NewProcessor() error: %v", err)
	}
	proc.SetCodec(&testCodec{})

	input := `{"password":"secret"}`
	_, err = proc.Decode(t.Context(), []byte(input))
	if err == nil {
		t.Error("Decode() should propagate Hashable error")
	}
	if err.Error() != "hash: custom hash error" {
		t.Errorf("Decode() error = %q, want 'hash: custom hash error'", err.Error())
	}
}

func TestMaskable_ErrorPropagation(t *testing.T) {
	proc, err := cereal.NewProcessor[maskErrorUser]()
	if err != nil {
		t.Fatalf("NewProcessor() error: %v", err)
	}
	proc.SetCodec(&testCodec{})

	user := &maskErrorUser{Email: "test@example.com"}
	_, err = proc.Encode(t.Context(), user)
	if err == nil {
		t.Error("Encode() should propagate Maskable error")
	}
	if err.Error() != "mask: custom mask error" {
		t.Errorf("Encode() error = %q, want 'mask: custom mask error'", err.Error())
	}
}

func TestRedactable_ErrorPropagation(t *testing.T) {
	proc, err := cereal.NewProcessor[redactErrorUser]()
	if err != nil {
		t.Fatalf("NewProcessor() error: %v", err)
	}
	proc.SetCodec(&testCodec{})

	user := &redactErrorUser{Secret: "secret-data"}
	_, err = proc.Encode(t.Context(), user)
	if err == nil {
		t.Error("Encode() should propagate Redactable error")
	}
	if err.Error() != "redact: custom redact error" {
		t.Errorf("Encode() error = %q, want 'redact: custom redact error'", err.Error())
	}
}
