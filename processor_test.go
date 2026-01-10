package cereal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Test constants for repeated values.
const (
	testEmail         = "alice@example.com"
	testRedactedValue = "***"
)

// testCodec is a simple JSON codec for testing.
type testCodec struct{}

func (c *testCodec) ContentType() string { return "application/json" }

func (c *testCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (c *testCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// SimpleUser has no transformation tags.
type SimpleUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (u SimpleUser) Clone() SimpleUser { return u }

// HashUser has hash tags.
type HashUser struct {
	ID       string `json:"id"`
	Password string `json:"password" receive.hash:"sha256"`
}

func (u HashUser) Clone() HashUser { return u }

// EncryptUser has encryption tags.
type EncryptUser struct {
	ID    string `json:"id"`
	Email string `json:"email" store.encrypt:"aes" load.decrypt:"aes"`
}

func (u EncryptUser) Clone() EncryptUser { return u }

// MaskUser has masking tags.
type MaskUser struct {
	ID    string `json:"id"`
	Email string `json:"email" send.mask:"email"`
	SSN   string `json:"ssn" send.mask:"ssn"`
}

func (u MaskUser) Clone() MaskUser { return u }

// RedactUser has redaction tags.
type RedactUser struct {
	ID       string `json:"id"`
	Password string `json:"password" send.redact:"***"`
	Token    string `json:"token" send.redact:"[REDACTED]"`
}

func (u RedactUser) Clone() RedactUser { return u }

func TestNewProcessor(t *testing.T) {
	proc, err := NewProcessor[SimpleUser](&testCodec{})
	if err != nil {
		t.Fatalf("NewProcessor() error: %v", err)
	}
	if proc == nil {
		t.Error("NewProcessor() returned nil")
	}
}

type BadTagUser struct {
	ID       string `json:"id"`
	Password string `json:"password" receive.hash:"invalid"`
}

func (u BadTagUser) Clone() BadTagUser { return u }

func TestNewProcessor_InvalidTag(t *testing.T) {
	_, err := NewProcessor[BadTagUser](&testCodec{})
	if err == nil {
		t.Error("NewProcessor() should fail for invalid hash algorithm")
	}
}

func TestProcessor_SetEncryptor(t *testing.T) {
	proc, _ := NewProcessor[EncryptUser](&testCodec{})

	enc, err := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	if err != nil {
		t.Fatalf("AES() error: %v", err)
	}

	result := proc.SetEncryptor(EncryptAES, enc)
	if result != proc {
		t.Error("SetEncryptor() should return processor for chaining")
	}
}

func TestProcessor_SetHasher(t *testing.T) {
	proc, _ := NewProcessor[HashUser](&testCodec{})

	result := proc.SetHasher(HashSHA256, SHA256Hasher())
	if result != proc {
		t.Error("SetHasher() should return processor for chaining")
	}
}

func TestProcessor_SetMasker(t *testing.T) {
	proc, _ := NewProcessor[MaskUser](&testCodec{})

	result := proc.SetMasker(MaskEmail, EmailMasker())
	if result != proc {
		t.Error("SetMasker() should return processor for chaining")
	}
}

func TestProcessor_Validate_MissingEncryptor(t *testing.T) {
	proc, _ := NewProcessor[EncryptUser](&testCodec{})

	err := proc.Validate()
	if err == nil {
		t.Error("Validate() should fail when encryptor is missing")
	}
	if !strings.Contains(err.Error(), "missing encryptor") {
		t.Errorf("Validate() error = %q, want 'missing encryptor'", err.Error())
	}
}

func TestProcessor_Validate_Success(t *testing.T) {
	proc, _ := NewProcessor[EncryptUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	err := proc.Validate()
	if err != nil {
		t.Errorf("Validate() error: %v", err)
	}
}

func TestProcessor_Receive_Hash(t *testing.T) {
	proc, _ := NewProcessor[HashUser](&testCodec{})

	input := `{"id":"123","password":"secret"}`
	user, err := proc.Receive(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("Receive() error: %v", err)
	}

	if user.Password == "secret" {
		t.Error("Receive() should hash password")
	}
	// SHA256 produces 64 hex chars
	if len(user.Password) != 64 {
		t.Errorf("Receive() password length = %d, want 64", len(user.Password))
	}
}

func TestProcessor_Store_Encrypt(t *testing.T) {
	proc, _ := NewProcessor[EncryptUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	user := &EncryptUser{ID: "123", Email: testEmail}
	data, err := proc.Store(context.Background(), user)
	if err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	// Original should not be modified
	if user.Email != testEmail {
		t.Error("Store() should not modify original")
	}

	// Stored data should have encrypted email
	var stored EncryptUser
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if stored.Email == testEmail {
		t.Error("Store() should encrypt email")
	}
}

func TestProcessor_Load_Decrypt(t *testing.T) {
	proc, _ := NewProcessor[EncryptUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	// First store to get encrypted data
	original := &EncryptUser{ID: "123", Email: testEmail}
	data, _ := proc.Store(context.Background(), original)

	// Then load to decrypt
	loaded, err := proc.Load(context.Background(), data)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if loaded.Email != original.Email {
		t.Errorf("Load() email = %q, want %q", loaded.Email, original.Email)
	}
}

func TestProcessor_Send_Mask(t *testing.T) {
	proc, _ := NewProcessor[MaskUser](&testCodec{})

	user := &MaskUser{
		ID:    "123",
		Email: testEmail,
		SSN:   "123-45-6789",
	}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	// Original should not be modified
	if user.Email != testEmail {
		t.Error("Send() should not modify original")
	}

	var sent MaskUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if sent.Email == testEmail {
		t.Error("Send() should mask email")
	}
	if sent.SSN == "123-45-6789" {
		t.Error("Send() should mask SSN")
	}
}

func TestProcessor_Send_MaskInvalidFormat(t *testing.T) {
	proc, _ := NewProcessor[MaskUser](&testCodec{})

	user := &MaskUser{
		ID:    "123",
		Email: "not-an-email",   // Invalid email format
		SSN:   "123-45-6789",    // Valid SSN
	}
	_, err := proc.Send(context.Background(), user)
	if err == nil {
		t.Fatal("Send() should fail for invalid email format")
	}
	if !errors.Is(err, ErrMask) {
		t.Errorf("Send() error = %v, want ErrMask", err)
	}
}

func TestProcessor_Send_Redact(t *testing.T) {
	proc, _ := NewProcessor[RedactUser](&testCodec{})

	user := &RedactUser{
		ID:       "123",
		Password: "secret",
		Token:    "abc123",
	}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent RedactUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if sent.Password != testRedactedValue {
		t.Errorf("Send() password = %q, want %q", sent.Password, testRedactedValue)
	}
	if sent.Token != "[REDACTED]" {
		t.Errorf("Send() token = %q, want %q", sent.Token, "[REDACTED]")
	}
}

func TestProcessor_Store_Nil(t *testing.T) {
	proc, _ := NewProcessor[SimpleUser](&testCodec{})

	data, err := proc.Store(context.Background(), nil)
	if err != nil {
		t.Fatalf("Store(nil) error: %v", err)
	}
	if string(data) != "null" {
		t.Errorf("Store(nil) = %q, want %q", data, "null")
	}
}

func TestProcessor_Send_Nil(t *testing.T) {
	proc, _ := NewProcessor[SimpleUser](&testCodec{})

	data, err := proc.Send(context.Background(), nil)
	if err != nil {
		t.Fatalf("Send(nil) error: %v", err)
	}
	if string(data) != "null" {
		t.Errorf("Send(nil) = %q, want %q", data, "null")
	}
}

// HashableUser implements the Hashable interface.
type HashableUser struct {
	ID       string `json:"id"`
	Password string `json:"password" receive.hash:"sha256"`
}

func (u HashableUser) Clone() HashableUser { return u }

func (u *HashableUser) Hash(_ map[HashAlgo]Hasher) error {
	u.Password = "custom-hashed"
	return nil
}

func TestProcessor_Receive_InterfaceOverride(t *testing.T) {
	proc, _ := NewProcessor[HashableUser](&testCodec{})

	input := `{"id":"123","password":"secret"}`
	user, err := proc.Receive(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("Receive() error: %v", err)
	}

	if user.Password != "custom-hashed" {
		t.Errorf("Receive() should use Hashable interface, got %q", user.Password)
	}
}

// EncryptableUser implements the Encryptable interface.
type EncryptableUser struct {
	ID    string `json:"id"`
	Email string `json:"email" store.encrypt:"aes"`
}

func (u EncryptableUser) Clone() EncryptableUser { return u }

func (u *EncryptableUser) Encrypt(_ map[EncryptAlgo]Encryptor) error {
	u.Email = "custom-encrypted"
	return nil
}

func TestProcessor_Store_InterfaceOverride(t *testing.T) {
	proc, _ := NewProcessor[EncryptableUser](&testCodec{})

	user := &EncryptableUser{ID: "123", Email: testEmail}
	data, err := proc.Store(context.Background(), user)
	if err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	var stored EncryptableUser
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if stored.Email != "custom-encrypted" {
		t.Errorf("Store() should use Encryptable interface, got %q", stored.Email)
	}
}

// DecryptableUser implements the Decryptable interface.
type DecryptableUser struct {
	ID    string `json:"id"`
	Email string `json:"email" load.decrypt:"aes"`
}

func (u DecryptableUser) Clone() DecryptableUser { return u }

func (u *DecryptableUser) Decrypt(_ map[EncryptAlgo]Encryptor) error {
	u.Email = "custom-decrypted"
	return nil
}

func TestProcessor_Load_InterfaceOverride(t *testing.T) {
	proc, _ := NewProcessor[DecryptableUser](&testCodec{})

	input := `{"id":"123","email":"encrypted-data"}`
	user, err := proc.Load(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if user.Email != "custom-decrypted" {
		t.Errorf("Load() should use Decryptable interface, got %q", user.Email)
	}
}

// MaskableUser implements the Maskable interface.
type MaskableUser struct {
	ID    string `json:"id"`
	Email string `json:"email" send.mask:"email"`
}

func (u MaskableUser) Clone() MaskableUser { return u }

func (u *MaskableUser) Mask(_ map[MaskType]Masker) error {
	u.Email = "custom-masked"
	return nil
}

func TestProcessor_Send_MaskInterfaceOverride(t *testing.T) {
	proc, _ := NewProcessor[MaskableUser](&testCodec{})

	user := &MaskableUser{ID: "123", Email: testEmail}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent MaskableUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if sent.Email != "custom-masked" {
		t.Errorf("Send() should use Maskable interface, got %q", sent.Email)
	}
}

// RedactableUser implements the Redactable interface.
type RedactableUser struct {
	ID       string `json:"id"`
	Password string `json:"password" send.redact:"***"`
}

func (u RedactableUser) Clone() RedactableUser { return u }

func (u *RedactableUser) Redact() error {
	u.Password = "custom-redacted"
	return nil
}

func TestProcessor_Send_RedactInterfaceOverride(t *testing.T) {
	proc, _ := NewProcessor[RedactableUser](&testCodec{})

	user := &RedactableUser{ID: "123", Password: "secret"}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent RedactableUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if sent.Password != "custom-redacted" {
		t.Errorf("Send() should use Redactable interface, got %q", sent.Password)
	}
}

// --- Nested struct tests ---

// Address is a nested struct with tagged fields.
type Address struct {
	Street string `json:"street" send.redact:"[HIDDEN]"`
	City   string `json:"city"`
}

// NestedUser has a nested struct.
type NestedUser struct {
	ID      string  `json:"id"`
	Address Address `json:"address"`
}

func (u NestedUser) Clone() NestedUser {
	return NestedUser{ID: u.ID, Address: u.Address}
}

func TestProcessor_Send_NestedStruct(t *testing.T) {
	proc, _ := NewProcessor[NestedUser](&testCodec{})

	user := &NestedUser{
		ID:      "123",
		Address: Address{Street: "123 Main St", City: "Boston"},
	}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent NestedUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if sent.Address.Street != "[HIDDEN]" {
		t.Errorf("Send() nested street = %q, want %q", sent.Address.Street, "[HIDDEN]")
	}
	if sent.Address.City != "Boston" {
		t.Errorf("Send() nested city = %q, want %q", sent.Address.City, "Boston")
	}
}

// --- Pointer to nested struct tests ---

// PointerNestedUser has a pointer to a nested struct.
type PointerNestedUser struct {
	ID      string   `json:"id"`
	Address *Address `json:"address"`
}

func (u PointerNestedUser) Clone() PointerNestedUser {
	clone := PointerNestedUser{ID: u.ID}
	if u.Address != nil {
		addr := *u.Address
		clone.Address = &addr
	}
	return clone
}

func TestProcessor_Send_PointerNestedStruct(t *testing.T) {
	proc, _ := NewProcessor[PointerNestedUser](&testCodec{})

	user := &PointerNestedUser{
		ID:      "123",
		Address: &Address{Street: "123 Main St", City: "Boston"},
	}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent PointerNestedUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if sent.Address.Street != "[HIDDEN]" {
		t.Errorf("Send() pointer nested street = %q, want %q", sent.Address.Street, "[HIDDEN]")
	}
}

func TestProcessor_Send_PointerNestedStruct_Nil(t *testing.T) {
	proc, _ := NewProcessor[PointerNestedUser](&testCodec{})

	user := &PointerNestedUser{
		ID:      "123",
		Address: nil,
	}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent PointerNestedUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if sent.Address != nil {
		t.Error("Send() should preserve nil pointer")
	}
}

// --- Slice field tests ---

// SliceUser has slice fields with tags.
type SliceUser struct {
	ID       string   `json:"id"`
	Emails   []string `json:"emails" send.mask:"email"`
	Secrets  []string `json:"secrets" send.redact:"***"`
	Tokens   []string `json:"tokens" receive.hash:"sha256"`
	SSNs     []string `json:"ssns" store.encrypt:"aes" load.decrypt:"aes"`
}

func (u SliceUser) Clone() SliceUser {
	clone := SliceUser{ID: u.ID}
	if u.Emails != nil {
		clone.Emails = make([]string, len(u.Emails))
		copy(clone.Emails, u.Emails)
	}
	if u.Secrets != nil {
		clone.Secrets = make([]string, len(u.Secrets))
		copy(clone.Secrets, u.Secrets)
	}
	if u.Tokens != nil {
		clone.Tokens = make([]string, len(u.Tokens))
		copy(clone.Tokens, u.Tokens)
	}
	if u.SSNs != nil {
		clone.SSNs = make([]string, len(u.SSNs))
		copy(clone.SSNs, u.SSNs)
	}
	return clone
}

func TestProcessor_Send_SliceMask(t *testing.T) {
	proc, _ := NewProcessor[SliceUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	user := &SliceUser{
		ID:     "123",
		Emails: []string{"alice@example.com", "bob@example.com"},
	}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent SliceUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	for i, email := range sent.Emails {
		if email == user.Emails[i] {
			t.Errorf("Send() should mask email[%d]", i)
		}
	}
}

func TestProcessor_Send_SliceRedact(t *testing.T) {
	proc, _ := NewProcessor[SliceUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	user := &SliceUser{
		ID:      "123",
		Secrets: []string{"secret1", "secret2"},
	}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent SliceUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	for _, secret := range sent.Secrets {
		if secret != testRedactedValue {
			t.Errorf("Send() secret = %q, want %q", secret, testRedactedValue)
		}
	}
}

func TestProcessor_Receive_SliceHash(t *testing.T) {
	proc, _ := NewProcessor[SliceUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	input := `{"id":"123","tokens":["token1","token2"]}`
	user, err := proc.Receive(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("Receive() error: %v", err)
	}

	for i, token := range user.Tokens {
		if token == "token1" || token == "token2" {
			t.Errorf("Receive() should hash token[%d]", i)
		}
		if len(token) != 64 {
			t.Errorf("Receive() token[%d] length = %d, want 64", i, len(token))
		}
	}
}

func TestProcessor_StoreLoad_SliceEncrypt(t *testing.T) {
	proc, _ := NewProcessor[SliceUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	original := &SliceUser{
		ID:   "123",
		SSNs: []string{"123-45-6789", "987-65-4321"},
	}
	data, err := proc.Store(context.Background(), original)
	if err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	loaded, err := proc.Load(context.Background(), data)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	for i, ssn := range loaded.SSNs {
		if ssn != original.SSNs[i] {
			t.Errorf("Load() SSN[%d] = %q, want %q", i, ssn, original.SSNs[i])
		}
	}
}

// --- Map field tests ---

// MapUser has map fields with tags.
type MapUser struct {
	ID       string            `json:"id"`
	Emails   map[string]string `json:"emails" send.mask:"email"`
	Secrets  map[string]string `json:"secrets" send.redact:"***"`
	Tokens   map[string]string `json:"tokens" receive.hash:"sha256"`
	SSNs     map[string]string `json:"ssns" store.encrypt:"aes" load.decrypt:"aes"`
}

func (u MapUser) Clone() MapUser {
	clone := MapUser{ID: u.ID}
	if u.Emails != nil {
		clone.Emails = make(map[string]string)
		for k, v := range u.Emails {
			clone.Emails[k] = v
		}
	}
	if u.Secrets != nil {
		clone.Secrets = make(map[string]string)
		for k, v := range u.Secrets {
			clone.Secrets[k] = v
		}
	}
	if u.Tokens != nil {
		clone.Tokens = make(map[string]string)
		for k, v := range u.Tokens {
			clone.Tokens[k] = v
		}
	}
	if u.SSNs != nil {
		clone.SSNs = make(map[string]string)
		for k, v := range u.SSNs {
			clone.SSNs[k] = v
		}
	}
	return clone
}

func TestProcessor_Send_MapMask(t *testing.T) {
	proc, _ := NewProcessor[MapUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	user := &MapUser{
		ID:     "123",
		Emails: map[string]string{"work": "alice@example.com", "home": "bob@example.com"},
	}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent MapUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	for k, email := range sent.Emails {
		if email == user.Emails[k] {
			t.Errorf("Send() should mask email[%s]", k)
		}
	}
}

func TestProcessor_Send_MapRedact(t *testing.T) {
	proc, _ := NewProcessor[MapUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	user := &MapUser{
		ID:      "123",
		Secrets: map[string]string{"api": "secret1", "db": "secret2"},
	}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent MapUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	for k, secret := range sent.Secrets {
		if secret != testRedactedValue {
			t.Errorf("Send() secrets[%s] = %q, want %q", k, secret, testRedactedValue)
		}
	}
}

func TestProcessor_Receive_MapHash(t *testing.T) {
	proc, _ := NewProcessor[MapUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	input := `{"id":"123","tokens":{"a":"token1","b":"token2"}}`
	user, err := proc.Receive(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("Receive() error: %v", err)
	}

	for k, token := range user.Tokens {
		if token == "token1" || token == "token2" {
			t.Errorf("Receive() should hash tokens[%s]", k)
		}
		if len(token) != 64 {
			t.Errorf("Receive() tokens[%s] length = %d, want 64", k, len(token))
		}
	}
}

func TestProcessor_StoreLoad_MapEncrypt(t *testing.T) {
	proc, _ := NewProcessor[MapUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	original := &MapUser{
		ID:   "123",
		SSNs: map[string]string{"primary": "123-45-6789", "spouse": "987-65-4321"},
	}
	data, err := proc.Store(context.Background(), original)
	if err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	loaded, err := proc.Load(context.Background(), data)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	for k, ssn := range loaded.SSNs {
		if ssn != original.SSNs[k] {
			t.Errorf("Load() SSNs[%s] = %q, want %q", k, ssn, original.SSNs[k])
		}
	}
}

// --- Clone validation tests ---

func TestProcessor_Send_SliceCloneValidation(t *testing.T) {
	proc, _ := NewProcessor[SliceUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	originalEmails := []string{"alice@example.com", "bob@example.com"}
	user := &SliceUser{
		ID:     "123",
		Emails: originalEmails,
	}

	// Capture original values
	emailsCopy := make([]string, len(originalEmails))
	copy(emailsCopy, originalEmails)

	_, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	// Verify original slice is unchanged
	for i, email := range user.Emails {
		if email != emailsCopy[i] {
			t.Errorf("Send() mutated original Emails[%d]: got %q, want %q", i, email, emailsCopy[i])
		}
	}
}

func TestProcessor_Send_MapCloneValidation(t *testing.T) {
	proc, _ := NewProcessor[MapUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	originalEmails := map[string]string{"work": "alice@example.com", "home": "bob@example.com"}
	user := &MapUser{
		ID:     "123",
		Emails: originalEmails,
	}

	// Capture original values
	emailsCopy := make(map[string]string)
	for k, v := range originalEmails {
		emailsCopy[k] = v
	}

	_, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	// Verify original map is unchanged
	for k, email := range user.Emails {
		if email != emailsCopy[k] {
			t.Errorf("Send() mutated original Emails[%s]: got %q, want %q", k, email, emailsCopy[k])
		}
	}
}

func TestProcessor_Store_SliceCloneValidation(t *testing.T) {
	proc, _ := NewProcessor[SliceUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	originalSSNs := []string{"123-45-6789", "987-65-4321"}
	user := &SliceUser{
		ID:   "123",
		SSNs: originalSSNs,
	}

	// Capture original values
	ssnsCopy := make([]string, len(originalSSNs))
	copy(ssnsCopy, originalSSNs)

	_, err := proc.Store(context.Background(), user)
	if err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	// Verify original slice is unchanged
	for i, ssn := range user.SSNs {
		if ssn != ssnsCopy[i] {
			t.Errorf("Store() mutated original SSNs[%d]: got %q, want %q", i, ssn, ssnsCopy[i])
		}
	}
}

func TestProcessor_Store_MapCloneValidation(t *testing.T) {
	proc, _ := NewProcessor[MapUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	originalSSNs := map[string]string{"primary": "123-45-6789", "spouse": "987-65-4321"}
	user := &MapUser{
		ID:   "123",
		SSNs: originalSSNs,
	}

	// Capture original values
	ssnsCopy := make(map[string]string)
	for k, v := range originalSSNs {
		ssnsCopy[k] = v
	}

	_, err := proc.Store(context.Background(), user)
	if err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	// Verify original map is unchanged
	for k, ssn := range user.SSNs {
		if ssn != ssnsCopy[k] {
			t.Errorf("Store() mutated original SSNs[%s]: got %q, want %q", k, ssn, ssnsCopy[k])
		}
	}
}

// --- Bytes field tests ---

// BytesUser has []byte fields with tags.
type BytesUser struct {
	ID      string `json:"id"`
	Secret  []byte `json:"secret" store.encrypt:"aes" load.decrypt:"aes"`
	Token   []byte `json:"token" receive.hash:"sha256"`
	Redact  []byte `json:"redact" send.redact:"[BYTES]"`
}

func (u BytesUser) Clone() BytesUser {
	clone := BytesUser{ID: u.ID}
	if u.Secret != nil {
		clone.Secret = make([]byte, len(u.Secret))
		copy(clone.Secret, u.Secret)
	}
	if u.Token != nil {
		clone.Token = make([]byte, len(u.Token))
		copy(clone.Token, u.Token)
	}
	if u.Redact != nil {
		clone.Redact = make([]byte, len(u.Redact))
		copy(clone.Redact, u.Redact)
	}
	return clone
}

func TestProcessor_StoreLoad_BytesEncrypt(t *testing.T) {
	proc, _ := NewProcessor[BytesUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	original := &BytesUser{
		ID:     "123",
		Secret: []byte("my-secret-bytes"),
	}
	data, err := proc.Store(context.Background(), original)
	if err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	loaded, err := proc.Load(context.Background(), data)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if string(loaded.Secret) != string(original.Secret) {
		t.Errorf("Load() Secret = %q, want %q", loaded.Secret, original.Secret)
	}
}

func TestProcessor_Receive_BytesHash(t *testing.T) {
	proc, _ := NewProcessor[BytesUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	input := `{"id":"123","token":"dG9rZW4xMjM="}`  // base64 of "token123"
	user, err := proc.Receive(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("Receive() error: %v", err)
	}

	// Token should be hashed (SHA256 = 64 hex chars as bytes)
	if len(user.Token) == 0 {
		t.Error("Receive() should hash token bytes")
	}
}

func TestProcessor_Send_BytesRedact(t *testing.T) {
	proc, _ := NewProcessor[BytesUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	user := &BytesUser{
		ID:     "123",
		Redact: []byte("sensitive-data"),
	}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent BytesUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if string(sent.Redact) != "[BYTES]" {
		t.Errorf("Send() Redact = %q, want %q", sent.Redact, "[BYTES]")
	}
}

// --- Invalid tag tests ---

type BadEncryptTagUser struct {
	ID    string `json:"id"`
	Email string `json:"email" store.encrypt:"invalid"`
}

func (u BadEncryptTagUser) Clone() BadEncryptTagUser { return u }

func TestNewProcessor_InvalidEncryptTag(t *testing.T) {
	_, err := NewProcessor[BadEncryptTagUser](&testCodec{})
	if err == nil {
		t.Error("NewProcessor() should fail for invalid encrypt algorithm")
	}
}

type BadDecryptTagUser struct {
	ID    string `json:"id"`
	Email string `json:"email" load.decrypt:"invalid"`
}

func (u BadDecryptTagUser) Clone() BadDecryptTagUser { return u }

func TestNewProcessor_InvalidDecryptTag(t *testing.T) {
	_, err := NewProcessor[BadDecryptTagUser](&testCodec{})
	if err == nil {
		t.Error("NewProcessor() should fail for invalid decrypt algorithm")
	}
}

type BadMaskTagUser struct {
	ID    string `json:"id"`
	Email string `json:"email" send.mask:"invalid"`
}

func (u BadMaskTagUser) Clone() BadMaskTagUser { return u }

func TestNewProcessor_InvalidMaskTag(t *testing.T) {
	_, err := NewProcessor[BadMaskTagUser](&testCodec{})
	if err == nil {
		t.Error("NewProcessor() should fail for invalid mask type")
	}
}

// --- Validation tests for other missing capabilities ---

type HashOnlyUser struct {
	ID       string `json:"id"`
	Password string `json:"password" receive.hash:"argon2"`
}

func (u HashOnlyUser) Clone() HashOnlyUser { return u }

func TestProcessor_Validate_HashersBuiltin(t *testing.T) {
	proc, _ := NewProcessor[HashOnlyUser](&testCodec{})

	// Hashers are builtin, should validate without error
	err := proc.Validate()
	if err != nil {
		t.Errorf("Validate() error: %v (hashers should be builtin)", err)
	}
}

type MaskOnlyUser struct {
	ID  string `json:"id"`
	SSN string `json:"ssn" send.mask:"ssn"`
}

func (u MaskOnlyUser) Clone() MaskOnlyUser { return u }

func TestProcessor_Validate_MaskersBuiltin(t *testing.T) {
	proc, _ := NewProcessor[MaskOnlyUser](&testCodec{})

	// Maskers are builtin, should validate without error
	err := proc.Validate()
	if err != nil {
		t.Errorf("Validate() error: %v (maskers should be builtin)", err)
	}
}

// --- Unmarshal error tests ---

func TestProcessor_Receive_UnmarshalError(t *testing.T) {
	proc, _ := NewProcessor[SimpleUser](&testCodec{})

	_, err := proc.Receive(context.Background(), []byte("invalid json"))
	if err == nil {
		t.Error("Receive() should fail on invalid JSON")
	}
}

func TestProcessor_Load_UnmarshalError(t *testing.T) {
	proc, _ := NewProcessor[SimpleUser](&testCodec{})

	_, err := proc.Load(context.Background(), []byte("invalid json"))
	if err == nil {
		t.Error("Load() should fail on invalid JSON")
	}
}

// --- Error path tests ---

func TestProcessor_Load_DecryptError_InvalidBase64(t *testing.T) {
	proc, _ := NewProcessor[EncryptUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	// Email field contains invalid base64
	input := `{"id":"123","email":"not-valid-base64!!!"}`
	_, err := proc.Load(context.Background(), []byte(input))
	if err == nil {
		t.Error("Load() should fail on invalid base64")
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("Load() error = %q, should mention base64", err.Error())
	}
}

func TestProcessor_Load_DecryptError_CorruptedCiphertext(t *testing.T) {
	proc, _ := NewProcessor[EncryptUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	// Valid base64 but not valid AES ciphertext
	input := `{"id":"123","email":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="}`
	_, err := proc.Load(context.Background(), []byte(input))
	if err == nil {
		t.Error("Load() should fail on corrupted ciphertext")
	}
	if !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("Load() error = %q, should mention decrypt", err.Error())
	}
}

func TestProcessor_Store_MarshalError(t *testing.T) {
	// Create a codec that fails on marshal
	failCodec := &failingCodec{failMarshal: true}
	proc, _ := NewProcessor[SimpleUser](failCodec)

	user := &SimpleUser{ID: "123", Name: "test"}
	_, err := proc.Store(context.Background(), user)
	if err == nil {
		t.Error("Store() should fail when marshal fails")
	}
}

func TestProcessor_Send_MarshalError(t *testing.T) {
	failCodec := &failingCodec{failMarshal: true}
	proc, _ := NewProcessor[SimpleUser](failCodec)

	user := &SimpleUser{ID: "123", Name: "test"}
	_, err := proc.Send(context.Background(), user)
	if err == nil {
		t.Error("Send() should fail when marshal fails")
	}
}

type failingCodec struct {
	failMarshal   bool
	failUnmarshal bool
}

func (c *failingCodec) ContentType() string { return "application/json" }

func (c *failingCodec) Marshal(v any) ([]byte, error) {
	if c.failMarshal {
		return nil, fmt.Errorf("marshal failed")
	}
	return json.Marshal(v)
}

func (c *failingCodec) Unmarshal(data []byte, v any) error {
	if c.failUnmarshal {
		return fmt.Errorf("unmarshal failed")
	}
	return json.Unmarshal(data, v)
}

// --- Validation error tests ---

func TestProcessor_Validate_CalledOnce(t *testing.T) {
	proc, _ := NewProcessor[EncryptUser](&testCodec{})

	// First validate should fail (no encryptor)
	err1 := proc.Validate()
	if err1 == nil {
		t.Fatal("Validate() should fail without encryptor")
	}

	// Add encryptor
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	// Second validate still returns cached error (validateOnce)
	err2 := proc.Validate()
	if err2 == nil || err2.Error() != err1.Error() {
		t.Error("Validate() should return cached error")
	}
}

func TestProcessor_Operations_FailWithoutValidation(t *testing.T) {
	proc, _ := NewProcessor[EncryptUser](&testCodec{})
	// Don't set encryptor - validation will fail

	ctx := context.Background()

	// All operations should fail validation
	_, err := proc.Store(ctx, &EncryptUser{ID: "123", Email: "test@example.com"})
	if err == nil {
		t.Error("Store() should fail validation")
	}

	_, err = proc.Load(ctx, []byte(`{"id":"123","email":"encrypted"}`))
	if err == nil {
		t.Error("Load() should fail validation")
	}
}

// --- Empty/nil handling tests ---

func TestProcessor_Store_EmptyFields(t *testing.T) {
	proc, _ := NewProcessor[EncryptUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	user := &EncryptUser{ID: "123", Email: ""} // Empty email
	data, err := proc.Store(context.Background(), user)
	if err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	loaded, err := proc.Load(context.Background(), data)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded.Email != "" {
		t.Errorf("Load() Email = %q, want empty", loaded.Email)
	}
}

func TestProcessor_Send_EmptyFields(t *testing.T) {
	proc, _ := NewProcessor[MaskUser](&testCodec{})

	user := &MaskUser{ID: "123", Email: "", SSN: ""} // Empty fields - invalid for masking
	_, err := proc.Send(context.Background(), user)
	if err == nil {
		t.Fatal("Send() should fail for empty masked fields")
	}
	if !errors.Is(err, ErrMask) {
		t.Errorf("Send() error = %v, want ErrMask", err)
	}
}

func TestProcessor_Receive_EmptyFields(t *testing.T) {
	proc, _ := NewProcessor[HashUser](&testCodec{})

	input := `{"id":"123","password":""}` // Empty password
	user, err := proc.Receive(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("Receive() error: %v", err)
	}
	// Empty password should be hashed (hash of empty string)
	if user.Password == "" {
		t.Error("Receive() should hash empty password")
	}
}

// --- Slice and Map error path tests ---

type SliceDecryptUser struct {
	ID     string   `json:"id"`
	Emails []string `json:"emails" store.encrypt:"aes" load.decrypt:"aes"`
}

func (u SliceDecryptUser) Clone() SliceDecryptUser {
	clone := SliceDecryptUser{ID: u.ID}
	if u.Emails != nil {
		clone.Emails = make([]string, len(u.Emails))
		copy(clone.Emails, u.Emails)
	}
	return clone
}

func TestProcessor_Load_SliceDecryptError(t *testing.T) {
	proc, _ := NewProcessor[SliceDecryptUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	// Slice with invalid base64
	input := `{"id":"123","emails":["invalid-base64!!!"]}`
	_, err := proc.Load(context.Background(), []byte(input))
	if err == nil {
		t.Error("Load() should fail on invalid base64 in slice")
	}
}

type MapDecryptUser struct {
	ID     string            `json:"id"`
	Emails map[string]string `json:"emails" store.encrypt:"aes" load.decrypt:"aes"`
}

func (u MapDecryptUser) Clone() MapDecryptUser {
	clone := MapDecryptUser{ID: u.ID}
	if u.Emails != nil {
		clone.Emails = make(map[string]string)
		for k, v := range u.Emails {
			clone.Emails[k] = v
		}
	}
	return clone
}

func TestProcessor_Load_MapDecryptError(t *testing.T) {
	proc, _ := NewProcessor[MapDecryptUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	// Map with invalid base64
	input := `{"id":"123","emails":{"work":"invalid-base64!!!"}}`
	_, err := proc.Load(context.Background(), []byte(input))
	if err == nil {
		t.Error("Load() should fail on invalid base64 in map")
	}
}

// --- Context cancellation tests ---

func TestProcessor_Operations_WithCancelledContext(t *testing.T) {
	proc, _ := NewProcessor[SimpleUser](&testCodec{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Operations should still work (context is for signaling only, not enforced)
	user := &SimpleUser{ID: "123", Name: "test"}
	_, err := proc.Store(ctx, user)
	// Context cancellation isn't checked by the processor itself
	// This just verifies no panic occurs
	if err != nil {
		t.Logf("Store with cancelled context: %v", err)
	}

	_, err = proc.Send(ctx, user)
	if err != nil {
		t.Logf("Send with cancelled context: %v", err)
	}
}

// --- Deep nesting tests ---

// Level3 is the deepest nested struct.
type Level3 struct {
	Secret string `json:"secret" send.redact:"[L3]"`
}

// Level2 contains Level3.
type Level2 struct {
	Data   string `json:"data" send.redact:"[L2]"`
	Nested Level3 `json:"nested"`
}

// Level1 contains Level2.
type Level1 struct {
	Info   string `json:"info" send.redact:"[L1]"`
	Nested Level2 `json:"nested"`
}

// DeeplyNestedUser has 3 levels of nesting.
type DeeplyNestedUser struct {
	ID     string `json:"id"`
	Nested Level1 `json:"nested"`
}

func (u DeeplyNestedUser) Clone() DeeplyNestedUser {
	return DeeplyNestedUser{ID: u.ID, Nested: u.Nested}
}

func TestProcessor_Send_DeeplyNestedStruct(t *testing.T) {
	proc, _ := NewProcessor[DeeplyNestedUser](&testCodec{})

	user := &DeeplyNestedUser{
		ID: "123",
		Nested: Level1{
			Info: "level1-info",
			Nested: Level2{
				Data: "level2-data",
				Nested: Level3{
					Secret: "level3-secret",
				},
			},
		},
	}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent DeeplyNestedUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if sent.Nested.Info != "[L1]" {
		t.Errorf("Level1 Info = %q, want %q", sent.Nested.Info, "[L1]")
	}
	if sent.Nested.Nested.Data != "[L2]" {
		t.Errorf("Level2 Data = %q, want %q", sent.Nested.Nested.Data, "[L2]")
	}
	if sent.Nested.Nested.Nested.Secret != "[L3]" {
		t.Errorf("Level3 Secret = %q, want %q", sent.Nested.Nested.Nested.Secret, "[L3]")
	}
}

// PointerLevel2 is a pointer-based nesting level.
type PointerLevel2 struct {
	Value string `json:"value" send.redact:"[PL2]"`
}

// PointerLevel1 contains a pointer to PointerLevel2.
type PointerLevel1 struct {
	Data   string         `json:"data" send.redact:"[PL1]"`
	Nested *PointerLevel2 `json:"nested"`
}

// DeeplyNestedPointerUser has pointer nesting.
type DeeplyNestedPointerUser struct {
	ID     string         `json:"id"`
	Nested *PointerLevel1 `json:"nested"`
}

func (u DeeplyNestedPointerUser) Clone() DeeplyNestedPointerUser {
	clone := DeeplyNestedPointerUser{ID: u.ID}
	if u.Nested != nil {
		nested1 := *u.Nested
		clone.Nested = &nested1
		if u.Nested.Nested != nil {
			nested2 := *u.Nested.Nested
			clone.Nested.Nested = &nested2
		}
	}
	return clone
}

func TestProcessor_Send_DeeplyNestedPointer(t *testing.T) {
	proc, _ := NewProcessor[DeeplyNestedPointerUser](&testCodec{})

	user := &DeeplyNestedPointerUser{
		ID: "123",
		Nested: &PointerLevel1{
			Data: "level1-data",
			Nested: &PointerLevel2{
				Value: "level2-value",
			},
		},
	}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent DeeplyNestedPointerUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if sent.Nested.Data != "[PL1]" {
		t.Errorf("Level1 Data = %q, want %q", sent.Nested.Data, "[PL1]")
	}
	if sent.Nested.Nested.Value != "[PL2]" {
		t.Errorf("Level2 Value = %q, want %q", sent.Nested.Nested.Value, "[PL2]")
	}
}

func TestProcessor_Send_DeeplyNestedPointer_NilIntermediate(t *testing.T) {
	proc, _ := NewProcessor[DeeplyNestedPointerUser](&testCodec{})

	// First level pointer is set, but second level is nil
	user := &DeeplyNestedPointerUser{
		ID: "123",
		Nested: &PointerLevel1{
			Data:   "level1-data",
			Nested: nil,
		},
	}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent DeeplyNestedPointerUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if sent.Nested.Data != "[PL1]" {
		t.Errorf("Level1 Data = %q, want %q", sent.Nested.Data, "[PL1]")
	}
	if sent.Nested.Nested != nil {
		t.Error("Level2 should remain nil")
	}
}

// --- Empty collection tests ---

func TestProcessor_Send_EmptySlice(t *testing.T) {
	proc, _ := NewProcessor[SliceUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	user := &SliceUser{
		ID:     "123",
		Emails: []string{}, // Empty slice
	}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent SliceUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if len(sent.Emails) != 0 {
		t.Errorf("Emails length = %d, want 0", len(sent.Emails))
	}
}

func TestProcessor_Send_EmptyMap(t *testing.T) {
	proc, _ := NewProcessor[MapUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	user := &MapUser{
		ID:     "123",
		Emails: map[string]string{}, // Empty map
	}
	data, err := proc.Send(context.Background(), user)
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	var sent MapUser
	if err := json.Unmarshal(data, &sent); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if len(sent.Emails) != 0 {
		t.Errorf("Emails length = %d, want 0", len(sent.Emails))
	}
}

func TestProcessor_Store_NilSlice(t *testing.T) {
	proc, _ := NewProcessor[SliceUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	user := &SliceUser{
		ID:     "123",
		Emails: nil, // Nil slice
		SSNs:   nil,
	}
	data, err := proc.Store(context.Background(), user)
	if err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	loaded, err := proc.Load(context.Background(), data)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if loaded.Emails != nil {
		t.Errorf("Emails = %v, want nil", loaded.Emails)
	}
}

func TestProcessor_Store_NilMap(t *testing.T) {
	proc, _ := NewProcessor[MapUser](&testCodec{})
	enc, _ := AES([]byte("32-byte-key-for-aes-256-encrypt!"))
	proc.SetEncryptor(EncryptAES, enc)

	user := &MapUser{
		ID:     "123",
		Emails: nil, // Nil map
		SSNs:   nil,
	}
	data, err := proc.Store(context.Background(), user)
	if err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	loaded, err := proc.Load(context.Background(), data)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if loaded.Emails != nil {
		t.Errorf("Emails = %v, want nil", loaded.Emails)
	}
}

// --- Validation edge case tests ---

// MultiMissingUser requires multiple handlers.
type MultiMissingUser struct {
	ID       string `json:"id"`
	Email    string `json:"email" store.encrypt:"aes"`
	Password string `json:"password" store.encrypt:"rsa"`
}

func (u MultiMissingUser) Clone() MultiMissingUser { return u }

func TestProcessor_Validate_MultipleErrors(t *testing.T) {
	proc, _ := NewProcessor[MultiMissingUser](&testCodec{})

	// Don't configure any encryptors - both aes and rsa are missing
	err := proc.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when encryptors are missing")
	}

	// Should return first error encountered
	if !strings.Contains(err.Error(), "missing encryptor") {
		t.Errorf("Validate() error = %q, want 'missing encryptor'", err.Error())
	}
}

// --- Interface override error path tests ---

// ErrorHashableUser implements Hashable but returns an error.
type ErrorHashableUser struct {
	ID       string `json:"id"`
	Password string `json:"password" receive.hash:"sha256"`
}

func (u ErrorHashableUser) Clone() ErrorHashableUser { return u }

func (u *ErrorHashableUser) Hash(_ map[HashAlgo]Hasher) error {
	return fmt.Errorf("hash override error")
}

func TestProcessor_Receive_HashableError(t *testing.T) {
	proc, _ := NewProcessor[ErrorHashableUser](&testCodec{})

	input := `{"id":"123","password":"secret"}`
	_, err := proc.Receive(context.Background(), []byte(input))
	if err == nil {
		t.Fatal("Receive() should fail when Hashable.Hash returns error")
	}
	if !strings.Contains(err.Error(), "hash override error") {
		t.Errorf("Receive() error = %q, want 'hash override error'", err.Error())
	}
}

// ErrorEncryptableUser implements Encryptable but returns an error.
type ErrorEncryptableUser struct {
	ID    string `json:"id"`
	Email string `json:"email" store.encrypt:"aes"`
}

func (u ErrorEncryptableUser) Clone() ErrorEncryptableUser { return u }

func (u *ErrorEncryptableUser) Encrypt(_ map[EncryptAlgo]Encryptor) error {
	return fmt.Errorf("encrypt override error")
}

func TestProcessor_Store_EncryptableError(t *testing.T) {
	proc, _ := NewProcessor[ErrorEncryptableUser](&testCodec{})

	user := &ErrorEncryptableUser{ID: "123", Email: "test@example.com"}
	_, err := proc.Store(context.Background(), user)
	if err == nil {
		t.Fatal("Store() should fail when Encryptable.Encrypt returns error")
	}
	if !strings.Contains(err.Error(), "encrypt override error") {
		t.Errorf("Store() error = %q, want 'encrypt override error'", err.Error())
	}
}

// ErrorDecryptableUser implements Decryptable but returns an error.
type ErrorDecryptableUser struct {
	ID    string `json:"id"`
	Email string `json:"email" load.decrypt:"aes"`
}

func (u ErrorDecryptableUser) Clone() ErrorDecryptableUser { return u }

func (u *ErrorDecryptableUser) Decrypt(_ map[EncryptAlgo]Encryptor) error {
	return fmt.Errorf("decrypt override error")
}

func TestProcessor_Load_DecryptableError(t *testing.T) {
	proc, _ := NewProcessor[ErrorDecryptableUser](&testCodec{})

	input := `{"id":"123","email":"encrypted-data"}`
	_, err := proc.Load(context.Background(), []byte(input))
	if err == nil {
		t.Fatal("Load() should fail when Decryptable.Decrypt returns error")
	}
	if !strings.Contains(err.Error(), "decrypt override error") {
		t.Errorf("Load() error = %q, want 'decrypt override error'", err.Error())
	}
}

// ErrorMaskableUser implements Maskable but returns an error.
type ErrorMaskableUser struct {
	ID    string `json:"id"`
	Email string `json:"email" send.mask:"email"`
}

func (u ErrorMaskableUser) Clone() ErrorMaskableUser { return u }

func (u *ErrorMaskableUser) Mask(_ map[MaskType]Masker) error {
	return fmt.Errorf("mask override error")
}

func TestProcessor_Send_MaskableError(t *testing.T) {
	proc, _ := NewProcessor[ErrorMaskableUser](&testCodec{})

	user := &ErrorMaskableUser{ID: "123", Email: "test@example.com"}
	_, err := proc.Send(context.Background(), user)
	if err == nil {
		t.Fatal("Send() should fail when Maskable.Mask returns error")
	}
	if !strings.Contains(err.Error(), "mask override error") {
		t.Errorf("Send() error = %q, want 'mask override error'", err.Error())
	}
}

// ErrorRedactableUser implements Redactable but returns an error.
type ErrorRedactableUser struct {
	ID       string `json:"id"`
	Password string `json:"password" send.redact:"***"`
}

func (u ErrorRedactableUser) Clone() ErrorRedactableUser { return u }

func (u *ErrorRedactableUser) Redact() error {
	return fmt.Errorf("redact override error")
}

func TestProcessor_Send_RedactableError(t *testing.T) {
	proc, _ := NewProcessor[ErrorRedactableUser](&testCodec{})

	user := &ErrorRedactableUser{ID: "123", Password: "secret"}
	_, err := proc.Send(context.Background(), user)
	if err == nil {
		t.Fatal("Send() should fail when Redactable.Redact returns error")
	}
	if !strings.Contains(err.Error(), "redact override error") {
		t.Errorf("Send() error = %q, want 'redact override error'", err.Error())
	}
}

