package integration

import (
	"context"
	"testing"

	"github.com/zoobzio/cereal"
	"github.com/zoobzio/cereal/json"
	"github.com/zoobzio/cereal/msgpack"
	"github.com/zoobzio/cereal/xml"
	"github.com/zoobzio/cereal/yaml"
	codectest "github.com/zoobzio/cereal/testing"
)

func TestProcessor_StoreLoad_JSON(t *testing.T) {
	testStoreLoad(t, json.New())
}

func TestProcessor_StoreLoad_YAML(t *testing.T) {
	testStoreLoad(t, yaml.New())
}

func TestProcessor_StoreLoad_MessagePack(t *testing.T) {
	testStoreLoad(t, msgpack.New())
}

// XMLUser for XML-specific tests
type XMLUser struct {
	ID       string `xml:"id"`
	Email    string `xml:"email" store.encrypt:"aes" load.decrypt:"aes" send.mask:"email"`
	Password string `xml:"password" receive.hash:"argon2" send.redact:"***"`
	Note     string `xml:"note" send.redact:"[REDACTED]"`
}

func (u XMLUser) Clone() XMLUser { return u }

// XML requires different struct tags, test separately
func TestProcessor_StoreLoad_XML(t *testing.T) {
	proc, err := cereal.NewProcessor[XMLUser](xml.New())
	if err != nil {
		t.Fatalf("NewProcessor error: %v", err)
	}
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(t))

	original := &XMLUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "supersecret",
		Note:     "internal note",
	}

	// Store encrypts email
	data, err := proc.Store(context.Background(), original)
	if err != nil {
		t.Fatalf("Store error: %v", err)
	}

	// Load decrypts email
	restored, err := proc.Load(context.Background(), data)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	// Email should be decrypted back to original
	if restored.Email != original.Email {
		t.Errorf("Email = %q, want %q", restored.Email, original.Email)
	}
}

func TestProcessor_Send_XML(t *testing.T) {
	xmlCodec := xml.New()
	proc, err := cereal.NewProcessor[XMLUser](xmlCodec)
	if err != nil {
		t.Fatalf("NewProcessor error: %v", err)
	}
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(t))

	original := &XMLUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "supersecret",
		Note:     "internal note",
	}

	// Send masks email and redacts password/note
	data, err := proc.Send(context.Background(), original)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}

	// Parse the result directly (without Load's decrypt) to verify masking/redaction
	var restored XMLUser
	if err := xmlCodec.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	// Email should be masked
	if restored.Email == original.Email {
		t.Error("Email should be masked")
	}

	// Password should be redacted
	if restored.Password != "***" {
		t.Errorf("Password = %q, want %q", restored.Password, "***")
	}

	// Note should be redacted
	if restored.Note != "[REDACTED]" {
		t.Errorf("Note = %q, want %q", restored.Note, "[REDACTED]")
	}
}

func testStoreLoad(t *testing.T, c cereal.Codec) {
	t.Helper()

	proc, err := cereal.NewProcessor[codectest.SanitizedUser](c)
	if err != nil {
		t.Fatalf("NewProcessor error: %v", err)
	}
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(t))

	original := &codectest.SanitizedUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "supersecret",
		SSN:      "123-45-6789",
		Note:     "internal note",
	}

	// Store encrypts email
	data, err := proc.Store(context.Background(), original)
	if err != nil {
		t.Fatalf("Store error: %v", err)
	}

	// Load decrypts email
	restored, err := proc.Load(context.Background(), data)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	// Email should be decrypted back to original
	if restored.Email != original.Email {
		t.Errorf("Email = %q, want %q", restored.Email, original.Email)
	}
}

func TestProcessor_Send(t *testing.T) {
	jsonCodec := json.New()
	proc, err := cereal.NewProcessor[codectest.SanitizedUser](jsonCodec)
	if err != nil {
		t.Fatalf("NewProcessor error: %v", err)
	}
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(t))

	original := &codectest.SanitizedUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "supersecret",
		SSN:      "123-45-6789",
		Note:     "internal note",
	}

	// Send masks email/SSN and redacts password/note
	data, err := proc.Send(context.Background(), original)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}

	// Parse directly (without Load's decrypt) to verify transformations
	var restored codectest.SanitizedUser
	if err := jsonCodec.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	// Email should be masked
	if restored.Email == original.Email {
		t.Error("Email should be masked")
	}
	if restored.Email != "a***@example.com" {
		t.Errorf("Email = %q, want %q", restored.Email, "a***@example.com")
	}

	// SSN should be masked
	if restored.SSN != "***-**-6789" {
		t.Errorf("SSN = %q, want %q", restored.SSN, "***-**-6789")
	}

	// Password should be redacted
	if restored.Password != "***" {
		t.Errorf("Password = %q, want %q", restored.Password, "***")
	}

	// Note should be redacted
	if restored.Note != "[REDACTED]" {
		t.Errorf("Note = %q, want %q", restored.Note, "[REDACTED]")
	}
}
