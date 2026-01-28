package integration

import (
	"context"
	"testing"

	"github.com/zoobzio/cereal"
	"github.com/zoobzio/cereal/bson"
	"github.com/zoobzio/cereal/json"
	"github.com/zoobzio/cereal/msgpack"
	"github.com/zoobzio/cereal/xml"
	"github.com/zoobzio/cereal/yaml"
	codectest "github.com/zoobzio/cereal/testing"
)

// --- Codec interface tests ---

func TestCodec_AllImplementations(t *testing.T) {
	codecs := []struct {
		name        string
		codec       cereal.Codec
		contentType string
	}{
		{"json", json.New(), "application/json"},
		{"yaml", yaml.New(), "application/yaml"},
		{"xml", xml.New(), "application/xml"},
		{"msgpack", msgpack.New(), "application/msgpack"},
		{"bson", bson.New(), "application/bson"},
	}

	for _, tc := range codecs {
		t.Run(tc.name, func(t *testing.T) {
			// Test ContentType
			if got := tc.codec.ContentType(); got != tc.contentType {
				t.Errorf("ContentType() = %q, want %q", got, tc.contentType)
			}

			// Test non-nil codec
			if tc.codec == nil {
				t.Error("New() returned nil codec")
			}
		})
	}
}

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
	proc, err := cereal.NewProcessor[XMLUser]()
	if err != nil {
		t.Fatalf("NewProcessor error: %v", err)
	}
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(t))
	proc.SetCodec(xml.New())

	original := &XMLUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "supersecret",
		Note:     "internal note",
	}

	// Store encrypts email
	data, err := proc.Write(context.Background(), original)
	if err != nil {
		t.Fatalf("Store error: %v", err)
	}

	// Load decrypts email
	restored, err := proc.Read(context.Background(), data)
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
	proc, err := cereal.NewProcessor[XMLUser]()
	if err != nil {
		t.Fatalf("NewProcessor error: %v", err)
	}
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(t))
	proc.SetCodec(xmlCodec)

	original := &XMLUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "supersecret",
		Note:     "internal note",
	}

	// Send masks email and redacts password/note
	data, err := proc.Encode(context.Background(), original)
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

	proc, err := cereal.NewProcessor[codectest.SanitizedUser]()
	if err != nil {
		t.Fatalf("NewProcessor error: %v", err)
	}
	proc.SetCodec(c)
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(t))

	original := &codectest.SanitizedUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "supersecret",
		SSN:      "123-45-6789",
		Note:     "internal note",
	}

	// Store encrypts email
	data, err := proc.Write(context.Background(), original)
	if err != nil {
		t.Fatalf("Store error: %v", err)
	}

	// Load decrypts email
	restored, err := proc.Read(context.Background(), data)
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
	proc, err := cereal.NewProcessor[codectest.SanitizedUser]()
	if err != nil {
		t.Fatalf("NewProcessor error: %v", err)
	}
	proc.SetCodec(jsonCodec)
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(t))

	original := &codectest.SanitizedUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "supersecret",
		SSN:      "123-45-6789",
		Note:     "internal note",
	}

	// Send masks email/SSN and redacts password/note
	data, err := proc.Encode(context.Background(), original)
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

// --- Full boundary cycle tests ---

// FullCycleUser has tags for all four boundaries.
type FullCycleUser struct {
	ID       string `json:"id"`
	Password string `json:"password" receive.hash:"sha256"`
	Email    string `json:"email" store.encrypt:"aes" load.decrypt:"aes" send.mask:"email"`
	Secret   string `json:"secret" send.redact:"[HIDDEN]"`
}

func (u FullCycleUser) Clone() FullCycleUser { return u }

func TestProcessor_FullBoundaryCycle(t *testing.T) {
	proc, err := cereal.NewProcessor[FullCycleUser]()
	if err != nil {
		t.Fatalf("NewProcessor error: %v", err)
	}
	proc.SetCodec(json.New())
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(t))

	// Step 1: Receive (hash password)
	input := `{"id":"123","password":"secret","email":"alice@example.com","secret":"my-secret"}`
	received, err := proc.Decode(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("Receive error: %v", err)
	}

	// Password should be hashed
	if received.Password == "secret" {
		t.Error("Receive should hash password")
	}
	if len(received.Password) != 64 { // SHA256 = 64 hex chars
		t.Errorf("Password hash length = %d, want 64", len(received.Password))
	}

	// Step 2: Store (encrypt email)
	stored, err := proc.Write(context.Background(), received)
	if err != nil {
		t.Fatalf("Store error: %v", err)
	}

	// Step 3: Load (decrypt email)
	loaded, err := proc.Read(context.Background(), stored)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	// Email should be decrypted back
	if loaded.Email != received.Email {
		t.Errorf("Load Email = %q, want %q", loaded.Email, received.Email)
	}

	// Password hash should be preserved
	if loaded.Password != received.Password {
		t.Error("Load should preserve password hash")
	}

	// Step 4: Send (mask email, redact secret)
	sent, err := proc.Encode(context.Background(), loaded)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}

	var sentUser FullCycleUser
	if err := json.New().Unmarshal(sent, &sentUser); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	// Email should be masked
	if sentUser.Email == loaded.Email {
		t.Error("Send should mask email")
	}

	// Secret should be redacted
	if sentUser.Secret != "[HIDDEN]" {
		t.Errorf("Send Secret = %q, want %q", sentUser.Secret, "[HIDDEN]")
	}
}

// --- Concurrent processor operations ---

func TestProcessor_ConcurrentOperations(t *testing.T) {
	proc, err := cereal.NewProcessor[codectest.SanitizedUser]()
	if err != nil {
		t.Fatalf("NewProcessor error: %v", err)
	}
	proc.SetCodec(json.New())
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(t))

	const goroutines = 50
	errs := make(chan error, goroutines*4)

	user := &codectest.SanitizedUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "secret",
		SSN:      "123-45-6789",
		Note:     "note",
	}

	// First store to get encrypted data for Load operations
	storedData, err := proc.Write(context.Background(), user)
	if err != nil {
		t.Fatalf("Initial Store error: %v", err)
	}

	for i := 0; i < goroutines; i++ {
		// Concurrent Store
		go func() {
			_, err := proc.Write(context.Background(), user)
			errs <- err
		}()

		// Concurrent Load
		go func() {
			_, err := proc.Read(context.Background(), storedData)
			errs <- err
		}()

		// Concurrent Send
		go func() {
			_, err := proc.Encode(context.Background(), user)
			errs <- err
		}()

		// Concurrent Receive
		go func() {
			input := `{"id":"123","email":"test@example.com","password":"pass","ssn":"111-22-3333","note":"n"}`
			_, err := proc.Decode(context.Background(), []byte(input))
			errs <- err
		}()
	}

	for i := 0; i < goroutines*4; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent operation error: %v", err)
		}
	}
}

// --- Complex nested structure tests ---

type NestedAddress struct {
	Street string `json:"street" send.redact:"[ADDRESS]"`
	City   string `json:"city"`
	ZIP    string `json:"zip" send.mask:"ssn"` // Using SSN mask for ZIP format
}

type NestedProfile struct {
	Bio   string `json:"bio" send.redact:"[BIO]"`
	Phone string `json:"phone" send.mask:"phone"`
}

type ComplexUser struct {
	ID       string         `json:"id"`
	Email    string         `json:"email" store.encrypt:"aes" load.decrypt:"aes" send.mask:"email"`
	Address  NestedAddress  `json:"address"`
	Profile  *NestedProfile `json:"profile"`
	Password string         `json:"password" receive.hash:"sha256" send.redact:"***"`
}

func (u ComplexUser) Clone() ComplexUser {
	clone := ComplexUser{
		ID:       u.ID,
		Email:    u.Email,
		Address:  u.Address,
		Password: u.Password,
	}
	if u.Profile != nil {
		p := *u.Profile
		clone.Profile = &p
	}
	return clone
}

func TestProcessor_ComplexNestedStructure(t *testing.T) {
	proc, err := cereal.NewProcessor[ComplexUser]()
	if err != nil {
		t.Fatalf("NewProcessor error: %v", err)
	}
	proc.SetCodec(json.New())
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(t))

	original := &ComplexUser{
		ID:    "123",
		Email: "alice@example.com",
		Address: NestedAddress{
			Street: "123 Main St",
			City:   "Boston",
			ZIP:    "123-45-6789",
		},
		Profile: &NestedProfile{
			Bio:   "Software developer",
			Phone: "(555) 123-4567",
		},
		Password: "secret",
	}

	// Test Store/Load cycle
	stored, err := proc.Write(context.Background(), original)
	if err != nil {
		t.Fatalf("Store error: %v", err)
	}

	loaded, err := proc.Read(context.Background(), stored)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if loaded.Email != original.Email {
		t.Errorf("Load Email = %q, want %q", loaded.Email, original.Email)
	}

	// Test Send transformations on nested fields
	sent, err := proc.Encode(context.Background(), loaded)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}

	var sentUser ComplexUser
	if err := json.New().Unmarshal(sent, &sentUser); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	// Nested address fields should be transformed
	if sentUser.Address.Street != "[ADDRESS]" {
		t.Errorf("Send Address.Street = %q, want %q", sentUser.Address.Street, "[ADDRESS]")
	}
	if sentUser.Address.City != "Boston" {
		t.Errorf("Send Address.City = %q, want %q (should not be transformed)", sentUser.Address.City, "Boston")
	}

	// Nested profile fields should be transformed
	if sentUser.Profile.Bio != "[BIO]" {
		t.Errorf("Send Profile.Bio = %q, want %q", sentUser.Profile.Bio, "[BIO]")
	}
	if sentUser.Profile.Phone == original.Profile.Phone {
		t.Error("Send should mask Profile.Phone")
	}
}

func TestProcessor_ComplexNestedStructure_NilPointer(t *testing.T) {
	proc, err := cereal.NewProcessor[ComplexUser]()
	if err != nil {
		t.Fatalf("NewProcessor error: %v", err)
	}
	proc.SetCodec(json.New())
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(t))

	original := &ComplexUser{
		ID:      "123",
		Email:   "alice@example.com",
		Profile: nil, // nil pointer
	}

	// Should handle nil pointer gracefully
	sent, err := proc.Encode(context.Background(), original)
	if err != nil {
		t.Fatalf("Send error: %v", err)
	}

	var sentUser ComplexUser
	if err := json.New().Unmarshal(sent, &sentUser); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if sentUser.Profile != nil {
		t.Error("Send should preserve nil Profile pointer")
	}
}

// --- Multiple processors same type ---

func TestProcessor_MultipleProcessorsSameType(t *testing.T) {
	key1 := []byte("32-byte-key-for-aes-256-encrypt!")
	key2 := []byte("another-32-byte-key-for-encrypt!")

	enc1, _ := cereal.AES(key1)
	enc2, _ := cereal.AES(key2)

	proc1, err := cereal.NewProcessor[codectest.SanitizedUser]()
	if err != nil {
		t.Fatalf("NewProcessor error: %v", err)
	}
	proc1.SetCodec(json.New())
	proc1.SetEncryptor(cereal.EncryptAES, enc1)

	proc2, err := cereal.NewProcessor[codectest.SanitizedUser]()
	if err != nil {
		t.Fatalf("NewProcessor error: %v", err)
	}
	proc2.SetCodec(json.New())
	proc2.SetEncryptor(cereal.EncryptAES, enc2)

	user := &codectest.SanitizedUser{
		ID:    "123",
		Email: "alice@example.com",
	}

	// Store with proc1
	data1, err := proc1.Write(context.Background(), user)
	if err != nil {
		t.Fatalf("proc1.Store error: %v", err)
	}

	// Store with proc2 (different key)
	data2, err := proc2.Write(context.Background(), user)
	if err != nil {
		t.Fatalf("proc2.Store error: %v", err)
	}

	// Load with same processor should work
	loaded1, err := proc1.Read(context.Background(), data1)
	if err != nil {
		t.Fatalf("proc1.Load error: %v", err)
	}
	if loaded1.Email != user.Email {
		t.Errorf("proc1.Load Email = %q, want %q", loaded1.Email, user.Email)
	}

	loaded2, err := proc2.Read(context.Background(), data2)
	if err != nil {
		t.Fatalf("proc2.Load error: %v", err)
	}
	if loaded2.Email != user.Email {
		t.Errorf("proc2.Load Email = %q, want %q", loaded2.Email, user.Email)
	}

	// Cross-load should fail (different keys)
	_, err = proc1.Read(context.Background(), data2)
	if err == nil {
		t.Error("proc1.Read(data2) should fail (different encryption key)")
	}
}

// --- BSON integration tests ---

func TestProcessor_StoreLoad_BSON(t *testing.T) {
	// BSON uses the same json tags for our test type
	testStoreLoadBSON(t)
}

// BSONUser for BSON-specific tests (uses bson tags)
type BSONUser struct {
	ID       string `bson:"id"`
	Email    string `bson:"email" store.encrypt:"aes" load.decrypt:"aes" send.mask:"email"`
	Password string `bson:"password" receive.hash:"argon2" send.redact:"***"`
}

func (u BSONUser) Clone() BSONUser { return u }

func testStoreLoadBSON(t *testing.T) {
	t.Helper()

	// Import bson package
	bsonCodec := bson.New()
	proc, err := cereal.NewProcessor[BSONUser]()
	if err != nil {
		t.Fatalf("NewProcessor error: %v", err)
	}
	proc.SetCodec(bsonCodec)
	proc.SetEncryptor(cereal.EncryptAES, codectest.TestEncryptor(t))

	original := &BSONUser{
		ID:       "123",
		Email:    "alice@example.com",
		Password: "supersecret",
	}

	// Store encrypts email
	data, err := proc.Write(context.Background(), original)
	if err != nil {
		t.Fatalf("Store error: %v", err)
	}

	// Load decrypts email
	restored, err := proc.Read(context.Background(), data)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	// Email should be decrypted back to original
	if restored.Email != original.Email {
		t.Errorf("Email = %q, want %q", restored.Email, original.Email)
	}
}
