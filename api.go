// Package codec provides context-aware serialization with field transformation.
//
// The package offers a Codec interface for marshaling/unmarshaling data,
// along with a generic Processor that adds context-aware field transformation
// including encryption, hashing, masking, and redaction based on struct tags.
//
// # Contexts
//
// Codec operates on four contexts representing boundary crossings:
//
//   - receive: Ingress from external sources (API requests, events)
//   - load: Ingress from storage (database, cache)
//   - store: Egress to storage
//   - send: Egress to external destinations (API responses, events)
//
// # Tag Syntax
//
// Field behavior is declared via struct tags:
//
//	{context}.{action}:"{capability}"
//
// Valid combinations:
//
//	receive.hash:"argon2"    - Hash on receive (passwords)
//	load.decrypt:"aes"       - Decrypt on load
//	store.encrypt:"aes"      - Encrypt on store
//	send.mask:"email"        - Mask on send
//	send.redact:"***"        - Redact on send
//
// # Basic Usage
//
//	type User struct {
//	    ID       string `json:"id"`
//	    Password string `json:"password" receive.hash:"argon2" send.redact:"***"`
//	    Email    string `json:"email" store.encrypt:"aes" load.decrypt:"aes" send.mask:"email"`
//	}
//
//	func (u User) Clone() User { return u }
//
//	proc, _ := codec.NewProcessor[User](
//	    json.Codec(),
//	    codec.WithKey(codec.EncryptAES, aesKey),
//	)
//
//	// Receive from API (hashes password)
//	user, _ := proc.Receive(requestBody)
//
//	// Store to database (encrypts email)
//	data, _ := proc.Store(user)
//
//	// Load from database (decrypts email)
//	user, _ := proc.Load(dbRow)
//
//	// Send to API (masks email, redacts password)
//	response, _ := proc.Send(user)
//
// # Capability Types
//
// Capabilities are constrained to predefined constants:
//
//   - EncryptAlgo: EncryptAES, EncryptRSA, EncryptEnvelope
//   - HashAlgo: HashArgon2, HashBcrypt, HashSHA256, HashSHA512
//   - MaskType: MaskSSN, MaskEmail, MaskPhone, MaskCard, MaskIP, MaskUUID, MaskIBAN, MaskName
//
// # Auto-Registration
//
// Hashers and maskers are auto-registered. Only encryption keys need manual registration:
//
//	codec.WithKey(codec.EncryptAES, key)
//
// # Override Interfaces
//
// Types can bypass reflection by implementing action-specific interfaces:
//
//   - Encryptable: Custom encryption logic
//   - Decryptable: Custom decryption logic
//   - Hashable: Custom hashing logic
//   - Maskable: Custom masking logic
//   - Redactable: Custom redaction logic
//
// # Codec Providers
//
// The following codec implementations are available as submodules:
//
//   - json - JSON encoding (application/json)
//   - xml - XML encoding (application/xml)
//   - yaml - YAML encoding (application/yaml)
//   - msgpack - MessagePack encoding (application/msgpack)
//   - bson - BSON encoding (application/bson)
//
// # Encryption Algorithms
//
// Built-in encryptors:
//
//   - AES(key) - AES-GCM symmetric encryption
//   - RSA(pub, priv) - RSA-OAEP asymmetric encryption
//   - Envelope(masterKey) - Envelope encryption with per-message data keys
//
// # Hash Algorithms
//
// Built-in hashers:
//
//   - Argon2() - Argon2id password hashing (salted)
//   - Bcrypt() - bcrypt password hashing (salted)
//   - SHA256Hasher() - SHA-256 deterministic hashing
//   - SHA512Hasher() - SHA-512 deterministic hashing
//
// # Masking
//
// Built-in content-aware maskers:
//
//   - ssn: 123-45-6789 → ***-**-6789
//   - email: alice@example.com → a***@example.com
//   - phone: (555) 123-4567 → (***) ***-4567
//   - card: 4111111111111111 → ************1111
//   - ip: 192.168.1.100 → 192.168.xxx.xxx
//   - uuid: 550e8400-e29b-... → 550e8400-****-****-****-************
//   - iban: GB82WEST12345698765432 → GB82**************5432
//   - name: John Smith → J*** S****
package codec

// Cloner allows types to provide deep copy logic.
// Implementing this interface is required for use with Serializer.
//
// The Clone method must return a deep copy where modifications to the clone
// do not affect the original value. For types containing pointers, slices, or maps,
// ensure these are also copied to achieve true isolation.
//
// For simple value types with no pointers, slices, or maps, Clone can simply return
// the receiver value:
//
//	func (u User) Clone() User { return u }
//
// For types with reference fields, ensure deep copying:
//
//	func (o Order) Clone() Order {
//	    items := make([]Item, len(o.Items))
//	    copy(items, o.Items)
//	    return Order{ID: o.ID, Items: items}
//	}
type Cloner[T any] interface {
	Clone() T
}

// Codec provides content-type aware marshaling.
type Codec interface {
	// ContentType returns the MIME type for this codec (e.g., "application/json").
	ContentType() string

	// Marshal encodes v into bytes.
	Marshal(v any) ([]byte, error)

	// Unmarshal decodes data into v.
	Unmarshal(data []byte, v any) error
}

// Override interfaces allow types to bypass reflection-based processing.
// When a type implements one of these interfaces, the Processor calls the
// interface method instead of using reflection to transform fields.
//
// This provides two benefits:
// 1. Performance: Avoid reflection overhead for hot paths
// 2. Custom logic: Implement transformations that can't be expressed via tags
//
// These interfaces are designed for codegen: a code generator can implement
// these methods based on struct tags, providing compile-time safety and
// optimal performance.

// Encryptable bypasses reflection for store.encrypt actions.
// Implement this to handle all encryption for a type.
type Encryptable interface {
	// Encrypt transforms the receiver's fields that require encryption.
	// The encryptors map contains all registered encryptors keyed by algorithm.
	// The receiver is a clone, so mutations are safe.
	Encrypt(encryptors map[EncryptAlgo]Encryptor) error
}

// Decryptable bypasses reflection for load.decrypt actions.
// Implement this to handle all decryption for a type.
type Decryptable interface {
	// Decrypt transforms the receiver's fields that require decryption.
	// The encryptors map contains all registered encryptors keyed by algorithm.
	// Called on freshly unmarshaled data.
	Decrypt(encryptors map[EncryptAlgo]Encryptor) error
}

// Hashable bypasses reflection for receive.hash actions.
// Implement this to handle all hashing for a type.
type Hashable interface {
	// Hash transforms the receiver's fields that require hashing.
	// The hashers map contains all registered hashers keyed by algorithm.
	// Called on freshly unmarshaled data.
	Hash(hashers map[HashAlgo]Hasher) error
}

// Maskable bypasses reflection for send.mask actions.
// Implement this to handle all masking for a type.
type Maskable interface {
	// Mask transforms the receiver's fields that require masking.
	// The maskers map contains all registered maskers keyed by type.
	// The receiver is a clone, so mutations are safe.
	Mask(maskers map[MaskType]Masker) error
}

// Redactable bypasses reflection for send.redact actions.
// Implement this to handle all redaction for a type.
type Redactable interface {
	// Redact transforms the receiver's fields that require redaction.
	// The receiver is a clone, so mutations are safe.
	// Redaction values are typically hardcoded based on struct tag values.
	Redact() error
}
