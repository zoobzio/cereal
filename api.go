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
// The following codec implementations are available in pkg/:
//
//   - pkg/json - JSON encoding (application/json)
//   - pkg/xml - XML encoding (application/xml)
//   - pkg/yaml - YAML encoding (application/yaml)
//   - pkg/msgpack - MessagePack encoding (application/msgpack)
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
