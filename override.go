package codec

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
