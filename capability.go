package cereal

// EncryptAlgo represents a supported encryption algorithm.
// Use these constants in struct tags: `store.encrypt:"aes"`
type EncryptAlgo string

const (
	// EncryptAES uses AES-GCM symmetric encryption.
	EncryptAES EncryptAlgo = "aes"

	// EncryptRSA uses RSA-OAEP asymmetric encryption.
	EncryptRSA EncryptAlgo = "rsa"

	// EncryptEnvelope uses envelope encryption with per-message data keys.
	EncryptEnvelope EncryptAlgo = "envelope"
)

// HashAlgo represents a supported hashing algorithm.
// Use these constants in struct tags: `receive.hash:"argon2"`
type HashAlgo string

const (
	// HashArgon2 uses Argon2id for password hashing (salted, slow).
	HashArgon2 HashAlgo = "argon2"

	// HashBcrypt uses bcrypt for password hashing (salted, slow).
	HashBcrypt HashAlgo = "bcrypt"

	// HashSHA256 uses SHA-256 for deterministic hashing (fast, no salt).
	// Use for fingerprinting/identification, NOT for passwords.
	HashSHA256 HashAlgo = "sha256"

	// HashSHA512 uses SHA-512 for deterministic hashing (fast, no salt).
	// Use for fingerprinting/identification, NOT for passwords.
	HashSHA512 HashAlgo = "sha512"
)

// validEncryptAlgos contains all valid encryption algorithms for tag validation.
var validEncryptAlgos = map[EncryptAlgo]bool{
	EncryptAES:      true,
	EncryptRSA:      true,
	EncryptEnvelope: true,
}

// validHashAlgos contains all valid hash algorithms for tag validation.
var validHashAlgos = map[HashAlgo]bool{
	HashArgon2: true,
	HashBcrypt: true,
	HashSHA256: true,
	HashSHA512: true,
}

// validMaskTypes contains all valid mask types for tag validation.
var validMaskTypes = map[MaskType]bool{
	MaskSSN:   true,
	MaskEmail: true,
	MaskPhone: true,
	MaskCard:  true,
	MaskIP:    true,
	MaskUUID:  true,
	MaskIBAN:  true,
	MaskName:  true,
}

// IsValidEncryptAlgo returns true if the algorithm is a known encryption algorithm.
func IsValidEncryptAlgo(algo EncryptAlgo) bool {
	return validEncryptAlgos[algo]
}

// IsValidHashAlgo returns true if the algorithm is a known hash algorithm.
func IsValidHashAlgo(algo HashAlgo) bool {
	return validHashAlgos[algo]
}

// IsValidMaskType returns true if the type is a known mask type.
func IsValidMaskType(mt MaskType) bool {
	return validMaskTypes[mt]
}
