package cereal

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Hasher performs one-way hashing.
type Hasher interface {
	// Hash returns the hash of plaintext as a string.
	// For password hashers (argon2, bcrypt), the result includes salt and parameters.
	// For deterministic hashers (sha256, sha512), the result is a hex-encoded hash.
	Hash(plaintext []byte) (string, error)
}

// Argon2Params configures Argon2id hashing.
type Argon2Params struct {
	Time    uint32 // Number of iterations
	Memory  uint32 // Memory usage in KiB
	Threads uint8  // Parallelism factor
	KeyLen  uint32 // Output key length
	SaltLen uint32 // Salt length
}

// DefaultArgon2Params returns recommended Argon2id parameters.
// Based on OWASP recommendations for password hashing.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Time:    1,
		Memory:  64 * 1024, // 64 MiB
		Threads: 4,
		KeyLen:  32,
		SaltLen: 16,
	}
}

// argon2Hasher implements Argon2id password hashing.
type argon2Hasher struct {
	params Argon2Params
}

// Argon2 returns an Argon2id hasher with default parameters.
func Argon2() Hasher {
	return Argon2WithParams(DefaultArgon2Params())
}

// Argon2WithParams returns an Argon2id hasher with custom parameters.
func Argon2WithParams(params Argon2Params) Hasher {
	return &argon2Hasher{params: params}
}

func (h *argon2Hasher) Hash(plaintext []byte) (string, error) {
	// Generate random salt
	salt := make([]byte, h.params.SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash with Argon2id
	hash := argon2.IDKey(plaintext, salt, h.params.Time, h.params.Memory, h.params.Threads, h.params.KeyLen)

	// Encode as: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
	// Using base64 encoding for salt and hash
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.params.Memory,
		h.params.Time,
		h.params.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encoded, nil
}

// BcryptCost represents the bcrypt cost factor.
type BcryptCost int

// Bcrypt cost constants.
const (
	BcryptMinCost     BcryptCost = BcryptCost(bcrypt.MinCost)
	BcryptDefaultCost BcryptCost = BcryptCost(bcrypt.DefaultCost)
	BcryptMaxCost     BcryptCost = BcryptCost(bcrypt.MaxCost)
)

// bcryptHasher implements bcrypt password hashing.
type bcryptHasher struct {
	cost int
}

// Bcrypt returns a bcrypt hasher with default cost.
func Bcrypt() Hasher {
	return BcryptWithCost(BcryptDefaultCost)
}

// BcryptWithCost returns a bcrypt hasher with a specific cost factor.
func BcryptWithCost(cost BcryptCost) Hasher {
	return &bcryptHasher{cost: int(cost)}
}

func (h *bcryptHasher) Hash(plaintext []byte) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(plaintext, h.cost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash failed: %w", err)
	}
	return string(hash), nil
}

// sha256Hasher implements SHA-256 hashing.
// Use for fingerprinting/identification, NOT for passwords.
type sha256Hasher struct{}

// SHA256Hasher returns a SHA-256 hasher.
// The result is a hex-encoded 64-character string.
// Use for fingerprinting/identification, NOT for passwords.
func SHA256Hasher() Hasher {
	return &sha256Hasher{}
}

func (h *sha256Hasher) Hash(plaintext []byte) (string, error) {
	sum := sha256.Sum256(plaintext)
	return hex.EncodeToString(sum[:]), nil
}

// sha512Hasher implements SHA-512 hashing.
// Use for fingerprinting/identification, NOT for passwords.
type sha512Hasher struct{}

// SHA512Hasher returns a SHA-512 hasher.
// The result is a hex-encoded 128-character string.
// Use for fingerprinting/identification, NOT for passwords.
func SHA512Hasher() Hasher {
	return &sha512Hasher{}
}

func (h *sha512Hasher) Hash(plaintext []byte) (string, error) {
	sum := sha512.Sum512(plaintext)
	return hex.EncodeToString(sum[:]), nil
}

// builtinHashers returns the default hasher registry.
func builtinHashers() map[HashAlgo]Hasher {
	return map[HashAlgo]Hasher{
		HashArgon2: Argon2(),
		HashBcrypt: Bcrypt(),
		HashSHA256: SHA256Hasher(),
		HashSHA512: SHA512Hasher(),
	}
}
