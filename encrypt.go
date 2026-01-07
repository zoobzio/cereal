package cereal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// Encryption errors.
var (
	ErrInvalidKeySize   = errors.New("invalid key size")
	ErrCiphertextShort  = errors.New("ciphertext too short")
	ErrDecryptionFailed = errors.New("decryption failed")
)

// Encryptor handles encryption/decryption operations.
type Encryptor interface {
	// Encrypt encrypts plaintext and returns ciphertext.
	Encrypt(plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext and returns plaintext.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// aesEncryptor implements AES-GCM encryption.
type aesEncryptor struct {
	gcm cipher.AEAD
}

// AES returns an AES-GCM encryptor.
// Key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.
func AES(key []byte) (Encryptor, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("%w: must be 16, 24, or 32 bytes, got %d", ErrInvalidKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &aesEncryptor{gcm: gcm}, nil
}

func (e *aesEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Prepend nonce to ciphertext
	return e.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *aesEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := e.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCiphertextShort
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// rsaEncryptor implements RSA-OAEP encryption.
type rsaEncryptor struct {
	pub  *rsa.PublicKey
	priv *rsa.PrivateKey
}

// RSA returns an RSA-OAEP encryptor.
// pub is required for encryption; priv is required for decryption.
// Either can be nil if only one operation is needed.
func RSA(pub *rsa.PublicKey, priv *rsa.PrivateKey) Encryptor {
	return &rsaEncryptor{pub: pub, priv: priv}
}

func (e *rsaEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	if e.pub == nil {
		return nil, errors.New("public key required for encryption")
	}

	return rsa.EncryptOAEP(sha256.New(), rand.Reader, e.pub, plaintext, nil)
}

func (e *rsaEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if e.priv == nil {
		return nil, errors.New("private key required for decryption")
	}

	return rsa.DecryptOAEP(sha256.New(), rand.Reader, e.priv, ciphertext, nil)
}

// envelopeEncryptor implements envelope encryption.
// A random data key is generated per operation, encrypted with the master key,
// and prepended to the ciphertext.
type envelopeEncryptor struct {
	masterGCM   cipher.AEAD
	dataKeySize int
}

// Envelope returns an envelope encryptor using a master key.
// Master key must be 16, 24, or 32 bytes.
func Envelope(masterKey []byte) (Encryptor, error) {
	if len(masterKey) != 16 && len(masterKey) != 24 && len(masterKey) != 32 {
		return nil, fmt.Errorf("%w: must be 16, 24, or 32 bytes, got %d", ErrInvalidKeySize, len(masterKey))
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &envelopeEncryptor{
		masterGCM:   gcm,
		dataKeySize: 32, // AES-256 data keys
	}, nil
}

func (e *envelopeEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	// Generate random data key
	dataKey := make([]byte, e.dataKeySize)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return nil, err
	}

	// Encrypt plaintext with data key
	dataBlock, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}

	dataGCM, err := cipher.NewGCM(dataBlock)
	if err != nil {
		return nil, err
	}

	dataNonce := make([]byte, dataGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, dataNonce); err != nil {
		return nil, err
	}

	encryptedData := dataGCM.Seal(dataNonce, dataNonce, plaintext, nil)

	// Encrypt data key with master key
	masterNonce := make([]byte, e.masterGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, masterNonce); err != nil {
		return nil, err
	}

	encryptedKey := e.masterGCM.Seal(masterNonce, masterNonce, dataKey, nil)

	// Format: [2 bytes key len][encrypted key][encrypted data]
	if len(encryptedKey) > 65535 {
		return nil, errors.New("encrypted key exceeds maximum length")
	}
	keyLen := uint16(len(encryptedKey)) // #nosec G115 -- bounds checked above
	result := make([]byte, 2+len(encryptedKey)+len(encryptedData))
	result[0] = byte(keyLen >> 8)
	result[1] = byte(keyLen)
	copy(result[2:], encryptedKey)
	copy(result[2+len(encryptedKey):], encryptedData)

	return result, nil
}

func (e *envelopeEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 2 {
		return nil, ErrCiphertextShort
	}

	// Parse key length
	keyLen := int(uint16(ciphertext[0])<<8 | uint16(ciphertext[1]))
	if len(ciphertext) < 2+keyLen {
		return nil, ErrCiphertextShort
	}

	encryptedKey := ciphertext[2 : 2+keyLen]
	encryptedData := ciphertext[2+keyLen:]

	// Decrypt data key with master key
	masterNonceSize := e.masterGCM.NonceSize()
	if len(encryptedKey) < masterNonceSize {
		return nil, ErrCiphertextShort
	}

	masterNonce := encryptedKey[:masterNonceSize]
	encryptedKey = encryptedKey[masterNonceSize:]

	dataKey, err := e.masterGCM.Open(nil, masterNonce, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decrypt data key: %w", ErrDecryptionFailed, err)
	}

	// Decrypt data with data key
	dataBlock, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}

	dataGCM, err := cipher.NewGCM(dataBlock)
	if err != nil {
		return nil, err
	}

	dataNonceSize := dataGCM.NonceSize()
	if len(encryptedData) < dataNonceSize {
		return nil, ErrCiphertextShort
	}

	dataNonce := encryptedData[:dataNonceSize]
	encryptedData = encryptedData[dataNonceSize:]

	plaintext, err := dataGCM.Open(nil, dataNonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decrypt data: %w", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}
