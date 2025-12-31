package codec

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestAES_RoundTrip(t *testing.T) {
	key := []byte("32-byte-key-for-aes-256-encrypt!")
	enc, err := AES(key)
	if err != nil {
		t.Fatalf("AES() error: %v", err)
	}

	plaintext := []byte("hello, world!")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestAES_InvalidKeySize(t *testing.T) {
	_, err := AES([]byte("short"))
	if err == nil {
		t.Error("expected error for invalid key size")
	}
}

func TestAES_DifferentNonce(t *testing.T) {
	key := []byte("32-byte-key-for-aes-256-encrypt!")
	enc, _ := AES(key)

	plaintext := []byte("hello")
	c1, _ := enc.Encrypt(plaintext)
	c2, _ := enc.Encrypt(plaintext)

	if bytes.Equal(c1, c2) {
		t.Error("same plaintext should produce different ciphertext (random nonce)")
	}
}

func TestRSA_RoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	enc := RSA(&priv.PublicKey, priv)

	plaintext := []byte("hello, world!")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestRSA_EncryptWithoutPublicKey(t *testing.T) {
	enc := RSA(nil, nil)
	_, err := enc.Encrypt([]byte("test"))
	if err == nil {
		t.Error("expected error when encrypting without public key")
	}
}

func TestRSA_DecryptWithoutPrivateKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	enc := RSA(&priv.PublicKey, nil)

	ciphertext, _ := enc.Encrypt([]byte("test"))
	_, err := enc.Decrypt(ciphertext)
	if err == nil {
		t.Error("expected error when decrypting without private key")
	}
}

func TestEnvelope_RoundTrip(t *testing.T) {
	masterKey := []byte("32-byte-master-key-for-envelope!")
	enc, err := Envelope(masterKey)
	if err != nil {
		t.Fatalf("Envelope() error: %v", err)
	}

	plaintext := []byte("hello, world!")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEnvelope_InvalidKeySize(t *testing.T) {
	_, err := Envelope([]byte("short"))
	if err == nil {
		t.Error("expected error for invalid key size")
	}
}

func TestEnvelope_DifferentDataKeys(t *testing.T) {
	masterKey := []byte("32-byte-master-key-for-envelope!")
	enc, _ := Envelope(masterKey)

	plaintext := []byte("hello")
	c1, _ := enc.Encrypt(plaintext)
	c2, _ := enc.Encrypt(plaintext)

	if bytes.Equal(c1, c2) {
		t.Error("same plaintext should produce different ciphertext (random data key)")
	}
}
