package cereal

import (
	"errors"
	"fmt"
)

// Sentinel errors for programmatic error handling.
// Use errors.Is() to check for these error types.
var (
	// ErrMissingEncryptor indicates a required encryptor was not registered.
	ErrMissingEncryptor = errors.New("missing encryptor")

	// ErrMissingHasher indicates a required hasher was not registered.
	ErrMissingHasher = errors.New("missing hasher")

	// ErrMissingMasker indicates a required masker was not registered.
	ErrMissingMasker = errors.New("missing masker")

	// ErrInvalidTag indicates a struct tag has an invalid format or value.
	ErrInvalidTag = errors.New("invalid tag")

	// ErrUnmarshal indicates the codec failed to unmarshal input data.
	ErrUnmarshal = errors.New("unmarshal failed")

	// ErrMarshal indicates the codec failed to marshal output data.
	ErrMarshal = errors.New("marshal failed")

	// ErrEncrypt indicates encryption of a field failed.
	ErrEncrypt = errors.New("encrypt failed")

	// ErrDecrypt indicates decryption of a field failed.
	ErrDecrypt = errors.New("decrypt failed")

	// ErrHash indicates hashing of a field failed.
	ErrHash = errors.New("hash failed")

	// ErrMask indicates masking of a field failed.
	ErrMask = errors.New("mask failed")

	// ErrRedact indicates redaction of a field failed.
	ErrRedact = errors.New("redact failed")

	// ErrInvalidKey indicates an encryption key has invalid size or format.
	ErrInvalidKey = errors.New("invalid key")
)

// ConfigError represents a processor configuration error.
// It wraps a sentinel error with additional context about the field and algorithm.
type ConfigError struct {
	Err       error  // Underlying sentinel error (ErrMissingEncryptor, etc.)
	Field     string // Field name that triggered the error
	Algorithm string // Algorithm or type that was missing/invalid
}

func (e *ConfigError) Error() string {
	if e.Field != "" && e.Algorithm != "" {
		return fmt.Sprintf("%s for algorithm %q (field %s)", e.Err.Error(), e.Algorithm, e.Field)
	}
	if e.Algorithm != "" {
		return fmt.Sprintf("%s for algorithm %q", e.Err.Error(), e.Algorithm)
	}
	if e.Field != "" {
		return fmt.Sprintf("%s (field %s)", e.Err.Error(), e.Field)
	}
	return e.Err.Error()
}

func (e *ConfigError) Unwrap() error {
	return e.Err
}

// TransformError represents an error during field transformation.
// It wraps a sentinel error with context about which field and operation failed.
type TransformError struct {
	Err       error  // Underlying sentinel error (ErrEncrypt, ErrDecrypt, etc.)
	Field     string // Field name that failed
	Operation string // Operation that failed (encrypt, decrypt, hash, mask, redact)
	Cause     error  // Original error from the underlying operation
}

func (e *TransformError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s field %s: %v", e.Operation, e.Field, e.Cause)
	}
	return fmt.Sprintf("%s field %s", e.Operation, e.Field)
}

func (e *TransformError) Unwrap() error {
	return e.Err
}

// CodecError represents a marshal/unmarshal error.
type CodecError struct {
	Err   error // Underlying sentinel error (ErrMarshal, ErrUnmarshal)
	Cause error // Original error from the codec
}

func (e *CodecError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Err.Error(), e.Cause)
	}
	return e.Err.Error()
}

func (e *CodecError) Unwrap() error {
	return e.Err
}

// newConfigError creates a ConfigError for missing handler scenarios.
func newConfigError(sentinel error, algorithm, field string) error {
	return &ConfigError{
		Err:       sentinel,
		Algorithm: algorithm,
		Field:     field,
	}
}

// newTransformError creates a TransformError for field transformation failures.
func newTransformError(sentinel error, operation, field string, cause error) error {
	return &TransformError{
		Err:       sentinel,
		Field:     field,
		Operation: operation,
		Cause:     cause,
	}
}

// newCodecError creates a CodecError for marshal/unmarshal failures.
func newCodecError(sentinel error, cause error) error {
	return &CodecError{
		Err:   sentinel,
		Cause: cause,
	}
}
