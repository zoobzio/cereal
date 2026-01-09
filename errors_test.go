package cereal

import (
	"errors"
	"testing"
)

func TestConfigError_Is(t *testing.T) {
	err := newConfigError(ErrMissingEncryptor, "aes", "Email")

	if !errors.Is(err, ErrMissingEncryptor) {
		t.Error("ConfigError should unwrap to ErrMissingEncryptor")
	}

	if errors.Is(err, ErrMissingHasher) {
		t.Error("ConfigError should not match ErrMissingHasher")
	}
}

func TestConfigError_Message(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantPart  string
	}{
		{
			name:     "full context",
			err:      newConfigError(ErrMissingEncryptor, "aes", "Email"),
			wantPart: `missing encryptor for algorithm "aes" (field Email)`,
		},
		{
			name:     "algorithm only",
			err:      &ConfigError{Err: ErrMissingHasher, Algorithm: "argon2"},
			wantPart: `missing hasher for algorithm "argon2"`,
		},
		{
			name:     "field only",
			err:      &ConfigError{Err: ErrInvalidTag, Field: "Password"},
			wantPart: `invalid tag (field Password)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.wantPart {
				t.Errorf("Error() = %q, want %q", got, tt.wantPart)
			}
		})
	}
}

func TestTransformError_Is(t *testing.T) {
	err := newTransformError(ErrEncrypt, "encrypt", "Email", errors.New("key error"))

	if !errors.Is(err, ErrEncrypt) {
		t.Error("TransformError should unwrap to ErrEncrypt")
	}

	if errors.Is(err, ErrDecrypt) {
		t.Error("TransformError should not match ErrDecrypt")
	}
}

func TestTransformError_Message(t *testing.T) {
	cause := errors.New("authentication failed")
	err := newTransformError(ErrDecrypt, "decrypt", "Email", cause)

	want := "decrypt field Email: authentication failed"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestCodecError_Is(t *testing.T) {
	err := newCodecError(ErrUnmarshal, errors.New("invalid json"))

	if !errors.Is(err, ErrUnmarshal) {
		t.Error("CodecError should unwrap to ErrUnmarshal")
	}

	if errors.Is(err, ErrMarshal) {
		t.Error("CodecError should not match ErrMarshal")
	}
}

func TestCodecError_Message(t *testing.T) {
	cause := errors.New("unexpected end of JSON input")
	err := newCodecError(ErrUnmarshal, cause)

	want := "unmarshal failed: unexpected end of JSON input"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestProcessor_Validate_TypedErrors(t *testing.T) {
	proc, _ := NewProcessor[EncryptUser](&testCodec{})

	err := proc.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when encryptor is missing")
	}

	if !errors.Is(err, ErrMissingEncryptor) {
		t.Errorf("Validate() error should be ErrMissingEncryptor, got %T", err)
	}

	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Errorf("Validate() error should be *ConfigError, got %T", err)
	} else {
		if configErr.Algorithm != "aes" {
			t.Errorf("ConfigError.Algorithm = %q, want %q", configErr.Algorithm, "aes")
		}
		if configErr.Field != "Email" {
			t.Errorf("ConfigError.Field = %q, want %q", configErr.Field, "Email")
		}
	}
}

func TestNewProcessor_InvalidTag_TypedError(t *testing.T) {
	_, err := NewProcessor[BadTagUser](&testCodec{})
	if err == nil {
		t.Fatal("NewProcessor() should fail for invalid tag")
	}

	if !errors.Is(err, ErrInvalidTag) {
		t.Errorf("NewProcessor() error should be ErrInvalidTag, got %T", err)
	}

	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Errorf("NewProcessor() error should be *ConfigError, got %T", err)
	}
}

// --- ConfigError edge cases ---

func TestConfigError_ErrOnly(t *testing.T) {
	err := &ConfigError{Err: ErrInvalidTag}

	want := "invalid tag"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestConfigError_Unwrap(t *testing.T) {
	err := &ConfigError{Err: ErrMissingEncryptor, Algorithm: "aes", Field: "Email"}

	unwrapped := err.Unwrap()
	if unwrapped != ErrMissingEncryptor {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, ErrMissingEncryptor)
	}
}

// --- TransformError edge cases ---

func TestTransformError_NoCause(t *testing.T) {
	err := &TransformError{Err: ErrEncrypt, Field: "Email", Operation: "encrypt"}

	want := "encrypt field Email"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestTransformError_Unwrap(t *testing.T) {
	err := &TransformError{Err: ErrDecrypt, Field: "Email", Operation: "decrypt", Cause: errors.New("key error")}

	unwrapped := err.Unwrap()
	if unwrapped != ErrDecrypt {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, ErrDecrypt)
	}
}

// --- CodecError edge cases ---

func TestCodecError_NoCause(t *testing.T) {
	err := &CodecError{Err: ErrMarshal}

	want := "marshal failed"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestCodecError_Unwrap(t *testing.T) {
	err := &CodecError{Err: ErrUnmarshal, Cause: errors.New("invalid json")}

	unwrapped := err.Unwrap()
	if unwrapped != ErrUnmarshal {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, ErrUnmarshal)
	}
}

// --- errors.As extraction tests ---

func TestErrorsAs_ConfigError(t *testing.T) {
	err := newConfigError(ErrMissingHasher, "argon2", "Password")

	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Fatal("errors.As should extract *ConfigError")
	}

	if configErr.Algorithm != "argon2" {
		t.Errorf("Algorithm = %q, want %q", configErr.Algorithm, "argon2")
	}
	if configErr.Field != "Password" {
		t.Errorf("Field = %q, want %q", configErr.Field, "Password")
	}
}

func TestErrorsAs_TransformError(t *testing.T) {
	err := newTransformError(ErrHash, "hash", "Token", errors.New("hash failed"))

	var transformErr *TransformError
	if !errors.As(err, &transformErr) {
		t.Fatal("errors.As should extract *TransformError")
	}

	if transformErr.Field != "Token" {
		t.Errorf("Field = %q, want %q", transformErr.Field, "Token")
	}
	if transformErr.Operation != "hash" {
		t.Errorf("Operation = %q, want %q", transformErr.Operation, "hash")
	}
}

func TestErrorsAs_CodecError(t *testing.T) {
	err := newCodecError(ErrMarshal, errors.New("encoding error"))

	var codecErr *CodecError
	if !errors.As(err, &codecErr) {
		t.Fatal("errors.As should extract *CodecError")
	}

	if codecErr.Err != ErrMarshal {
		t.Errorf("Err = %v, want %v", codecErr.Err, ErrMarshal)
	}
}
