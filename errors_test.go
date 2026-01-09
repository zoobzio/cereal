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
