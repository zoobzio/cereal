package cereal

import "testing"

func TestIsValidEncryptAlgo(t *testing.T) {
	tests := []struct {
		algo EncryptAlgo
		want bool
	}{
		{EncryptAES, true},
		{EncryptRSA, true},
		{EncryptEnvelope, true},
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			if got := IsValidEncryptAlgo(tt.algo); got != tt.want {
				t.Errorf("IsValidEncryptAlgo(%q) = %v, want %v", tt.algo, got, tt.want)
			}
		})
	}
}

func TestIsValidHashAlgo(t *testing.T) {
	tests := []struct {
		algo HashAlgo
		want bool
	}{
		{HashArgon2, true},
		{HashBcrypt, true},
		{HashSHA256, true},
		{HashSHA512, true},
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			if got := IsValidHashAlgo(tt.algo); got != tt.want {
				t.Errorf("IsValidHashAlgo(%q) = %v, want %v", tt.algo, got, tt.want)
			}
		})
	}
}

func TestIsValidMaskType(t *testing.T) {
	tests := []struct {
		mt   MaskType
		want bool
	}{
		{MaskSSN, true},
		{MaskEmail, true},
		{MaskPhone, true},
		{MaskCard, true},
		{MaskIP, true},
		{MaskUUID, true},
		{MaskIBAN, true},
		{MaskName, true},
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mt), func(t *testing.T) {
			if got := IsValidMaskType(tt.mt); got != tt.want {
				t.Errorf("IsValidMaskType(%q) = %v, want %v", tt.mt, got, tt.want)
			}
		})
	}
}

// --- Case sensitivity tests ---

func TestIsValidEncryptAlgo_CaseSensitive(t *testing.T) {
	tests := []struct {
		algo EncryptAlgo
		want bool
	}{
		{"AES", false},
		{"Aes", false},
		{"RSA", false},
		{"Rsa", false},
		{"ENVELOPE", false},
		{"Envelope", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			if got := IsValidEncryptAlgo(tt.algo); got != tt.want {
				t.Errorf("IsValidEncryptAlgo(%q) = %v, want %v", tt.algo, got, tt.want)
			}
		})
	}
}

func TestIsValidHashAlgo_CaseSensitive(t *testing.T) {
	tests := []struct {
		algo HashAlgo
		want bool
	}{
		{"ARGON2", false},
		{"Argon2", false},
		{"BCRYPT", false},
		{"Bcrypt", false},
		{"SHA256", false},
		{"Sha256", false},
		{"SHA512", false},
		{"Sha512", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			if got := IsValidHashAlgo(tt.algo); got != tt.want {
				t.Errorf("IsValidHashAlgo(%q) = %v, want %v", tt.algo, got, tt.want)
			}
		})
	}
}

func TestIsValidMaskType_CaseSensitive(t *testing.T) {
	tests := []struct {
		mt   MaskType
		want bool
	}{
		{"SSN", false},
		{"Ssn", false},
		{"EMAIL", false},
		{"Email", false},
		{"PHONE", false},
		{"Phone", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mt), func(t *testing.T) {
			if got := IsValidMaskType(tt.mt); got != tt.want {
				t.Errorf("IsValidMaskType(%q) = %v, want %v", tt.mt, got, tt.want)
			}
		})
	}
}

// --- Whitespace tests ---

func TestIsValidEncryptAlgo_Whitespace(t *testing.T) {
	tests := []struct {
		algo EncryptAlgo
		want bool
	}{
		{" aes", false},
		{"aes ", false},
		{" aes ", false},
		{"\taes", false},
		{"aes\n", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			if got := IsValidEncryptAlgo(tt.algo); got != tt.want {
				t.Errorf("IsValidEncryptAlgo(%q) = %v, want %v", tt.algo, got, tt.want)
			}
		})
	}
}

func TestIsValidHashAlgo_Whitespace(t *testing.T) {
	tests := []struct {
		algo HashAlgo
		want bool
	}{
		{" sha256", false},
		{"sha256 ", false},
		{" sha256 ", false},
		{"\tsha256", false},
		{"sha256\n", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			if got := IsValidHashAlgo(tt.algo); got != tt.want {
				t.Errorf("IsValidHashAlgo(%q) = %v, want %v", tt.algo, got, tt.want)
			}
		})
	}
}

func TestIsValidMaskType_Whitespace(t *testing.T) {
	tests := []struct {
		mt   MaskType
		want bool
	}{
		{" ssn", false},
		{"ssn ", false},
		{" ssn ", false},
		{"\tssn", false},
		{"ssn\n", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mt), func(t *testing.T) {
			if got := IsValidMaskType(tt.mt); got != tt.want {
				t.Errorf("IsValidMaskType(%q) = %v, want %v", tt.mt, got, tt.want)
			}
		})
	}
}
