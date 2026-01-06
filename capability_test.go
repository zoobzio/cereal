package codec

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
