package cereal

import (
	"errors"
	"testing"
)

func TestSSNMasker(t *testing.T) {
	m := SSNMasker()

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"123-45-6789", "***-**-6789"},
			{"123456789", "***-**-6789"},
			{"123 45 6789", "***-**-6789"},
		}

		for _, tt := range tests {
			result, err := m.Mask(tt.input)
			if err != nil {
				t.Errorf("SSNMasker(%q) unexpected error: %v", tt.input, err)
				continue
			}
			if result != tt.expected {
				t.Errorf("SSNMasker(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []string{
			"123",        // Too few digits
			"12345678",   // 8 digits
			"1234567890", // 10 digits
			"",           // Empty
		}

		for _, input := range tests {
			_, err := m.Mask(input)
			if err == nil {
				t.Errorf("SSNMasker(%q) expected error, got nil", input)
				continue
			}
			if !errors.Is(err, ErrMask) {
				t.Errorf("SSNMasker(%q) error = %v, want ErrMask", input, err)
			}
		}
	})
}

func TestEmailMasker(t *testing.T) {
	m := EmailMasker()

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"alice@example.com", "a***@example.com"},
			{"bob@test.org", "b***@test.org"},
			{"a@b.com", "a***@b.com"},
		}

		for _, tt := range tests {
			result, err := m.Mask(tt.input)
			if err != nil {
				t.Errorf("EmailMasker(%q) unexpected error: %v", tt.input, err)
				continue
			}
			if result != tt.expected {
				t.Errorf("EmailMasker(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []string{
			"noatsign",   // No @
			"@domain",    // @ at start
			"",           // Empty
		}

		for _, input := range tests {
			_, err := m.Mask(input)
			if err == nil {
				t.Errorf("EmailMasker(%q) expected error, got nil", input)
				continue
			}
			if !errors.Is(err, ErrMask) {
				t.Errorf("EmailMasker(%q) error = %v, want ErrMask", input, err)
			}
		}
	})
}

func TestPhoneMasker(t *testing.T) {
	m := PhoneMasker()

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"(555) 123-4567", "(***) ***-4567"},
			{"555-123-4567", "***-***-4567"},
			{"5551234567", "***-***-4567"},
			{"1234567", "***-4567"}, // 7 digits minimum
		}

		for _, tt := range tests {
			result, err := m.Mask(tt.input)
			if err != nil {
				t.Errorf("PhoneMasker(%q) unexpected error: %v", tt.input, err)
				continue
			}
			if result != tt.expected {
				t.Errorf("PhoneMasker(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []string{
			"123456", // 6 digits
			"123",    // Too short
			"",       // Empty
		}

		for _, input := range tests {
			_, err := m.Mask(input)
			if err == nil {
				t.Errorf("PhoneMasker(%q) expected error, got nil", input)
				continue
			}
			if !errors.Is(err, ErrMask) {
				t.Errorf("PhoneMasker(%q) error = %v, want ErrMask", input, err)
			}
		}
	})
}

func TestCardMasker(t *testing.T) {
	m := CardMasker()

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"4111111111111111", "************1111"},           // 16 digits
			{"4111 1111 1111 1111", "**** **** **** 1111"},     // Spaced
			{"4111-1111-1111-1111", "****-****-****-1111"},     // Dashed
			{"4111111111111", "*********1111"},                 // 13 digits (min)
			{"4111111111111111111", "***************1111"},     // 19 digits (max)
		}

		for _, tt := range tests {
			result, err := m.Mask(tt.input)
			if err != nil {
				t.Errorf("CardMasker(%q) unexpected error: %v", tt.input, err)
				continue
			}
			if result != tt.expected {
				t.Errorf("CardMasker(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []string{
			"123456789012",                 // 12 digits (too few)
			"12345678901234567890",         // 20 digits (too many)
			"123",                          // Way too short
			"",                             // Empty
		}

		for _, input := range tests {
			_, err := m.Mask(input)
			if err == nil {
				t.Errorf("CardMasker(%q) expected error, got nil", input)
				continue
			}
			if !errors.Is(err, ErrMask) {
				t.Errorf("CardMasker(%q) error = %v, want ErrMask", input, err)
			}
		}
	})
}

func TestIPMasker(t *testing.T) {
	m := IPMasker()

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			// IPv4
			{"192.168.1.100", "192.168.xxx.xxx"},
			{"10.0.0.1", "10.0.xxx.xxx"},
			// IPv6 full form
			{"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:0db8:85a3:0000:xxxx:xxxx:xxxx:xxxx"},
			// IPv6 compressed
			{"2001:db8:85a3::8a2e:370:7334", "2001:db8:85a3:0000:xxxx:xxxx:xxxx:xxxx"},
			// IPv6 loopback
			{"::1", "0000:0000:0000:0000:xxxx:xxxx:xxxx:xxxx"},
			// IPv6 all zeros
			{"::", "0000:0000:0000:0000:xxxx:xxxx:xxxx:xxxx"},
		}

		for _, tt := range tests {
			result, err := m.Mask(tt.input)
			if err != nil {
				t.Errorf("IPMasker(%q) unexpected error: %v", tt.input, err)
				continue
			}
			if result != tt.expected {
				t.Errorf("IPMasker(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []string{
			"invalid",      // Not an IP
			"192.168.1",    // Incomplete IPv4
			"",             // Empty
		}

		for _, input := range tests {
			_, err := m.Mask(input)
			if err == nil {
				t.Errorf("IPMasker(%q) expected error, got nil", input)
				continue
			}
			if !errors.Is(err, ErrMask) {
				t.Errorf("IPMasker(%q) error = %v, want ErrMask", input, err)
			}
		}
	})
}

func TestUUIDMasker(t *testing.T) {
	m := UUIDMasker()

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"550e8400-e29b-41d4-a716-446655440000", "550e8400-****-****-****-************"},
			{"12345678-1234-1234-1234-123456789012", "12345678-****-****-****-************"},
		}

		for _, tt := range tests {
			result, err := m.Mask(tt.input)
			if err != nil {
				t.Errorf("UUIDMasker(%q) unexpected error: %v", tt.input, err)
				continue
			}
			if result != tt.expected {
				t.Errorf("UUIDMasker(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []string{
			"invalid",     // Not UUID format
			"a-b-c-d-e",   // Wrong segment lengths
			"",            // Empty
		}

		for _, input := range tests {
			_, err := m.Mask(input)
			if err == nil {
				t.Errorf("UUIDMasker(%q) expected error, got nil", input)
				continue
			}
			if !errors.Is(err, ErrMask) {
				t.Errorf("UUIDMasker(%q) error = %v, want ErrMask", input, err)
			}
		}
	})
}

func TestIBANMasker(t *testing.T) {
	m := IBANMasker()

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"GB82WEST12345698765432", "GB82**************5432"},
			{"DE89370400440532013000", "DE89**************3000"},
			{"NO9386011117947", "NO93*******7947"}, // 15 chars (min)
		}

		for _, tt := range tests {
			result, err := m.Mask(tt.input)
			if err != nil {
				t.Errorf("IBANMasker(%q) unexpected error: %v", tt.input, err)
				continue
			}
			if result != tt.expected {
				t.Errorf("IBANMasker(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []string{
			"SHORT",           // Too short
			"12345678901234",  // 14 chars (too few)
			"1234567890123456789012345678901234567890", // 40 chars (too many)
			"12GB12345678901234", // Doesn't start with letters
			"",                // Empty
		}

		for _, input := range tests {
			_, err := m.Mask(input)
			if err == nil {
				t.Errorf("IBANMasker(%q) expected error, got nil", input)
				continue
			}
			if !errors.Is(err, ErrMask) {
				t.Errorf("IBANMasker(%q) error = %v, want ErrMask", input, err)
			}
		}
	})
}

func TestNameMasker(t *testing.T) {
	m := NameMasker()

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"John Smith", "J*** S****"},
			{"Alice", "A****"},
			{"Bob Jones Jr", "B** J**** J*"},
		}

		for _, tt := range tests {
			result, err := m.Mask(tt.input)
			if err != nil {
				t.Errorf("NameMasker(%q) unexpected error: %v", tt.input, err)
				continue
			}
			if result != tt.expected {
				t.Errorf("NameMasker(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []string{
			"",    // Empty
			"   ", // Whitespace only
		}

		for _, input := range tests {
			_, err := m.Mask(input)
			if err == nil {
				t.Errorf("NameMasker(%q) expected error, got nil", input)
				continue
			}
			if !errors.Is(err, ErrMask) {
				t.Errorf("NameMasker(%q) error = %v, want ErrMask", input, err)
			}
		}
	})
}

func TestBuiltinMaskers(t *testing.T) {
	maskers := builtinMaskers()

	expectedTypes := []MaskType{
		MaskSSN, MaskEmail, MaskPhone, MaskCard,
		MaskIP, MaskUUID, MaskIBAN, MaskName,
	}

	for _, mt := range expectedTypes {
		if _, ok := maskers[mt]; !ok {
			t.Errorf("builtinMaskers missing %q", mt)
		}
	}
}
