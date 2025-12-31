package codec

import (
	"testing"
)

func TestSSNMasker(t *testing.T) {
	m := SSNMasker()

	tests := []struct {
		input    string
		expected string
	}{
		{"123-45-6789", "***-**-6789"},
		{"123456789", "***-**-6789"},
		{"12-34-5678", "***-**-5678"},
		{"123", "***"}, // Too short
	}

	for _, tt := range tests {
		result := m.Mask(tt.input)
		if result != tt.expected {
			t.Errorf("SSNMasker(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestEmailMasker(t *testing.T) {
	m := EmailMasker()

	tests := []struct {
		input    string
		expected string
	}{
		{"alice@example.com", "a***@example.com"},
		{"bob@test.org", "b***@test.org"},
		{"a@b.com", "a***@b.com"},
		{"noatsign", "********"}, // No @
	}

	for _, tt := range tests {
		result := m.Mask(tt.input)
		if result != tt.expected {
			t.Errorf("EmailMasker(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestPhoneMasker(t *testing.T) {
	m := PhoneMasker()

	tests := []struct {
		input    string
		expected string
	}{
		{"(555) 123-4567", "(***) ***-4567"},
		{"555-123-4567", "***-***-4567"},
		{"5551234567", "***-***-4567"},
		{"123", "***"}, // Too short
	}

	for _, tt := range tests {
		result := m.Mask(tt.input)
		if result != tt.expected {
			t.Errorf("PhoneMasker(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestCardMasker(t *testing.T) {
	m := CardMasker()

	tests := []struct {
		input    string
		expected string
	}{
		{"4111111111111111", "************1111"},
		{"4111 1111 1111 1111", "**** **** **** 1111"},
		{"4111-1111-1111-1111", "****-****-****-1111"},
		{"123", "***"}, // Too short
	}

	for _, tt := range tests {
		result := m.Mask(tt.input)
		if result != tt.expected {
			t.Errorf("CardMasker(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestIPMasker(t *testing.T) {
	m := IPMasker()

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
		// Invalid
		{"invalid", "*******"},
	}

	for _, tt := range tests {
		result := m.Mask(tt.input)
		if result != tt.expected {
			t.Errorf("IPMasker(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestUUIDMasker(t *testing.T) {
	m := UUIDMasker()

	tests := []struct {
		input    string
		expected string
	}{
		{"550e8400-e29b-41d4-a716-446655440000", "550e8400-****-****-****-************"},
		{"12345678-1234-1234-1234-123456789012", "12345678-****-****-****-************"},
		{"invalid", "*******"}, // Not UUID format
	}

	for _, tt := range tests {
		result := m.Mask(tt.input)
		if result != tt.expected {
			t.Errorf("UUIDMasker(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestIBANMasker(t *testing.T) {
	m := IBANMasker()

	tests := []struct {
		input    string
		expected string
	}{
		{"GB82WEST12345698765432", "GB82**************5432"},
		{"DE89370400440532013000", "DE89**************3000"},
		{"SHORT", "*****"}, // Too short
	}

	for _, tt := range tests {
		result := m.Mask(tt.input)
		if result != tt.expected {
			t.Errorf("IBANMasker(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestNameMasker(t *testing.T) {
	m := NameMasker()

	tests := []struct {
		input    string
		expected string
	}{
		{"John Smith", "J*** S****"},
		{"Alice", "A****"},
		{"Bob Jones Jr", "B** J**** J*"},
	}

	for _, tt := range tests {
		result := m.Mask(tt.input)
		if result != tt.expected {
			t.Errorf("NameMasker(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
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
