package cereal

import (
	"fmt"
	"strings"
	"unicode"
)

// MaskType represents a known data format with masking rules.
type MaskType string

// Mask type constants for content-aware masking.
const (
	MaskSSN   MaskType = "ssn"   // 123-45-6789 -> ***-**-6789
	MaskEmail MaskType = "email" // alice@example.com -> a***@example.com
	MaskPhone MaskType = "phone" // (555) 123-4567 -> (***) ***-4567
	MaskCard  MaskType = "card"  // 4111111111111111 -> ************1111
	MaskIP    MaskType = "ip"    // 192.168.1.100 -> 192.168.xxx.xxx
	MaskUUID  MaskType = "uuid"  // 550e8400-e29b-41d4-a716-446655440000 -> 550e8400-****-****-****-************
	MaskIBAN  MaskType = "iban"  // GB82WEST12345698765432 -> GB82************5432
	MaskName  MaskType = "name"  // John Smith -> J*** S****
)

// Masker applies content-aware masking.
type Masker interface {
	// Mask applies masking to the value.
	// Returns an error if the value doesn't match the expected format.
	Mask(value string) (string, error)
}

// ssnMasker masks SSN format: 123-45-6789 -> ***-**-6789
type ssnMasker struct{}

// SSNMasker returns a masker for Social Security Numbers.
// Preserves the last 4 digits, masks everything else.
func SSNMasker() Masker {
	return &ssnMasker{}
}

func (m *ssnMasker) Mask(value string) (string, error) {
	digits := extractDigits(value)
	if len(digits) != 9 {
		return "", fmt.Errorf("%w: SSN requires exactly 9 digits, got %d", ErrMask, len(digits))
	}

	last4 := digits[len(digits)-4:]
	return "***-**-" + last4, nil
}

// emailMasker masks email format: alice@example.com -> a***@example.com
type emailMasker struct{}

// EmailMasker returns a masker for email addresses.
// Preserves first character of local part and full domain.
func EmailMasker() Masker {
	return &emailMasker{}
}

func (m *emailMasker) Mask(value string) (string, error) {
	atIdx := strings.LastIndex(value, "@")
	if atIdx < 1 {
		return "", fmt.Errorf("%w: invalid email format, missing or misplaced @", ErrMask)
	}

	local := value[:atIdx]
	domain := value[atIdx:]

	if len(local) == 1 {
		return local + "***" + domain, nil
	}
	return string(local[0]) + "***" + domain, nil
}

// phoneMasker masks phone format: (555) 123-4567 -> (***) ***-4567
type phoneMasker struct{}

// PhoneMasker returns a masker for phone numbers.
// Preserves the last 4 digits, masks everything else.
func PhoneMasker() Masker {
	return &phoneMasker{}
}

func (m *phoneMasker) Mask(value string) (string, error) {
	digits := extractDigits(value)
	if len(digits) < 7 {
		return "", fmt.Errorf("%w: phone requires at least 7 digits, got %d", ErrMask, len(digits))
	}

	last4 := digits[len(digits)-4:]

	switch {
	case strings.HasPrefix(value, "(") && len(digits) >= 10:
		return "(***) ***-" + last4, nil
	case len(digits) >= 10:
		return "***-***-" + last4, nil
	default:
		return "***-" + last4, nil
	}
}

// cardMasker masks card format: 4111111111111111 -> ************1111
type cardMasker struct{}

// CardMasker returns a masker for credit card numbers.
// Preserves the last 4 digits, masks everything else.
func CardMasker() Masker {
	return &cardMasker{}
}

func (m *cardMasker) Mask(value string) (string, error) {
	digits := extractDigits(value)
	if len(digits) < 13 || len(digits) > 19 {
		return "", fmt.Errorf("%w: card requires 13-19 digits, got %d", ErrMask, len(digits))
	}

	last4 := digits[len(digits)-4:]
	masked := strings.Repeat("*", len(digits)-4)

	if strings.Contains(value, " ") {
		return maskWithSpaces(len(digits), last4), nil
	}

	if strings.Contains(value, "-") {
		return maskWithDashes(len(digits), last4), nil
	}

	return masked + last4, nil
}

// extractDigits returns only the digit characters from a string.
func extractDigits(s string) string {
	var digits strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			digits.WriteRune(r)
		}
	}
	return digits.String()
}

// maskWithSpaces formats masked card with spaces: **** **** **** 1234
func maskWithSpaces(totalDigits int, last4 string) string {
	groups := (totalDigits - 4 + 3) / 4 // Number of masked groups
	masked := make([]string, groups)
	for i := range masked {
		masked[i] = "****"
	}
	return strings.Join(masked, " ") + " " + last4
}

// maskWithDashes formats masked card with dashes: ****-****-****-1234
func maskWithDashes(totalDigits int, last4 string) string {
	groups := (totalDigits - 4 + 3) / 4 // Number of masked groups
	masked := make([]string, groups)
	for i := range masked {
		masked[i] = "****"
	}
	return strings.Join(masked, "-") + "-" + last4
}

// ipMasker masks IP addresses.
// IPv4: 192.168.1.100 -> 192.168.xxx.xxx
// IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334 -> 2001:0db8:85a3:0000:xxxx:xxxx:xxxx:xxxx
type ipMasker struct{}

// IPMasker returns a masker for IP addresses.
// Supports both IPv4 and IPv6.
// IPv4: Preserves first two octets (network), masks last two (host).
// IPv6: Preserves first four groups (network prefix), masks last four (interface ID).
func IPMasker() Masker {
	return &ipMasker{}
}

func (m *ipMasker) Mask(value string) (string, error) {
	// Try IPv4 first
	if parts := strings.Split(value, "."); len(parts) == 4 {
		return parts[0] + "." + parts[1] + ".xxx.xxx", nil
	}

	// Try IPv6
	if strings.Contains(value, ":") {
		masked, ok := maskIPv6(value)
		if !ok {
			return "", fmt.Errorf("%w: invalid IPv6 format", ErrMask)
		}
		return masked, nil
	}

	return "", fmt.Errorf("%w: invalid IP format", ErrMask)
}

// maskIPv6 masks an IPv6 address, preserving the network prefix.
// Returns the masked address and true if valid, or empty string and false if invalid.
func maskIPv6(value string) (string, bool) {
	expanded := expandIPv6(value)
	parts := strings.Split(expanded, ":")

	if len(parts) != 8 {
		return "", false
	}

	return parts[0] + ":" + parts[1] + ":" + parts[2] + ":" + parts[3] +
		":xxxx:xxxx:xxxx:xxxx", true
}

// expandIPv6 expands :: notation to full 8-group form.
func expandIPv6(value string) string {
	// Handle :: expansion
	if strings.Contains(value, "::") {
		parts := strings.Split(value, "::")
		if len(parts) != 2 {
			return value // Multiple ::, invalid
		}

		left := strings.Split(parts[0], ":")
		right := strings.Split(parts[1], ":")

		// Remove empty strings from splits
		if parts[0] == "" {
			left = []string{}
		}
		if parts[1] == "" {
			right = []string{}
		}

		// Calculate how many zero groups to insert
		missing := 8 - len(left) - len(right)
		if missing < 0 {
			return value // Too many groups, invalid
		}

		zeros := make([]string, missing)
		for i := range zeros {
			zeros[i] = "0000"
		}

		all := make([]string, 0, len(left)+len(zeros)+len(right))
		all = append(all, left...)
		all = append(all, zeros...)
		all = append(all, right...)
		return strings.Join(all, ":")
	}

	return value
}

// uuidMasker masks UUIDs: 550e8400-e29b-41d4-a716-446655440000 -> 550e8400-****-****-****-************
type uuidMasker struct{}

// UUIDMasker returns a masker for UUIDs.
// Preserves first segment, masks the rest.
func UUIDMasker() Masker {
	return &uuidMasker{}
}

func (m *uuidMasker) Mask(value string) (string, error) {
	parts := strings.Split(value, "-")
	if len(parts) != 5 {
		return "", fmt.Errorf("%w: UUID requires 5 hyphen-separated segments", ErrMask)
	}

	// Validate segment lengths: 8-4-4-4-12
	expectedLengths := []int{8, 4, 4, 4, 12}
	for i, expected := range expectedLengths {
		if len(parts[i]) != expected {
			return "", fmt.Errorf("%w: UUID segment %d has length %d, expected %d", ErrMask, i+1, len(parts[i]), expected)
		}
	}

	return parts[0] + "-****-****-****-************", nil
}

// ibanMasker masks IBANs: GB82WEST12345698765432 -> GB82************5432
type ibanMasker struct{}

// IBANMasker returns a masker for IBANs.
// Preserves country code + check digits (first 4) and last 4 chars.
func IBANMasker() Masker {
	return &ibanMasker{}
}

func (m *ibanMasker) Mask(value string) (string, error) {
	if len(value) < 15 || len(value) > 34 {
		return "", fmt.Errorf("%w: IBAN requires 15-34 characters, got %d", ErrMask, len(value))
	}

	// First two characters must be letters (country code)
	if len(value) < 2 || !unicode.IsLetter(rune(value[0])) || !unicode.IsLetter(rune(value[1])) {
		return "", fmt.Errorf("%w: IBAN must start with 2-letter country code", ErrMask)
	}

	first4 := value[:4]
	last4 := value[len(value)-4:]
	middle := strings.Repeat("*", len(value)-8)

	return first4 + middle + last4, nil
}

// nameMasker masks names: John Smith -> J*** S***
type nameMasker struct{}

// NameMasker returns a masker for personal names.
// Preserves first letter of each word, masks the rest.
func NameMasker() Masker {
	return &nameMasker{}
}

func (m *nameMasker) Mask(value string) (string, error) {
	words := strings.Fields(value)
	if len(words) == 0 {
		return "", fmt.Errorf("%w: name cannot be empty", ErrMask)
	}

	masked := make([]string, len(words))
	for i, word := range words {
		runes := []rune(word)
		masked[i] = string(runes[0]) + strings.Repeat("*", len(runes)-1)
	}

	return strings.Join(masked, " "), nil
}

// builtinMaskers returns the default masker registry.
func builtinMaskers() map[MaskType]Masker {
	return map[MaskType]Masker{
		MaskSSN:   SSNMasker(),
		MaskEmail: EmailMasker(),
		MaskPhone: PhoneMasker(),
		MaskCard:  CardMasker(),
		MaskIP:    IPMasker(),
		MaskUUID:  UUIDMasker(),
		MaskIBAN:  IBANMasker(),
		MaskName:  NameMasker(),
	}
}
