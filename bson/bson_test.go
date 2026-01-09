package bson

import (
	"testing"
)

func TestNew(t *testing.T) {
	c := New()
	if c == nil {
		t.Error("New() should return non-nil codec")
	}
}

func TestContentType(t *testing.T) {
	c := New()
	if c.ContentType() != "application/bson" {
		t.Errorf("ContentType() = %q, want %q", c.ContentType(), "application/bson")
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	c := New()

	type TestStruct struct {
		Name  string `bson:"name"`
		Value int    `bson:"value"`
	}

	original := TestStruct{Name: "test", Value: 42}

	data, err := c.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	var restored TestStruct
	if err := c.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if restored.Name != original.Name || restored.Value != original.Value {
		t.Errorf("round-trip failed: got %+v, want %+v", restored, original)
	}
}

func TestUnmarshalInvalid(t *testing.T) {
	c := New()

	var v struct{}
	err := c.Unmarshal([]byte("invalid bson"), &v)
	if err == nil {
		t.Error("Unmarshal(invalid) should return error")
	}
}

func TestMarshalNil(t *testing.T) {
	c := New()

	// BSON cannot marshal nil directly (unlike JSON)
	_, err := c.Marshal(nil)
	if err == nil {
		t.Error("Marshal(nil) should return error for BSON")
	}
}

func TestMarshalEmptyStruct(t *testing.T) {
	c := New()

	data, err := c.Marshal(struct{}{})
	if err != nil {
		t.Fatalf("Marshal(empty struct) error: %v", err)
	}

	// BSON represents empty struct as an empty document
	// Minimum BSON document is 5 bytes
	if len(data) < 5 {
		t.Errorf("Marshal(empty struct) produced invalid BSON: len = %d", len(data))
	}
}

// --- Malformed input tests ---

func TestUnmarshal_EmptyInput(t *testing.T) {
	c := New()

	var v struct{}
	err := c.Unmarshal([]byte{}, &v)
	if err == nil {
		t.Error("Unmarshal(empty) should return error")
	}
}

func TestUnmarshal_TruncatedData(t *testing.T) {
	c := New()

	type TestStruct struct {
		Name  string `bson:"name"`
		Value int    `bson:"value"`
	}

	// First marshal valid data
	original := TestStruct{Name: "test", Value: 42}
	data, err := c.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	// Now truncate it at various points
	truncations := []int{1, 4, len(data) / 2, len(data) - 1}
	for _, truncLen := range truncations {
		t.Run("truncate_at_"+string(rune('0'+truncLen)), func(t *testing.T) {
			var v TestStruct
			err := c.Unmarshal(data[:truncLen], &v)
			if err == nil {
				t.Errorf("Unmarshal(truncated at %d) should return error", truncLen)
			}
		})
	}
}

func TestUnmarshal_InvalidHeader(t *testing.T) {
	c := New()

	// BSON starts with a 4-byte little-endian length
	// This claims a length of 1000 bytes but only has 10
	invalidData := []byte{0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	var v struct{}
	err := c.Unmarshal(invalidData, &v)
	if err == nil {
		t.Error("Unmarshal(invalid header) should return error")
	}
}

func TestUnmarshal_NestedStructure(t *testing.T) {
	c := New()

	type Nested struct {
		Level int     `bson:"level"`
		Child *Nested `bson:"child"`
	}

	original := Nested{
		Level: 1,
		Child: &Nested{
			Level: 2,
			Child: &Nested{
				Level: 3,
			},
		},
	}

	data, err := c.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal(nested) error: %v", err)
	}

	var v Nested
	err = c.Unmarshal(data, &v)
	if err != nil {
		t.Errorf("Unmarshal(nested) error: %v", err)
	}

	if v.Level != 1 || v.Child == nil || v.Child.Level != 2 {
		t.Error("Unmarshal(nested) did not correctly parse nested structure")
	}
}

func TestMarshal_SpecialCharacters(t *testing.T) {
	c := New()

	type TestStruct struct {
		Text string `bson:"text"`
	}

	testCases := []struct {
		name  string
		input string
	}{
		{"newline", "line1\nline2"},
		{"unicode", "日本語テスト"},
		{"emoji", "hello 👋 world"},
		{"special", "key.with.dots"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			original := TestStruct{Text: tc.input}
			data, err := c.Marshal(original)
			if err != nil {
				t.Fatalf("Marshal() error: %v", err)
			}

			var restored TestStruct
			if err := c.Unmarshal(data, &restored); err != nil {
				t.Fatalf("Unmarshal() error: %v", err)
			}

			if restored.Text != original.Text {
				t.Errorf("round-trip failed for %q: got %q", tc.input, restored.Text)
			}
		})
	}
}

func TestMarshal_ComplexTypes(t *testing.T) {
	c := New()

	type Inner struct {
		Value int `bson:"value"`
	}

	type Complex struct {
		Strings []string       `bson:"strings"`
		Map     map[string]int `bson:"map"`
		Nested  []Inner        `bson:"nested"`
		Pointer *Inner         `bson:"pointer"`
	}

	original := Complex{
		Strings: []string{"a", "b", "c"},
		Map:     map[string]int{"x": 1, "y": 2},
		Nested:  []Inner{{Value: 10}, {Value: 20}},
		Pointer: &Inner{Value: 30},
	}

	data, err := c.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal(complex) error: %v", err)
	}

	var restored Complex
	if err := c.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal(complex) error: %v", err)
	}

	if len(restored.Strings) != 3 || restored.Strings[0] != "a" {
		t.Error("round-trip failed for Strings")
	}
	if restored.Map["x"] != 1 {
		t.Error("round-trip failed for Map")
	}
	if len(restored.Nested) != 2 || restored.Nested[0].Value != 10 {
		t.Error("round-trip failed for Nested")
	}
	if restored.Pointer == nil || restored.Pointer.Value != 30 {
		t.Error("round-trip failed for Pointer")
	}
}

func TestMarshal_BinaryData(t *testing.T) {
	c := New()

	type TestStruct struct {
		Data []byte `bson:"data"`
	}

	original := TestStruct{Data: []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}}

	data, err := c.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal(binary) error: %v", err)
	}

	var restored TestStruct
	if err := c.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal(binary) error: %v", err)
	}

	if len(restored.Data) != len(original.Data) {
		t.Errorf("round-trip failed: len = %d, want %d", len(restored.Data), len(original.Data))
	}
	for i, b := range original.Data {
		if restored.Data[i] != b {
			t.Errorf("round-trip failed at byte %d: got %d, want %d", i, restored.Data[i], b)
		}
	}
}

func TestUnmarshal_ExtraData(t *testing.T) {
	c := New()

	type Small struct {
		Name string `bson:"name"`
	}

	type Large struct {
		Name  string `bson:"name"`
		Extra string `bson:"extra"`
	}

	// Marshal large struct, unmarshal into small (extra field ignored)
	original := Large{Name: "test", Extra: "ignored"}
	data, err := c.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal(large) error: %v", err)
	}

	var restored Small
	err = c.Unmarshal(data, &restored)
	if err != nil {
		t.Errorf("Unmarshal(into smaller struct) error: %v", err)
	}
	if restored.Name != "test" {
		t.Errorf("Unmarshal Name = %q, want %q", restored.Name, "test")
	}
}
