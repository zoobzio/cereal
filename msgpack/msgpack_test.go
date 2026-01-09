package msgpack

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
	if c.ContentType() != "application/msgpack" {
		t.Errorf("ContentType() = %q, want %q", c.ContentType(), "application/msgpack")
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	c := New()

	type TestStruct struct {
		Name  string `msgpack:"name"`
		Value int    `msgpack:"value"`
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

func TestMarshalBinary(t *testing.T) {
	c := New()

	data, err := c.Marshal(map[string]int{"a": 1, "b": 2})
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	// MessagePack is binary, should not be valid UTF-8 JSON
	if data[0] == '{' {
		t.Error("MessagePack output should be binary, not JSON")
	}
}

func TestUnmarshalInvalid(t *testing.T) {
	c := New()

	var v struct{}
	err := c.Unmarshal([]byte("not msgpack"), &v)
	if err == nil {
		t.Error("Unmarshal(invalid) should return error")
	}
}

func TestMarshalNil(t *testing.T) {
	c := New()

	data, err := c.Marshal(nil)
	if err != nil {
		t.Fatalf("Marshal(nil) error: %v", err)
	}

	// MessagePack nil is 0xc0
	if len(data) != 1 || data[0] != 0xc0 {
		t.Errorf("Marshal(nil) = %v, want [0xc0]", data)
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
		Name  string `msgpack:"name"`
		Value int    `msgpack:"value"`
	}

	// First marshal valid data
	original := TestStruct{Name: "test", Value: 42}
	data, err := c.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	// Now truncate it at various points
	truncations := []int{1, len(data) / 2, len(data) - 1}
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

func TestUnmarshal_TypeMismatch(t *testing.T) {
	c := New()

	// Marshal a string, try to unmarshal as int
	strData, err := c.Marshal("not a number")
	if err != nil {
		t.Fatalf("Marshal(string) error: %v", err)
	}

	var intVal int
	err = c.Unmarshal(strData, &intVal)
	if err == nil {
		t.Error("Unmarshal(string as int) should return error")
	}
}

func TestUnmarshal_NestedStructure(t *testing.T) {
	c := New()

	type Nested struct {
		Level int     `msgpack:"level"`
		Child *Nested `msgpack:"child"`
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
		Text string `msgpack:"text"`
	}

	testCases := []struct {
		name  string
		input string
	}{
		{"newline", "line1\nline2"},
		{"null byte", "before\x00after"},
		{"unicode", "日本語テスト"},
		{"emoji", "hello 👋 world"},
		{"binary-like", string([]byte{0x00, 0x01, 0x02, 0xff})},
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
				t.Errorf("round-trip failed for input: got %q, want %q", restored.Text, tc.input)
			}
		})
	}
}

func TestMarshal_LargeData(t *testing.T) {
	c := New()

	type TestStruct struct {
		Data []byte `msgpack:"data"`
	}

	// Create large data (1MB)
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	original := TestStruct{Data: largeData}
	data, err := c.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal(large) error: %v", err)
	}

	var restored TestStruct
	if err := c.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal(large) error: %v", err)
	}

	if len(restored.Data) != len(original.Data) {
		t.Errorf("round-trip failed: len = %d, want %d", len(restored.Data), len(original.Data))
	}
}

func TestUnmarshal_InvalidType(t *testing.T) {
	c := New()

	// Marshal an array, try to unmarshal as map
	arrData, err := c.Marshal([]int{1, 2, 3})
	if err != nil {
		t.Fatalf("Marshal(array) error: %v", err)
	}

	var mapVal map[string]int
	err = c.Unmarshal(arrData, &mapVal)
	if err == nil {
		t.Error("Unmarshal(array as map) should return error")
	}
}

func TestMarshal_ComplexTypes(t *testing.T) {
	c := New()

	type Inner struct {
		Value int `msgpack:"value"`
	}

	type Complex struct {
		Strings []string          `msgpack:"strings"`
		Map     map[string]int    `msgpack:"map"`
		Nested  []Inner           `msgpack:"nested"`
		Pointer *Inner            `msgpack:"pointer"`
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
