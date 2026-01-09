package json

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
	if c.ContentType() != "application/json" {
		t.Errorf("ContentType() = %q, want %q", c.ContentType(), "application/json")
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	c := New()

	type TestStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
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

func TestMarshalNil(t *testing.T) {
	c := New()

	data, err := c.Marshal(nil)
	if err != nil {
		t.Fatalf("Marshal(nil) error: %v", err)
	}

	if string(data) != "null" {
		t.Errorf("Marshal(nil) = %q, want %q", data, "null")
	}
}

func TestUnmarshalInvalid(t *testing.T) {
	c := New()

	var v struct{}
	err := c.Unmarshal([]byte("invalid json"), &v)
	if err == nil {
		t.Error("Unmarshal(invalid) should return error")
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

func TestUnmarshal_TruncatedJSON(t *testing.T) {
	c := New()

	testCases := []struct {
		name  string
		input string
	}{
		{"truncated object", `{"name": "test`},
		{"truncated array", `[1, 2, 3`},
		{"truncated string", `{"name": "te`},
		{"truncated number", `{"value": 12`},
		{"unclosed brace", `{"name": "test"`},
		{"unclosed bracket", `["a", "b"`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var v map[string]any
			err := c.Unmarshal([]byte(tc.input), &v)
			if err == nil {
				t.Errorf("Unmarshal(%q) should return error", tc.input)
			}
		})
	}
}

func TestUnmarshal_TypeMismatch(t *testing.T) {
	c := New()

	type TestStruct struct {
		Value int `json:"value"`
	}

	testCases := []struct {
		name  string
		input string
	}{
		{"string for int", `{"value": "not a number"}`},
		{"object for int", `{"value": {"nested": true}}`},
		{"array for int", `{"value": [1, 2, 3]}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var v TestStruct
			err := c.Unmarshal([]byte(tc.input), &v)
			if err == nil {
				t.Errorf("Unmarshal(%q) should return error for type mismatch", tc.input)
			}
		})
	}
}

func TestUnmarshal_InvalidUnicode(t *testing.T) {
	c := New()

	var v struct {
		Name string `json:"name"`
	}

	// Invalid unicode escape sequence
	err := c.Unmarshal([]byte(`{"name": "\uZZZZ"}`), &v)
	if err == nil {
		t.Error("Unmarshal(invalid unicode) should return error")
	}
}

func TestUnmarshal_NestedStructure(t *testing.T) {
	c := New()

	type Nested struct {
		Level int     `json:"level"`
		Child *Nested `json:"child"`
	}

	// Create deeply nested but valid JSON
	input := `{"level": 1, "child": {"level": 2, "child": {"level": 3, "child": null}}}`

	var v Nested
	err := c.Unmarshal([]byte(input), &v)
	if err != nil {
		t.Errorf("Unmarshal(nested) error: %v", err)
	}

	if v.Level != 1 || v.Child == nil || v.Child.Level != 2 {
		t.Error("Unmarshal(nested) did not correctly parse nested structure")
	}
}

func TestMarshal_CyclicReference(t *testing.T) {
	c := New()

	type Node struct {
		Value int   `json:"value"`
		Next  *Node `json:"next"`
	}

	// Create a cycle (this will cause marshal to fail or infinite loop)
	node1 := &Node{Value: 1}
	node2 := &Node{Value: 2}
	node1.Next = node2
	node2.Next = node1

	// This should cause an error (stack overflow protection)
	_, err := c.Marshal(node1)
	if err == nil {
		t.Error("Marshal(cyclic) should return error")
	}
}

func TestUnmarshal_ExtraFields(t *testing.T) {
	c := New()

	type TestStruct struct {
		Name string `json:"name"`
	}

	// Extra fields should be ignored by default
	input := `{"name": "test", "extra": "ignored", "another": 123}`
	var v TestStruct
	err := c.Unmarshal([]byte(input), &v)
	if err != nil {
		t.Errorf("Unmarshal(extra fields) error: %v", err)
	}
	if v.Name != "test" {
		t.Errorf("Unmarshal(extra fields) Name = %q, want %q", v.Name, "test")
	}
}

func TestUnmarshal_NullValues(t *testing.T) {
	c := New()

	type TestStruct struct {
		Name  *string `json:"name"`
		Value *int    `json:"value"`
	}

	input := `{"name": null, "value": null}`
	var v TestStruct
	err := c.Unmarshal([]byte(input), &v)
	if err != nil {
		t.Errorf("Unmarshal(null values) error: %v", err)
	}
	if v.Name != nil || v.Value != nil {
		t.Error("Unmarshal(null values) should set pointers to nil")
	}
}

func TestMarshal_SpecialCharacters(t *testing.T) {
	c := New()

	type TestStruct struct {
		Text string `json:"text"`
	}

	testCases := []struct {
		name  string
		input string
	}{
		{"newline", "line1\nline2"},
		{"tab", "col1\tcol2"},
		{"quote", `say "hello"`},
		{"backslash", `path\to\file`},
		{"unicode", "日本語テスト"},
		{"emoji", "hello 👋 world"},
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
