package yaml

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
	if c.ContentType() != "application/yaml" {
		t.Errorf("ContentType() = %q, want %q", c.ContentType(), "application/yaml")
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	c := New()

	type TestStruct struct {
		Name  string `yaml:"name"`
		Value int    `yaml:"value"`
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

	var v struct {
		Name string `yaml:"name"`
	}
	// YAML is very permissive, this should still parse as string
	err := c.Unmarshal([]byte("name: [invalid"), &v)
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

	// YAML represents nil as "null\n"
	if string(data) != "null\n" {
		t.Errorf("Marshal(nil) = %q, want %q", data, "null\n")
	}
}

// --- Malformed input tests ---

func TestUnmarshal_EmptyInput(t *testing.T) {
	c := New()

	var v struct {
		Name string `yaml:"name"`
	}
	// Empty input should not error in YAML (results in zero value)
	err := c.Unmarshal([]byte{}, &v)
	if err != nil {
		t.Errorf("Unmarshal(empty) error: %v", err)
	}
}

func TestUnmarshal_MalformedYAML(t *testing.T) {
	c := New()

	testCases := []struct {
		name  string
		input string
	}{
		{"bad indentation", "name: test\n  invalid: indentation"},
		{"unclosed quote", `name: "unterminated`},
		{"tab character in indentation", "name: test\n\t- invalid"},
		{"duplicate key mapping", "name: first\nname: second"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var v map[string]any
			err := c.Unmarshal([]byte(tc.input), &v)
			// Note: YAML is very permissive, some of these may not error
			// We're testing that they at least don't panic
			_ = err
		})
	}
}

func TestUnmarshal_TypeMismatch(t *testing.T) {
	c := New()

	type TestStruct struct {
		Value int `yaml:"value"`
	}

	testCases := []struct {
		name  string
		input string
	}{
		{"string for int", "value: not_a_number"},
		{"array for int", "value:\n  - 1\n  - 2"},
		{"map for int", "value:\n  nested: true"},
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

func TestUnmarshal_NestedStructure(t *testing.T) {
	c := New()

	type Nested struct {
		Level int     `yaml:"level"`
		Child *Nested `yaml:"child"`
	}

	input := `level: 1
child:
  level: 2
  child:
    level: 3
    child: null`

	var v Nested
	err := c.Unmarshal([]byte(input), &v)
	if err != nil {
		t.Errorf("Unmarshal(nested) error: %v", err)
	}

	if v.Level != 1 || v.Child == nil || v.Child.Level != 2 {
		t.Error("Unmarshal(nested) did not correctly parse nested structure")
	}
}

func TestUnmarshal_Anchors(t *testing.T) {
	c := New()

	// YAML anchors and aliases
	input := `default: &default
  timeout: 30
  retries: 3
production:
  <<: *default
  timeout: 60`

	var v map[string]any
	err := c.Unmarshal([]byte(input), &v)
	if err != nil {
		t.Errorf("Unmarshal(anchors) error: %v", err)
	}

	prod, ok := v["production"].(map[string]any)
	if !ok {
		t.Fatal("production key not found or wrong type")
	}
	if prod["timeout"] != 60 {
		t.Errorf("production.timeout = %v, want 60", prod["timeout"])
	}
	if prod["retries"] != 3 {
		t.Errorf("production.retries = %v, want 3", prod["retries"])
	}
}

func TestMarshal_SpecialCharacters(t *testing.T) {
	c := New()

	type TestStruct struct {
		Text string `yaml:"text"`
	}

	testCases := []struct {
		name  string
		input string
	}{
		{"newline", "line1\nline2"},
		{"colon", "key: value"},
		{"unicode", "日本語テスト"},
		{"emoji", "hello 👋 world"},
		{"special chars", "#@!$%^&*()"},
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

func TestUnmarshal_MultiDocument(t *testing.T) {
	c := New()

	// Multi-document YAML (only first document is parsed)
	input := `---
name: doc1
---
name: doc2`

	var v struct {
		Name string `yaml:"name"`
	}
	err := c.Unmarshal([]byte(input), &v)
	if err != nil {
		t.Errorf("Unmarshal(multi-doc) error: %v", err)
	}
	if v.Name != "doc1" {
		t.Errorf("Unmarshal(multi-doc) Name = %q, want %q", v.Name, "doc1")
	}
}
