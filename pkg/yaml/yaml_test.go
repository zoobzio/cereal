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
