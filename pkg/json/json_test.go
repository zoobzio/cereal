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
