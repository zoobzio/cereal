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
