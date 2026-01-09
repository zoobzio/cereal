package xml

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
	if c.ContentType() != "application/xml" {
		t.Errorf("ContentType() = %q, want %q", c.ContentType(), "application/xml")
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	c := New()

	type TestStruct struct {
		Name  string `xml:"name"`
		Value int    `xml:"value"`
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
	err := c.Unmarshal([]byte("not xml at all {{{"), &v)
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

	// XML represents nil as empty (no element)
	if len(data) != 0 {
		t.Errorf("Marshal(nil) = %q, want empty", data)
	}
}

// --- Malformed input tests ---

func TestUnmarshal_EmptyInput(t *testing.T) {
	c := New()

	var v struct {
		Name string `xml:"name"`
	}
	err := c.Unmarshal([]byte{}, &v)
	if err == nil {
		t.Error("Unmarshal(empty) should return error")
	}
}

func TestUnmarshal_MalformedXML(t *testing.T) {
	c := New()

	testCases := []struct {
		name  string
		input string
	}{
		{"unclosed tag", "<root><name>test</root>"},
		{"mismatched tags", "<root></wrong>"},
		{"no root element", "just text"},
		{"invalid characters", "<root>\x00invalid</root>"},
		{"unclosed element", "<root><name>"},
		{"invalid attribute", "<root attr=>value</root>"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var v struct {
				Name string `xml:"name"`
			}
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
		Value int `xml:"value"`
	}

	// XML is string-based, so type coercion happens differently
	testCases := []struct {
		name        string
		input       string
		shouldError bool
	}{
		{"string for int", "<TestStruct><value>not_a_number</value></TestStruct>", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var v TestStruct
			err := c.Unmarshal([]byte(tc.input), &v)
			if tc.shouldError && err == nil {
				t.Errorf("Unmarshal(%q) should return error for type mismatch", tc.input)
			}
		})
	}
}

func TestUnmarshal_NestedStructure(t *testing.T) {
	c := New()

	type Child struct {
		Level int `xml:"level"`
	}
	type Parent struct {
		Level int    `xml:"level"`
		Child *Child `xml:"child"`
	}

	input := `<Parent><level>1</level><child><level>2</level></child></Parent>`

	var v Parent
	err := c.Unmarshal([]byte(input), &v)
	if err != nil {
		t.Errorf("Unmarshal(nested) error: %v", err)
	}

	if v.Level != 1 || v.Child == nil || v.Child.Level != 2 {
		t.Error("Unmarshal(nested) did not correctly parse nested structure")
	}
}

func TestUnmarshal_Attributes(t *testing.T) {
	c := New()

	type Item struct {
		ID    string `xml:"id,attr"`
		Value string `xml:",chardata"`
	}

	input := `<Item id="123">test value</Item>`

	var v Item
	err := c.Unmarshal([]byte(input), &v)
	if err != nil {
		t.Errorf("Unmarshal(attributes) error: %v", err)
	}

	if v.ID != "123" {
		t.Errorf("Unmarshal(attributes) ID = %q, want %q", v.ID, "123")
	}
	if v.Value != "test value" {
		t.Errorf("Unmarshal(attributes) Value = %q, want %q", v.Value, "test value")
	}
}

func TestUnmarshal_CDATA(t *testing.T) {
	c := New()

	type Item struct {
		Content string `xml:"content"`
	}

	input := `<Item><content><![CDATA[<special> content & stuff]]></content></Item>`

	var v Item
	err := c.Unmarshal([]byte(input), &v)
	if err != nil {
		t.Errorf("Unmarshal(CDATA) error: %v", err)
	}

	expected := "<special> content & stuff"
	if v.Content != expected {
		t.Errorf("Unmarshal(CDATA) Content = %q, want %q", v.Content, expected)
	}
}

func TestMarshal_SpecialCharacters(t *testing.T) {
	c := New()

	type TestStruct struct {
		Text string `xml:"text"`
	}

	testCases := []struct {
		name  string
		input string
	}{
		{"ampersand", "rock & roll"},
		{"less than", "a < b"},
		{"greater than", "a > b"},
		{"quote", `say "hello"`},
		{"apostrophe", "it's fine"},
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

func TestUnmarshal_Namespaces(t *testing.T) {
	c := New()

	type Item struct {
		XMLName struct{} `xml:"item"`
		Name    string   `xml:"name"`
	}

	// Namespaced XML
	input := `<item xmlns="http://example.com"><name>test</name></item>`

	var v Item
	err := c.Unmarshal([]byte(input), &v)
	if err != nil {
		t.Errorf("Unmarshal(namespaces) error: %v", err)
	}
	if v.Name != "test" {
		t.Errorf("Unmarshal(namespaces) Name = %q, want %q", v.Name, "test")
	}
}

func TestUnmarshal_XMLDeclaration(t *testing.T) {
	c := New()

	type Item struct {
		Name string `xml:"name"`
	}

	input := `<?xml version="1.0" encoding="UTF-8"?><Item><name>test</name></Item>`

	var v Item
	err := c.Unmarshal([]byte(input), &v)
	if err != nil {
		t.Errorf("Unmarshal(XML declaration) error: %v", err)
	}
	if v.Name != "test" {
		t.Errorf("Unmarshal(XML declaration) Name = %q, want %q", v.Name, "test")
	}
}
