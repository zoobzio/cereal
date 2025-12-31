// Package json provides a JSON codec implementation.
package json

import (
	"encoding/json"

	"github.com/zoobzio/codec"
)

// jsonCodec implements codec.Codec for JSON.
type jsonCodec struct{}

// New returns a JSON codec.
func New() codec.Codec {
	return &jsonCodec{}
}

// ContentType returns the MIME type for JSON.
func (c *jsonCodec) ContentType() string {
	return "application/json"
}

// Marshal encodes v as JSON.
func (c *jsonCodec) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

// Unmarshal decodes JSON data into v.
func (c *jsonCodec) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
