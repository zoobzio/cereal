// Package xml provides an XML codec implementation.
package xml

import (
	"encoding/xml"

	"github.com/zoobzio/cereal"
)

// xmlCodec implements cereal.Codec for XML.
type xmlCodec struct{}

// New returns an XML cereal.
func New() cereal.Codec {
	return &xmlCodec{}
}

// ContentType returns the MIME type for XML.
func (c *xmlCodec) ContentType() string {
	return "application/xml"
}

// Marshal encodes v as XML.
func (c *xmlCodec) Marshal(v any) ([]byte, error) {
	return xml.Marshal(v)
}

// Unmarshal decodes XML data into v.
func (c *xmlCodec) Unmarshal(data []byte, v any) error {
	return xml.Unmarshal(data, v)
}
