// Package yaml provides a YAML codec implementation.
package yaml

import (
	"github.com/zoobzio/cereal"
	"gopkg.in/yaml.v3"
)

// yamlCodec implements cereal.Codec for YAML.
type yamlCodec struct{}

// New returns a YAML cereal.
func New() cereal.Codec {
	return &yamlCodec{}
}

// ContentType returns the MIME type for YAML.
func (c *yamlCodec) ContentType() string {
	return "application/yaml"
}

// Marshal encodes v as YAML.
func (c *yamlCodec) Marshal(v any) ([]byte, error) {
	return yaml.Marshal(v)
}

// Unmarshal decodes YAML data into v.
func (c *yamlCodec) Unmarshal(data []byte, v any) error {
	return yaml.Unmarshal(data, v)
}
