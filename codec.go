// Package codec provides content-type aware marshaling with sanitization support.
package codec

// Codec provides content-type aware marshaling.
type Codec interface {
	// ContentType returns the MIME type for this codec (e.g., "application/json").
	ContentType() string

	// Marshal encodes v into bytes.
	Marshal(v any) ([]byte, error)

	// Unmarshal decodes data into v.
	Unmarshal(data []byte, v any) error
}
