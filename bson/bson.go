// Package bson provides a BSON codec implementation.
package bson

import (
	"github.com/zoobzio/codec"
	"go.mongodb.org/mongo-driver/bson"
)

// bsonCodec implements codec.Codec for BSON.
type bsonCodec struct{}

// New returns a BSON codec.
func New() codec.Codec {
	return &bsonCodec{}
}

// ContentType returns the MIME type for BSON.
func (c *bsonCodec) ContentType() string {
	return "application/bson"
}

// Marshal encodes v as BSON.
func (c *bsonCodec) Marshal(v any) ([]byte, error) {
	return bson.Marshal(v)
}

// Unmarshal decodes BSON data into v.
func (c *bsonCodec) Unmarshal(data []byte, v any) error {
	return bson.Unmarshal(data, v)
}
