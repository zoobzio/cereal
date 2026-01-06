// Package msgpack provides a MessagePack codec implementation.
package msgpack

import (
	"github.com/vmihailenco/msgpack/v5"
	"github.com/zoobzio/codec"
)

// msgpackCodec implements codec.Codec for MessagePack.
type msgpackCodec struct{}

// New returns a MessagePack codec.
func New() codec.Codec {
	return &msgpackCodec{}
}

// ContentType returns the MIME type for MessagePack.
func (c *msgpackCodec) ContentType() string {
	return "application/msgpack"
}

// Marshal encodes v as MessagePack.
func (c *msgpackCodec) Marshal(v any) ([]byte, error) {
	return msgpack.Marshal(v)
}

// Unmarshal decodes MessagePack data into v.
func (c *msgpackCodec) Unmarshal(data []byte, v any) error {
	return msgpack.Unmarshal(data, v)
}
