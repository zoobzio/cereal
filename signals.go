package codec

import (
	"context"
	"time"

	"github.com/zoobzio/capitan"
)

// Signals for codec events.
var (
	SignalProcessorCreated = capitan.NewSignal("codec.processor.created", "Processor instantiated")
	SignalReceiveStart     = capitan.NewSignal("codec.receive.start", "Receive operation beginning")
	SignalReceiveComplete  = capitan.NewSignal("codec.receive.complete", "Receive operation finished")
	SignalLoadStart        = capitan.NewSignal("codec.load.start", "Load operation beginning")
	SignalLoadComplete     = capitan.NewSignal("codec.load.complete", "Load operation finished")
	SignalStoreStart       = capitan.NewSignal("codec.store.start", "Store operation beginning")
	SignalStoreComplete    = capitan.NewSignal("codec.store.complete", "Store operation finished")
	SignalSendStart        = capitan.NewSignal("codec.send.start", "Send operation beginning")
	SignalSendComplete     = capitan.NewSignal("codec.send.complete", "Send operation finished")
)

// Keys for typed event data.
var (
	KeyContentType    = capitan.NewStringKey("content_type")
	KeyTypeName       = capitan.NewStringKey("type_name")
	KeySize           = capitan.NewIntKey("size")
	KeyDuration       = capitan.NewDurationKey("duration")
	KeyError          = capitan.NewErrorKey("error")
	KeyEncryptedCount = capitan.NewIntKey("encrypted_count")
	KeyDecryptedCount = capitan.NewIntKey("decrypted_count")
	KeyHashedCount    = capitan.NewIntKey("hashed_count")
	KeyMaskedCount    = capitan.NewIntKey("masked_count")
	KeyRedactedCount  = capitan.NewIntKey("redacted_count")
)

// emitProcessorCreated emits an event when a processor is created.
func emitProcessorCreated(contentType, typeName string) {
	capitan.Emit(context.Background(), SignalProcessorCreated,
		KeyContentType.Field(contentType),
		KeyTypeName.Field(typeName),
	)
}

// emitReceiveStart emits an event when receive begins.
func emitReceiveStart(contentType, typeName string) {
	capitan.Emit(context.Background(), SignalReceiveStart,
		KeyContentType.Field(contentType),
		KeyTypeName.Field(typeName),
	)
}

// emitReceiveComplete emits an event when receive finishes.
func emitReceiveComplete(contentType, typeName string, duration time.Duration, hashed int, err error) {
	ctx := context.Background()
	fields := []capitan.Field{
		KeyContentType.Field(contentType),
		KeyTypeName.Field(typeName),
		KeyDuration.Field(duration),
		KeyHashedCount.Field(hashed),
	}
	if err != nil {
		fields = append(fields, KeyError.Field(err))
		capitan.Error(ctx, SignalReceiveComplete, fields...)
	} else {
		capitan.Emit(ctx, SignalReceiveComplete, fields...)
	}
}

// emitLoadStart emits an event when load begins.
func emitLoadStart(contentType, typeName string) {
	capitan.Emit(context.Background(), SignalLoadStart,
		KeyContentType.Field(contentType),
		KeyTypeName.Field(typeName),
	)
}

// emitLoadComplete emits an event when load finishes.
func emitLoadComplete(contentType, typeName string, duration time.Duration, decrypted int, err error) {
	ctx := context.Background()
	fields := []capitan.Field{
		KeyContentType.Field(contentType),
		KeyTypeName.Field(typeName),
		KeyDuration.Field(duration),
		KeyDecryptedCount.Field(decrypted),
	}
	if err != nil {
		fields = append(fields, KeyError.Field(err))
		capitan.Error(ctx, SignalLoadComplete, fields...)
	} else {
		capitan.Emit(ctx, SignalLoadComplete, fields...)
	}
}

// emitStoreStart emits an event when store begins.
func emitStoreStart(contentType, typeName string) {
	capitan.Emit(context.Background(), SignalStoreStart,
		KeyContentType.Field(contentType),
		KeyTypeName.Field(typeName),
	)
}

// emitStoreComplete emits an event when store finishes.
func emitStoreComplete(contentType, typeName string, size int, duration time.Duration, encrypted int, err error) {
	ctx := context.Background()
	fields := []capitan.Field{
		KeyContentType.Field(contentType),
		KeyTypeName.Field(typeName),
		KeySize.Field(size),
		KeyDuration.Field(duration),
		KeyEncryptedCount.Field(encrypted),
	}
	if err != nil {
		fields = append(fields, KeyError.Field(err))
		capitan.Error(ctx, SignalStoreComplete, fields...)
	} else {
		capitan.Emit(ctx, SignalStoreComplete, fields...)
	}
}

// emitSendStart emits an event when send begins.
func emitSendStart(contentType, typeName string) {
	capitan.Emit(context.Background(), SignalSendStart,
		KeyContentType.Field(contentType),
		KeyTypeName.Field(typeName),
	)
}

// emitSendComplete emits an event when send finishes.
func emitSendComplete(contentType, typeName string, size int, duration time.Duration, masked, redacted int, err error) {
	ctx := context.Background()
	fields := []capitan.Field{
		KeyContentType.Field(contentType),
		KeyTypeName.Field(typeName),
		KeySize.Field(size),
		KeyDuration.Field(duration),
		KeyMaskedCount.Field(masked),
		KeyRedactedCount.Field(redacted),
	}
	if err != nil {
		fields = append(fields, KeyError.Field(err))
		capitan.Error(ctx, SignalSendComplete, fields...)
	} else {
		capitan.Emit(ctx, SignalSendComplete, fields...)
	}
}
