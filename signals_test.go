package codec

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEmitProcessorCreated(t *testing.T) {
	// Should not panic
	emitProcessorCreated(context.Background(), "application/json", "TestType")
}

func TestEmitReceiveStart(t *testing.T) {
	emitReceiveStart(context.Background(), "application/json", "TestType")
}

func TestEmitReceiveComplete_Success(t *testing.T) {
	emitReceiveComplete(context.Background(), "application/json", "TestType", 100*time.Millisecond, 5, nil)
}

func TestEmitReceiveComplete_Error(t *testing.T) {
	emitReceiveComplete(context.Background(), "application/json", "TestType", 100*time.Millisecond, 0, errors.New("test error"))
}

func TestEmitLoadStart(t *testing.T) {
	emitLoadStart(context.Background(), "application/json", "TestType")
}

func TestEmitLoadComplete_Success(t *testing.T) {
	emitLoadComplete(context.Background(), "application/json", "TestType", 100*time.Millisecond, 3, nil)
}

func TestEmitLoadComplete_Error(t *testing.T) {
	emitLoadComplete(context.Background(), "application/json", "TestType", 100*time.Millisecond, 0, errors.New("test error"))
}

func TestEmitStoreStart(t *testing.T) {
	emitStoreStart(context.Background(), "application/json", "TestType")
}

func TestEmitStoreComplete_Success(t *testing.T) {
	emitStoreComplete(context.Background(), "application/json", "TestType", 1024, 100*time.Millisecond, 2, nil)
}

func TestEmitStoreComplete_Error(t *testing.T) {
	emitStoreComplete(context.Background(), "application/json", "TestType", 0, 100*time.Millisecond, 0, errors.New("test error"))
}

func TestEmitSendStart(t *testing.T) {
	emitSendStart(context.Background(), "application/json", "TestType")
}

func TestEmitSendComplete_Success(t *testing.T) {
	emitSendComplete(context.Background(), "application/json", "TestType", 512, 100*time.Millisecond, 4, 2, nil)
}

func TestEmitSendComplete_Error(t *testing.T) {
	emitSendComplete(context.Background(), "application/json", "TestType", 0, 100*time.Millisecond, 0, 0, errors.New("test error"))
}

func TestSignalVariables(t *testing.T) {
	// Verify signals are properly initialized
	signals := []struct {
		name   string
		signal interface{}
	}{
		{"SignalProcessorCreated", SignalProcessorCreated},
		{"SignalReceiveStart", SignalReceiveStart},
		{"SignalReceiveComplete", SignalReceiveComplete},
		{"SignalLoadStart", SignalLoadStart},
		{"SignalLoadComplete", SignalLoadComplete},
		{"SignalStoreStart", SignalStoreStart},
		{"SignalStoreComplete", SignalStoreComplete},
		{"SignalSendStart", SignalSendStart},
		{"SignalSendComplete", SignalSendComplete},
	}

	for _, s := range signals {
		if s.signal == nil {
			t.Errorf("%s is nil", s.name)
		}
	}
}

func TestKeyVariables(t *testing.T) {
	// Verify keys are properly initialized
	keys := []struct {
		name string
		key  interface{}
	}{
		{"KeyContentType", KeyContentType},
		{"KeyTypeName", KeyTypeName},
		{"KeySize", KeySize},
		{"KeyDuration", KeyDuration},
		{"KeyError", KeyError},
		{"KeyEncryptedCount", KeyEncryptedCount},
		{"KeyDecryptedCount", KeyDecryptedCount},
		{"KeyHashedCount", KeyHashedCount},
		{"KeyMaskedCount", KeyMaskedCount},
		{"KeyRedactedCount", KeyRedactedCount},
	}

	for _, k := range keys {
		if k.key == nil {
			t.Errorf("%s is nil", k.name)
		}
	}
}
