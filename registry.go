package codec

import (
	"reflect"
	"sync"
)

// registryKey combines type and codec for cache lookup.
type registryKey struct {
	typ         reflect.Type
	contentType string
}

var (
	registry   = make(map[registryKey]any)
	registryMu sync.RWMutex
)

// Use returns a cached processor or builds a new one.
// The processor is cached by type and codec content type.
// T must implement Cloner[T].
func Use[T Cloner[T]](codec Codec, opts ...ProcessorOption) (*Processor[T], error) {
	typ := reflect.TypeFor[T]()
	key := registryKey{typ: typ, contentType: codec.ContentType()}

	// Fast path: read-lock cache check
	registryMu.RLock()
	if cached, ok := registry[key]; ok {
		registryMu.RUnlock()
		return cached.(*Processor[T]), nil
	}
	registryMu.RUnlock()

	// Slow path: build and cache with write-lock
	registryMu.Lock()
	defer registryMu.Unlock()

	// Double-check pattern
	if cached, ok := registry[key]; ok {
		return cached.(*Processor[T]), nil
	}

	processor, err := NewProcessor[T](codec, opts...)
	if err != nil {
		return nil, err
	}

	registry[key] = processor
	return processor, nil
}

// Reset clears the processor registry.
// This is primarily useful for test isolation.
func Reset() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = make(map[registryKey]any)
}
