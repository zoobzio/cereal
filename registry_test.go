package cereal_test

import (
	"testing"

	"github.com/zoobzio/cereal"
	"github.com/zoobzio/cereal/json"
)

type CacheTestUser struct {
	Name string `json:"name"`
}

func (u CacheTestUser) Clone() CacheTestUser { return u }

func TestUse_Caching(t *testing.T) {
	cereal.Reset() // Clear cache

	s1, err := cereal.Use[CacheTestUser](json.New())
	if err != nil {
		t.Fatalf("Use() error: %v", err)
	}

	s2, err := cereal.Use[CacheTestUser](json.New())
	if err != nil {
		t.Fatalf("Use() error: %v", err)
	}

	if s1 != s2 {
		t.Error("Use() should return cached processor")
	}
}

func TestUse_DifferentCodecs(t *testing.T) {
	cereal.Reset()

	// Create a simple codec for testing
	jsonCodec := json.New()

	s1, _ := cereal.Use[CacheTestUser](jsonCodec)

	// Same type, same codec should return same instance
	s2, _ := cereal.Use[CacheTestUser](jsonCodec)

	if s1 != s2 {
		t.Error("same type and codec should return cached processor")
	}
}

func TestReset(t *testing.T) {
	s1, _ := cereal.Use[CacheTestUser](json.New())

	cereal.Reset()

	s2, _ := cereal.Use[CacheTestUser](json.New())

	if s1 == s2 {
		t.Error("Reset() should clear cache, new processor expected")
	}
}
