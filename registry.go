package cereal

import (
	"reflect"
	"sync"
)

// typeFieldPlans holds the immutable field plans for a type.
// These are built once via reflection and cached for reuse.
type typeFieldPlans struct {
	receive  receivePlan
	load     loadPlan
	store    storePlan
	send     sendPlan
	typeName string
}

var (
	plansCache   = make(map[reflect.Type]*typeFieldPlans)
	plansCacheMu sync.RWMutex
)

// getOrBuildPlans returns cached field plans or builds and caches them.
func getOrBuildPlans[T Cloner[T]]() (*typeFieldPlans, error) {
	typ := reflect.TypeFor[T]()

	// Fast path: read-lock cache check
	plansCacheMu.RLock()
	if cached, ok := plansCache[typ]; ok {
		plansCacheMu.RUnlock()
		return cached, nil
	}
	plansCacheMu.RUnlock()

	// Slow path: build and cache with write-lock
	plansCacheMu.Lock()
	defer plansCacheMu.Unlock()

	// Double-check pattern
	if cached, ok := plansCache[typ]; ok {
		return cached, nil
	}

	plans, err := buildFieldPlans[T]()
	if err != nil {
		return nil, err
	}

	plansCache[typ] = plans
	return plans, nil
}

// ResetPlansCache clears the field plans cache.
// This is primarily useful for test isolation.
func ResetPlansCache() {
	plansCacheMu.Lock()
	defer plansCacheMu.Unlock()
	plansCache = make(map[reflect.Type]*typeFieldPlans)
}
