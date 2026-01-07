package cereal

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/zoobzio/sentinel"
)

func init() {
	// Register compound tags with sentinel
	sentinel.Tag("receive.hash")
	sentinel.Tag("load.decrypt")
	sentinel.Tag("store.encrypt")
	sentinel.Tag("send.mask")
	sentinel.Tag("send.redact")
}

// Processor provides context-aware serialization with field transformation.
// Use Receive/Load for ingress and Store/Send for egress.
//
// Processors are safe for concurrent use. Configuration methods (SetEncryptor,
// SetHasher, SetMasker) may be called at any time to update or rotate keys.
//
// Validation occurs automatically on first operation. Configure all required
// handlers before the first call to Receive, Load, Store, or Send.
type Processor[T Cloner[T]] struct {
	codec Codec

	// Mutable configuration protected by mu
	mu         sync.RWMutex
	encryptors map[EncryptAlgo]Encryptor
	hashers    map[HashAlgo]Hasher
	maskers    map[MaskType]Masker

	// Validation state (runs once on first operation)
	validateOnce sync.Once
	validateErr  error

	// Per-context field plans (immutable after construction)
	receivePlans receivePlan
	loadPlans    loadPlan
	storePlans   storePlan
	sendPlans    sendPlan

	// Type metadata
	typeName string
}

// receivePlan holds field plans for receive context actions.
type receivePlan struct {
	hashFields []processorFieldPlan
}

// loadPlan holds field plans for load context actions.
type loadPlan struct {
	decryptFields []processorFieldPlan
}

// storePlan holds field plans for store context actions.
type storePlan struct {
	encryptFields []processorFieldPlan
}

// sendPlan holds field plans for send context actions.
type sendPlan struct {
	maskFields   []processorFieldPlan
	redactFields []processorFieldPlan
}

// processorFieldPlan describes how to transform a single field.
type processorFieldPlan struct {
	index      []int  // reflect.Value.FieldByIndex access path
	name       string // field name for error messages
	tagVal     string // tag value (e.g., "aes", "argon2", "ssn", "***")
	isBytes    bool   // true if field is []byte, false if string
	ptrIndices []int  // indices where pointer dereference is needed
	isSlice    bool   // true if field is []string
	isMap      bool   // true if field is map[K]string
}

// NewProcessor creates a new Processor for type T.
//
// The processor is created with builtin hashers and maskers. Encryptors must
// be configured via SetEncryptor before using Store/Load operations on fields
// with encryption tags.
//
// Use Validate() to check that all required capabilities are configured.
func NewProcessor[T Cloner[T]](codec Codec) (*Processor[T], error) {
	// Get or build cached field plans
	plans, err := getOrBuildPlans[T]()
	if err != nil {
		return nil, err
	}

	p := &Processor[T]{
		codec:        codec,
		encryptors:   make(map[EncryptAlgo]Encryptor),
		hashers:      builtinHashers(),
		maskers:      builtinMaskers(),
		typeName:     plans.typeName,
		receivePlans: plans.receive,
		loadPlans:    plans.load,
		storePlans:   plans.store,
		sendPlans:    plans.send,
	}

	emitProcessorCreated(context.Background(), codec.ContentType(), plans.typeName)
	return p, nil
}

// SetEncryptor registers an encryptor for the given algorithm.
// Returns the processor for chaining. Safe for concurrent use.
func (p *Processor[T]) SetEncryptor(algo EncryptAlgo, enc Encryptor) *Processor[T] {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.encryptors[algo] = enc
	return p
}

// SetHasher registers a hasher for the given algorithm.
// Returns the processor for chaining. Safe for concurrent use.
func (p *Processor[T]) SetHasher(algo HashAlgo, h Hasher) *Processor[T] {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hashers[algo] = h
	return p
}

// SetMasker registers a masker for the given type.
// Returns the processor for chaining. Safe for concurrent use.
func (p *Processor[T]) SetMasker(mt MaskType, m Masker) *Processor[T] {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maskers[mt] = m
	return p
}

// Validate checks that all required capabilities are configured.
// Returns an error if any field's required encryptor, hasher, or masker
// is not registered.
//
// Validation also runs automatically on first operation. Calling Validate
// explicitly allows catching configuration errors at startup.
func (p *Processor[T]) Validate() error {
	return p.ensureValidated()
}

// ensureValidated runs validation once and caches the result.
func (p *Processor[T]) ensureValidated() error {
	p.validateOnce.Do(func() {
		p.mu.RLock()
		defer p.mu.RUnlock()
		p.validateErr = p.validateCapabilities()
	})
	return p.validateErr
}

// buildFieldPlans creates field plans for type T by scanning struct tags.
func buildFieldPlans[T Cloner[T]]() (*typeFieldPlans, error) {
	spec := sentinel.Scan[T]()
	plans := &typeFieldPlans{
		typeName: spec.TypeName,
	}

	if err := buildFieldPlansRecursive(plans, spec, nil, nil, ""); err != nil {
		return nil, err
	}

	return plans, nil
}

// buildFieldPlansRecursive recursively processes fields and nested structs.
func buildFieldPlansRecursive(plans *typeFieldPlans, spec sentinel.Metadata, parentIndex, ptrIndices []int, namePrefix string) error {
	for _, field := range spec.Fields {
		fullIndex := append(append([]int{}, parentIndex...), field.Index...)
		fullName := field.Name
		if namePrefix != "" {
			fullName = namePrefix + "." + field.Name
		}

		// Handle nested structs
		if field.Kind == sentinel.KindStruct {
			nestedSpec := scanNestedType(field.ReflectType)
			if nestedSpec != nil {
				if err := buildFieldPlansRecursive(plans, *nestedSpec, fullIndex, ptrIndices, fullName); err != nil {
					return err
				}
			}
			continue
		}

		// Handle pointer to struct
		if field.Kind == sentinel.KindPointer && field.ReflectType.Elem().Kind() == reflect.Struct {
			nestedSpec := scanNestedType(field.ReflectType.Elem())
			if nestedSpec != nil {
				newPtrIndices := append(append([]int{}, ptrIndices...), len(fullIndex)-1)
				if err := buildFieldPlansRecursive(plans, *nestedSpec, fullIndex, newPtrIndices, fullName); err != nil {
					return err
				}
			}
			continue
		}

		// Check underlying kind for string, []byte, []string, or map[K]string fields
		isString := field.ReflectType.Kind() == reflect.String
		isBytes := field.ReflectType.Kind() == reflect.Slice &&
			field.ReflectType.Elem().Kind() == reflect.Uint8
		isStringSlice := field.ReflectType.Kind() == reflect.Slice &&
			field.ReflectType.Elem().Kind() == reflect.String
		isStringMap := field.ReflectType.Kind() == reflect.Map &&
			field.ReflectType.Elem().Kind() == reflect.String

		if !isString && !isBytes && !isStringSlice && !isStringMap {
			continue
		}

		basePlan := processorFieldPlan{
			index:      fullIndex,
			name:       fullName,
			isBytes:    isBytes,
			ptrIndices: ptrIndices,
			isSlice:    isStringSlice,
			isMap:      isStringMap,
		}

		// Check for compound tags
		if val, ok := field.Tags["receive.hash"]; ok {
			if !IsValidHashAlgo(HashAlgo(val)) {
				return fmt.Errorf("invalid hash algorithm %q for field %s", val, fullName)
			}
			plan := basePlan
			plan.tagVal = val
			plans.receive.hashFields = append(plans.receive.hashFields, plan)
		}

		if val, ok := field.Tags["load.decrypt"]; ok {
			if !IsValidEncryptAlgo(EncryptAlgo(val)) {
				return fmt.Errorf("invalid encryption algorithm %q for field %s", val, fullName)
			}
			plan := basePlan
			plan.tagVal = val
			plans.load.decryptFields = append(plans.load.decryptFields, plan)
		}

		if val, ok := field.Tags["store.encrypt"]; ok {
			if !IsValidEncryptAlgo(EncryptAlgo(val)) {
				return fmt.Errorf("invalid encryption algorithm %q for field %s", val, fullName)
			}
			plan := basePlan
			plan.tagVal = val
			plans.store.encryptFields = append(plans.store.encryptFields, plan)
		}

		if val, ok := field.Tags["send.mask"]; ok {
			if !IsValidMaskType(MaskType(val)) {
				return fmt.Errorf("invalid mask type %q for field %s", val, fullName)
			}
			plan := basePlan
			plan.tagVal = val
			plans.send.maskFields = append(plans.send.maskFields, plan)
		}

		if val, ok := field.Tags["send.redact"]; ok {
			// Redact values are arbitrary strings, no validation needed
			plan := basePlan
			plan.tagVal = val
			plans.send.redactFields = append(plans.send.redactFields, plan)
		}
	}

	return nil
}

// scanNestedType scans a nested struct type and returns its metadata.
func scanNestedType(rt reflect.Type) *sentinel.Metadata {
	if spec, ok := sentinel.Lookup(rt.String()); ok {
		return &spec
	}

	if rt.Kind() != reflect.Struct {
		return nil
	}

	spec := sentinel.Metadata{
		TypeName:    rt.Name(),
		PackageName: rt.PkgPath(),
		Fields:      make([]sentinel.FieldMetadata, 0, rt.NumField()),
	}

	for i := 0; i < rt.NumField(); i++ {
		sf := rt.Field(i)
		if !sf.IsExported() {
			continue
		}

		fm := sentinel.FieldMetadata{
			Name:        sf.Name,
			Type:        sf.Type.String(),
			ReflectType: sf.Type,
			Index:       sf.Index,
			Tags:        parseContextTags(sf.Tag),
		}

		switch sf.Type.Kind() {
		case reflect.Struct:
			fm.Kind = sentinel.KindStruct
		case reflect.Ptr:
			fm.Kind = sentinel.KindPointer
		case reflect.Slice, reflect.Array:
			fm.Kind = sentinel.KindSlice
		case reflect.Map:
			fm.Kind = sentinel.KindMap
		case reflect.Interface:
			fm.Kind = sentinel.KindInterface
		default:
			fm.Kind = sentinel.KindScalar
		}

		spec.Fields = append(spec.Fields, fm)
	}

	return &spec
}

// parseContextTags extracts context.action tags from a struct tag.
func parseContextTags(tag reflect.StructTag) map[string]string {
	tags := make(map[string]string)
	contextActions := []string{
		"receive.hash",
		"load.decrypt",
		"store.encrypt",
		"send.mask",
		"send.redact",
	}

	for _, ca := range contextActions {
		if val, ok := tag.Lookup(ca); ok {
			tags[ca] = val
		}
	}

	return tags
}

// validateCapabilities ensures all required capabilities are registered.
// Skips validation for transform types where the type implements override interfaces.
func (p *Processor[T]) validateCapabilities() error {
	// Check which override interfaces are implemented
	var zero T
	_, hasHashable := any(&zero).(Hashable)
	_, hasDecryptable := any(&zero).(Decryptable)
	_, hasEncryptable := any(&zero).(Encryptable)
	_, hasMaskable := any(&zero).(Maskable)

	// Validate hashers (skip if Hashable implemented)
	if !hasHashable {
		for _, plan := range p.receivePlans.hashFields {
			algo := HashAlgo(plan.tagVal)
			if _, ok := p.hashers[algo]; !ok {
				return fmt.Errorf("missing hasher for algorithm %q (field %s)", plan.tagVal, plan.name)
			}
		}
	}

	// Validate decryptors (skip if Decryptable implemented)
	if !hasDecryptable {
		for _, plan := range p.loadPlans.decryptFields {
			algo := EncryptAlgo(plan.tagVal)
			if _, ok := p.encryptors[algo]; !ok {
				return fmt.Errorf("missing encryptor for algorithm %q (field %s)", plan.tagVal, plan.name)
			}
		}
	}

	// Validate encryptors (skip if Encryptable implemented)
	if !hasEncryptable {
		for _, plan := range p.storePlans.encryptFields {
			algo := EncryptAlgo(plan.tagVal)
			if _, ok := p.encryptors[algo]; !ok {
				return fmt.Errorf("missing encryptor for algorithm %q (field %s)", plan.tagVal, plan.name)
			}
		}
	}

	// Validate maskers (skip if Maskable implemented)
	if !hasMaskable {
		for _, plan := range p.sendPlans.maskFields {
			mt := MaskType(plan.tagVal)
			if _, ok := p.maskers[mt]; !ok {
				return fmt.Errorf("missing masker for type %q (field %s)", plan.tagVal, plan.name)
			}
		}
	}

	return nil
}

// Receive unmarshals data and applies receive context actions (hash).
// Use for data coming from external sources (API requests, events).
//
//nolint:dupl // Intentional parallel structure with Load for boundary operations
func (p *Processor[T]) Receive(ctx context.Context, data []byte) (*T, error) {
	if err := p.ensureValidated(); err != nil {
		return nil, err
	}

	start := time.Now()
	emitReceiveStart(ctx, p.codec.ContentType(), p.typeName)

	var retErr error
	defer func() {
		emitReceiveComplete(ctx, p.codec.ContentType(), p.typeName,
			time.Since(start), len(p.receivePlans.hashFields), retErr)
	}()

	var obj T
	if err := p.codec.Unmarshal(data, &obj); err != nil {
		retErr = fmt.Errorf("unmarshal: %w", err)
		return nil, retErr
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	// Check for override interface
	if h, ok := any(&obj).(Hashable); ok {
		if err := h.Hash(p.hashers); err != nil {
			retErr = fmt.Errorf("hash: %w", err)
			return nil, retErr
		}
		return &obj, nil
	}

	// Apply hash actions via reflection
	if err := p.applyHash(&obj); err != nil {
		retErr = fmt.Errorf("hash: %w", err)
		return nil, retErr
	}

	return &obj, nil
}

// Load unmarshals data and applies load context actions (decrypt).
// Use for data coming from storage (database, cache).
//
//nolint:dupl // Intentional parallel structure with Receive for boundary operations
func (p *Processor[T]) Load(ctx context.Context, data []byte) (*T, error) {
	if err := p.ensureValidated(); err != nil {
		return nil, err
	}

	start := time.Now()
	emitLoadStart(ctx, p.codec.ContentType(), p.typeName)

	var retErr error
	defer func() {
		emitLoadComplete(ctx, p.codec.ContentType(), p.typeName,
			time.Since(start), len(p.loadPlans.decryptFields), retErr)
	}()

	var obj T
	if err := p.codec.Unmarshal(data, &obj); err != nil {
		retErr = fmt.Errorf("unmarshal: %w", err)
		return nil, retErr
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	// Check for override interface
	if d, ok := any(&obj).(Decryptable); ok {
		if err := d.Decrypt(p.encryptors); err != nil {
			retErr = fmt.Errorf("decrypt: %w", err)
			return nil, retErr
		}
		return &obj, nil
	}

	// Apply decrypt actions via reflection
	if err := p.applyDecrypt(&obj); err != nil {
		retErr = fmt.Errorf("decrypt: %w", err)
		return nil, retErr
	}

	return &obj, nil
}

// Store applies store context actions (encrypt) and marshals the result.
// Use for data going to storage (database, cache).
func (p *Processor[T]) Store(ctx context.Context, obj *T) ([]byte, error) {
	if err := p.ensureValidated(); err != nil {
		return nil, err
	}

	start := time.Now()
	emitStoreStart(ctx, p.codec.ContentType(), p.typeName)

	var retErr error
	var retData []byte
	defer func() {
		emitStoreComplete(ctx, p.codec.ContentType(), p.typeName,
			len(retData), time.Since(start), len(p.storePlans.encryptFields), retErr)
	}()

	if obj == nil {
		retData, retErr = p.codec.Marshal(nil)
		return retData, retErr
	}

	// Clone to avoid mutating original
	clone := (*obj).Clone()

	p.mu.RLock()
	defer p.mu.RUnlock()

	// Check for override interface
	if e, ok := any(&clone).(Encryptable); ok {
		if err := e.Encrypt(p.encryptors); err != nil {
			retErr = fmt.Errorf("encrypt: %w", err)
			return nil, retErr
		}
		retData, retErr = p.codec.Marshal(&clone)
		return retData, retErr
	}

	// Apply encrypt actions via reflection
	if err := p.applyEncrypt(&clone); err != nil {
		retErr = fmt.Errorf("encrypt: %w", err)
		return nil, retErr
	}

	retData, retErr = p.codec.Marshal(&clone)
	return retData, retErr
}

// Send applies send context actions (mask, redact) and marshals the result.
// Use for data going to external destinations (API responses, events).
func (p *Processor[T]) Send(ctx context.Context, obj *T) ([]byte, error) {
	if err := p.ensureValidated(); err != nil {
		return nil, err
	}

	start := time.Now()
	emitSendStart(ctx, p.codec.ContentType(), p.typeName)

	var retErr error
	var retData []byte
	defer func() {
		emitSendComplete(ctx, p.codec.ContentType(), p.typeName,
			len(retData), time.Since(start),
			len(p.sendPlans.maskFields), len(p.sendPlans.redactFields), retErr)
	}()

	if obj == nil {
		retData, retErr = p.codec.Marshal(nil)
		return retData, retErr
	}

	// Clone to avoid mutating original
	clone := (*obj).Clone()

	p.mu.RLock()
	defer p.mu.RUnlock()

	// Apply mask - check for override interface
	if m, ok := any(&clone).(Maskable); ok {
		if err := m.Mask(p.maskers); err != nil {
			retErr = fmt.Errorf("mask: %w", err)
			return nil, retErr
		}
	} else {
		if err := p.applyMask(&clone); err != nil {
			retErr = fmt.Errorf("mask: %w", err)
			return nil, retErr
		}
	}

	// Apply redact - check for override interface
	if r, ok := any(&clone).(Redactable); ok {
		if err := r.Redact(); err != nil {
			retErr = fmt.Errorf("redact: %w", err)
			return nil, retErr
		}
	} else {
		if err := p.applyRedact(&clone); err != nil {
			retErr = fmt.Errorf("redact: %w", err)
			return nil, retErr
		}
	}

	retData, retErr = p.codec.Marshal(&clone)
	return retData, retErr
}

// applyHash applies hash transformations via reflection.
func (p *Processor[T]) applyHash(obj *T) error {
	rv := reflect.ValueOf(obj).Elem()

	for _, plan := range p.receivePlans.hashFields {
		hasher := p.hashers[HashAlgo(plan.tagVal)]

		field, ok := p.getField(rv, plan)
		if !ok {
			continue
		}

		// Handle slice of strings
		if plan.isSlice {
			for i := 0; i < field.Len(); i++ {
				elem := field.Index(i)
				if elem.CanSet() {
					hashed, err := hasher.Hash([]byte(elem.String()))
					if err != nil {
						return fmt.Errorf("hash field %s[%d]: %w", plan.name, i, err)
					}
					elem.SetString(hashed)
				}
			}
			continue
		}

		// Handle map of strings
		if plan.isMap {
			iter := field.MapRange()
			for iter.Next() {
				k, v := iter.Key(), iter.Value()
				hashed, err := hasher.Hash([]byte(v.String()))
				if err != nil {
					return fmt.Errorf("hash field %s[%v]: %w", plan.name, k.Interface(), err)
				}
				field.SetMapIndex(k, reflect.ValueOf(hashed))
			}
			continue
		}

		// Handle scalar string or []byte
		if !field.CanSet() {
			continue
		}

		var plaintext []byte
		if plan.isBytes {
			plaintext = field.Bytes()
		} else {
			plaintext = []byte(field.String())
		}

		hashed, err := hasher.Hash(plaintext)
		if err != nil {
			return fmt.Errorf("hash field %s: %w", plan.name, err)
		}

		if plan.isBytes {
			field.SetBytes([]byte(hashed))
		} else {
			field.SetString(hashed)
		}
	}

	return nil
}

// applyDecrypt applies decrypt transformations via reflection.
func (p *Processor[T]) applyDecrypt(obj *T) error {
	rv := reflect.ValueOf(obj).Elem()

	for _, plan := range p.loadPlans.decryptFields {
		enc := p.encryptors[EncryptAlgo(plan.tagVal)]

		field, ok := p.getField(rv, plan)
		if !ok {
			continue
		}

		// Handle slice of strings
		if plan.isSlice {
			for i := 0; i < field.Len(); i++ {
				elem := field.Index(i)
				if elem.CanSet() {
					ciphertext, err := base64.StdEncoding.DecodeString(elem.String())
					if err != nil {
						return fmt.Errorf("base64 decode field %s[%d]: %w", plan.name, i, err)
					}
					plaintext, err := enc.Decrypt(ciphertext)
					if err != nil {
						return fmt.Errorf("decrypt field %s[%d]: %w", plan.name, i, err)
					}
					elem.SetString(string(plaintext))
				}
			}
			continue
		}

		// Handle map of strings
		if plan.isMap {
			iter := field.MapRange()
			for iter.Next() {
				k, v := iter.Key(), iter.Value()
				ciphertext, err := base64.StdEncoding.DecodeString(v.String())
				if err != nil {
					return fmt.Errorf("base64 decode field %s[%v]: %w", plan.name, k.Interface(), err)
				}
				plaintext, err := enc.Decrypt(ciphertext)
				if err != nil {
					return fmt.Errorf("decrypt field %s[%v]: %w", plan.name, k.Interface(), err)
				}
				field.SetMapIndex(k, reflect.ValueOf(string(plaintext)))
			}
			continue
		}

		// Handle scalar string or []byte
		if !field.CanSet() {
			continue
		}

		var ciphertext []byte
		var err error

		if plan.isBytes {
			ciphertext = field.Bytes()
		} else {
			ciphertext, err = base64.StdEncoding.DecodeString(field.String())
			if err != nil {
				return fmt.Errorf("base64 decode field %s: %w", plan.name, err)
			}
		}

		plaintext, err := enc.Decrypt(ciphertext)
		if err != nil {
			return fmt.Errorf("decrypt field %s: %w", plan.name, err)
		}

		if plan.isBytes {
			field.SetBytes(plaintext)
		} else {
			field.SetString(string(plaintext))
		}
	}

	return nil
}

// applyEncrypt applies encrypt transformations via reflection.
func (p *Processor[T]) applyEncrypt(obj *T) error {
	rv := reflect.ValueOf(obj).Elem()

	for _, plan := range p.storePlans.encryptFields {
		enc := p.encryptors[EncryptAlgo(plan.tagVal)]

		field, ok := p.getField(rv, plan)
		if !ok {
			continue
		}

		// Handle slice of strings
		if plan.isSlice {
			for i := 0; i < field.Len(); i++ {
				elem := field.Index(i)
				if elem.CanSet() {
					ciphertext, err := enc.Encrypt([]byte(elem.String()))
					if err != nil {
						return fmt.Errorf("encrypt field %s[%d]: %w", plan.name, i, err)
					}
					elem.SetString(base64.StdEncoding.EncodeToString(ciphertext))
				}
			}
			continue
		}

		// Handle map of strings
		if plan.isMap {
			iter := field.MapRange()
			for iter.Next() {
				k, v := iter.Key(), iter.Value()
				ciphertext, err := enc.Encrypt([]byte(v.String()))
				if err != nil {
					return fmt.Errorf("encrypt field %s[%v]: %w", plan.name, k.Interface(), err)
				}
				field.SetMapIndex(k, reflect.ValueOf(base64.StdEncoding.EncodeToString(ciphertext)))
			}
			continue
		}

		// Handle scalar string or []byte
		if !field.CanSet() {
			continue
		}

		var plaintext []byte
		if plan.isBytes {
			plaintext = field.Bytes()
		} else {
			plaintext = []byte(field.String())
		}

		ciphertext, err := enc.Encrypt(plaintext)
		if err != nil {
			return fmt.Errorf("encrypt field %s: %w", plan.name, err)
		}

		if plan.isBytes {
			field.SetBytes(ciphertext)
		} else {
			field.SetString(base64.StdEncoding.EncodeToString(ciphertext))
		}
	}

	return nil
}

// applyMask applies mask transformations via reflection.
func (p *Processor[T]) applyMask(obj *T) error {
	rv := reflect.ValueOf(obj).Elem()

	for _, plan := range p.sendPlans.maskFields {
		masker := p.maskers[MaskType(plan.tagVal)]

		field, ok := p.getField(rv, plan)
		if !ok {
			continue
		}

		// Handle slice of strings
		if plan.isSlice {
			for i := 0; i < field.Len(); i++ {
				elem := field.Index(i)
				if elem.CanSet() {
					elem.SetString(masker.Mask(elem.String()))
				}
			}
			continue
		}

		// Handle map of strings
		if plan.isMap {
			iter := field.MapRange()
			for iter.Next() {
				k, v := iter.Key(), iter.Value()
				field.SetMapIndex(k, reflect.ValueOf(masker.Mask(v.String())))
			}
			continue
		}

		// Handle scalar string or []byte
		if !field.CanSet() {
			continue
		}

		var value string
		if plan.isBytes {
			value = string(field.Bytes())
		} else {
			value = field.String()
		}

		masked := masker.Mask(value)

		if plan.isBytes {
			field.SetBytes([]byte(masked))
		} else {
			field.SetString(masked)
		}
	}

	return nil
}

// applyRedact applies redact transformations via reflection.
func (p *Processor[T]) applyRedact(obj *T) error {
	rv := reflect.ValueOf(obj).Elem()

	for _, plan := range p.sendPlans.redactFields {
		field, ok := p.getField(rv, plan)
		if !ok {
			continue
		}

		// Handle slice of strings
		if plan.isSlice {
			for i := 0; i < field.Len(); i++ {
				elem := field.Index(i)
				if elem.CanSet() {
					elem.SetString(plan.tagVal)
				}
			}
			continue
		}

		// Handle map of strings
		if plan.isMap {
			iter := field.MapRange()
			for iter.Next() {
				k := iter.Key()
				field.SetMapIndex(k, reflect.ValueOf(plan.tagVal))
			}
			continue
		}

		// Handle scalar string or []byte
		if !field.CanSet() {
			continue
		}

		if plan.isBytes {
			field.SetBytes([]byte(plan.tagVal))
		} else {
			field.SetString(plan.tagVal)
		}
	}

	return nil
}

// getField navigates a field path, dereferencing pointers as needed.
func (p *Processor[T]) getField(rv reflect.Value, plan processorFieldPlan) (reflect.Value, bool) {
	if len(plan.ptrIndices) == 0 {
		return rv.FieldByIndex(plan.index), true
	}

	current := rv
	ptrSet := make(map[int]bool, len(plan.ptrIndices))
	for _, idx := range plan.ptrIndices {
		ptrSet[idx] = true
	}

	for i, idx := range plan.index {
		current = current.Field(idx)

		if ptrSet[i] {
			if current.IsNil() {
				return reflect.Value{}, false
			}
			current = current.Elem()
		}
	}

	return current, true
}
