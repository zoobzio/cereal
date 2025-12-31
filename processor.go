package codec

import (
	"encoding/base64"
	"fmt"
	"reflect"

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
type Processor[T Cloner[T]] struct {
	codec      Codec
	encryptors map[EncryptAlgo]Encryptor
	hashers    map[HashAlgo]Hasher
	maskers    map[MaskType]Masker

	// Per-context field plans
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

// ProcessorOption configures a Processor.
type ProcessorOption func(*processorConfig)

// processorConfig holds configuration for processor creation.
type processorConfig struct {
	encryptors map[EncryptAlgo]Encryptor
	hashers    map[HashAlgo]Hasher
	maskers    map[MaskType]Masker
}

func newProcessorConfig() *processorConfig {
	return &processorConfig{
		encryptors: make(map[EncryptAlgo]Encryptor),
		hashers:    builtinHashers(),
		maskers:    builtinMaskers(),
	}
}

// WithKey registers an encryption key for the given algorithm.
// This creates the appropriate encryptor based on the algorithm.
func WithKey(algo EncryptAlgo, key []byte) ProcessorOption {
	return func(cfg *processorConfig) {
		var enc Encryptor
		var err error

		switch algo {
		case EncryptAES:
			enc, err = AES(key)
		case EncryptEnvelope:
			enc, err = Envelope(key)
		default:
			// RSA requires key pair, not raw bytes
			return
		}

		if err == nil {
			cfg.encryptors[algo] = enc
		}
	}
}

// WithRSAKey registers an RSA key pair for encryption.
func WithRSAKey(pub interface{}, priv interface{}) ProcessorOption {
	return func(cfg *processorConfig) {
		// Type assertion for RSA keys
		// This accepts both *rsa.PublicKey and *rsa.PrivateKey
		var pubKey interface{}
		var privKey interface{}

		if pub != nil {
			pubKey = pub
		}
		if priv != nil {
			privKey = priv
		}

		// We need to import crypto/rsa, but to avoid circular deps,
		// we'll accept interface{} and let the RSA function handle it
		// For now, this is a placeholder - users should use WithEncryptor directly
		_ = pubKey
		_ = privKey
	}
}

// WithProcessorEncryptor registers a custom encryptor for the given algorithm.
func WithProcessorEncryptor(algo EncryptAlgo, enc Encryptor) ProcessorOption {
	return func(cfg *processorConfig) {
		cfg.encryptors[algo] = enc
	}
}

// WithHasher registers a custom hasher for the given algorithm.
func WithHasher(algo HashAlgo, h Hasher) ProcessorOption {
	return func(cfg *processorConfig) {
		cfg.hashers[algo] = h
	}
}

// WithMasker registers a custom masker for the given type.
func WithMasker(mt MaskType, m Masker) ProcessorOption {
	return func(cfg *processorConfig) {
		cfg.maskers[mt] = m
	}
}

// NewProcessor creates a new Processor for type T.
// Returns an error if required capabilities are not registered.
func NewProcessor[T Cloner[T]](codec Codec, opts ...ProcessorOption) (*Processor[T], error) {
	cfg := newProcessorConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	// Scan type metadata
	spec := sentinel.Scan[T]()

	p := &Processor[T]{
		codec:      codec,
		encryptors: cfg.encryptors,
		hashers:    cfg.hashers,
		maskers:    cfg.maskers,
		typeName:   spec.TypeName,
	}

	// Build field plans
	if err := p.buildFieldPlans(spec, nil, nil, ""); err != nil {
		return nil, err
	}

	// Validate all required capabilities are registered
	if err := p.validateCapabilities(); err != nil {
		return nil, err
	}

	return p, nil
}

// buildFieldPlans recursively processes fields and nested structs.
func (p *Processor[T]) buildFieldPlans(spec sentinel.Metadata, parentIndex, ptrIndices []int, namePrefix string) error {
	for _, field := range spec.Fields {
		fullIndex := append(append([]int{}, parentIndex...), field.Index...)
		fullName := field.Name
		if namePrefix != "" {
			fullName = namePrefix + "." + field.Name
		}

		// Handle nested structs
		if field.Kind == sentinel.KindStruct {
			nestedSpec := p.scanNestedType(field.ReflectType)
			if nestedSpec != nil {
				if err := p.buildFieldPlans(*nestedSpec, fullIndex, ptrIndices, fullName); err != nil {
					return err
				}
			}
			continue
		}

		// Handle pointer to struct
		if field.Kind == sentinel.KindPointer && field.ReflectType.Elem().Kind() == reflect.Struct {
			nestedSpec := p.scanNestedType(field.ReflectType.Elem())
			if nestedSpec != nil {
				newPtrIndices := append(append([]int{}, ptrIndices...), len(fullIndex)-1)
				if err := p.buildFieldPlans(*nestedSpec, fullIndex, newPtrIndices, fullName); err != nil {
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
			p.receivePlans.hashFields = append(p.receivePlans.hashFields, plan)
		}

		if val, ok := field.Tags["load.decrypt"]; ok {
			if !IsValidEncryptAlgo(EncryptAlgo(val)) {
				return fmt.Errorf("invalid encryption algorithm %q for field %s", val, fullName)
			}
			plan := basePlan
			plan.tagVal = val
			p.loadPlans.decryptFields = append(p.loadPlans.decryptFields, plan)
		}

		if val, ok := field.Tags["store.encrypt"]; ok {
			if !IsValidEncryptAlgo(EncryptAlgo(val)) {
				return fmt.Errorf("invalid encryption algorithm %q for field %s", val, fullName)
			}
			plan := basePlan
			plan.tagVal = val
			p.storePlans.encryptFields = append(p.storePlans.encryptFields, plan)
		}

		if val, ok := field.Tags["send.mask"]; ok {
			if !IsValidMaskType(MaskType(val)) {
				return fmt.Errorf("invalid mask type %q for field %s", val, fullName)
			}
			plan := basePlan
			plan.tagVal = val
			p.sendPlans.maskFields = append(p.sendPlans.maskFields, plan)
		}

		if val, ok := field.Tags["send.redact"]; ok {
			// Redact values are arbitrary strings, no validation needed
			plan := basePlan
			plan.tagVal = val
			p.sendPlans.redactFields = append(p.sendPlans.redactFields, plan)
		}
	}

	return nil
}

// scanNestedType scans a nested struct type and returns its metadata.
func (p *Processor[T]) scanNestedType(rt reflect.Type) *sentinel.Metadata {
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
			Tags:        p.parseContextTags(sf.Tag),
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
func (p *Processor[T]) parseContextTags(tag reflect.StructTag) map[string]string {
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
func (p *Processor[T]) validateCapabilities() error {
	// Validate hashers
	for _, plan := range p.receivePlans.hashFields {
		algo := HashAlgo(plan.tagVal)
		if _, ok := p.hashers[algo]; !ok {
			return fmt.Errorf("missing hasher for algorithm %q (field %s)", plan.tagVal, plan.name)
		}
	}

	// Validate decryptors
	for _, plan := range p.loadPlans.decryptFields {
		algo := EncryptAlgo(plan.tagVal)
		if _, ok := p.encryptors[algo]; !ok {
			return fmt.Errorf("missing encryptor for algorithm %q (field %s)", plan.tagVal, plan.name)
		}
	}

	// Validate encryptors
	for _, plan := range p.storePlans.encryptFields {
		algo := EncryptAlgo(plan.tagVal)
		if _, ok := p.encryptors[algo]; !ok {
			return fmt.Errorf("missing encryptor for algorithm %q (field %s)", plan.tagVal, plan.name)
		}
	}

	// Validate maskers
	for _, plan := range p.sendPlans.maskFields {
		mt := MaskType(plan.tagVal)
		if _, ok := p.maskers[mt]; !ok {
			return fmt.Errorf("missing masker for type %q (field %s)", plan.tagVal, plan.name)
		}
	}

	return nil
}

// Receive unmarshals data and applies receive context actions (hash).
// Use for data coming from external sources (API requests, events).
func (p *Processor[T]) Receive(data []byte) (*T, error) {
	var obj T
	if err := p.codec.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	// Check for override interface
	if h, ok := any(&obj).(Hashable); ok {
		if err := h.Hash(p.hashers); err != nil {
			return nil, fmt.Errorf("hash: %w", err)
		}
		return &obj, nil
	}

	// Apply hash actions via reflection
	if err := p.applyHash(&obj); err != nil {
		return nil, fmt.Errorf("hash: %w", err)
	}

	return &obj, nil
}

// Load unmarshals data and applies load context actions (decrypt).
// Use for data coming from storage (database, cache).
func (p *Processor[T]) Load(data []byte) (*T, error) {
	var obj T
	if err := p.codec.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	// Check for override interface
	if d, ok := any(&obj).(Decryptable); ok {
		if err := d.Decrypt(p.encryptors); err != nil {
			return nil, fmt.Errorf("decrypt: %w", err)
		}
		return &obj, nil
	}

	// Apply decrypt actions via reflection
	if err := p.applyDecrypt(&obj); err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return &obj, nil
}

// Store applies store context actions (encrypt) and marshals the result.
// Use for data going to storage (database, cache).
func (p *Processor[T]) Store(obj *T) ([]byte, error) {
	if obj == nil {
		return p.codec.Marshal(nil)
	}

	// Clone to avoid mutating original
	clone := (*obj).Clone()

	// Check for override interface
	if e, ok := any(&clone).(Encryptable); ok {
		if err := e.Encrypt(p.encryptors); err != nil {
			return nil, fmt.Errorf("encrypt: %w", err)
		}
		return p.codec.Marshal(&clone)
	}

	// Apply encrypt actions via reflection
	if err := p.applyEncrypt(&clone); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	return p.codec.Marshal(&clone)
}

// Send applies send context actions (mask, redact) and marshals the result.
// Use for data going to external destinations (API responses, events).
func (p *Processor[T]) Send(obj *T) ([]byte, error) {
	if obj == nil {
		return p.codec.Marshal(nil)
	}

	// Clone to avoid mutating original
	clone := (*obj).Clone()

	// Apply mask - check for override interface
	if m, ok := any(&clone).(Maskable); ok {
		if err := m.Mask(p.maskers); err != nil {
			return nil, fmt.Errorf("mask: %w", err)
		}
	} else {
		if err := p.applyMask(&clone); err != nil {
			return nil, fmt.Errorf("mask: %w", err)
		}
	}

	// Apply redact - check for override interface
	if r, ok := any(&clone).(Redactable); ok {
		if err := r.Redact(); err != nil {
			return nil, fmt.Errorf("redact: %w", err)
		}
	} else {
		if err := p.applyRedact(&clone); err != nil {
			return nil, fmt.Errorf("redact: %w", err)
		}
	}

	return p.codec.Marshal(&clone)
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
