package ai

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"

	gguf_parser "github.com/gpustack/gguf-parser-go"
)

// GGUF file format constants
const (
	ggufMagicNumber = 0x46554747       // "GGUF" in little-endian
	maxHeaderSize   = 50 * 1024 * 1024 // 50MB for large tokenizer vocabularies

	// maxGGUFArrayDepth allows arrays of arrays but nothing deeper.
	maxGGUFArrayDepth = 2
	// maxGGUFDecodedItems bounds the items, across the whole header, of arrays that gguf-parser-go
	// always decodes in full. Real files hold a few per-layer arrays.
	maxGGUFDecodedItems = 65536
	// maxGGUFSplitTensors bounds split.tensors.count, which the library preallocates tensor infos for.
	// Shards declare the total across all splits, so this can't be the header tensor count.
	maxGGUFSplitTensors = 1 << 17
	// maxGGUFKeyLength is the key length limit from the GGUF spec.
	maxGGUFKeyLength = 65535
	// maxGGUFKVCount bounds the metadata KV count. Real files hold hundreds; vocabularies live in arrays.
	maxGGUFKVCount = 65536
	// maxGGUFReadStringBytes bounds, across the header, the key and string bytes the library reads in
	// full and syft then hashes and encodes (chat templates are the largest, at tens of KB).
	maxGGUFReadStringBytes = 8 << 20
	// maxGGUFSkippedStrings bounds, across the header, the strings the library skips one at a time
	// inside arrays (vocabularies run to a few hundred thousand tokens and merges).
	maxGGUFSkippedStrings = 1 << 22
)

// ggufDecodedArraySuffixes are the keys gguf-parser-go decodes in full even with SkipLargeMetadata
// (hardcoded in its ReadArray as of v0.26.3; re-check on upgrade).
var ggufDecodedArraySuffixes = []string{
	".feed_forward_length", ".attention.head_count", ".attention.head_count_kv", ".attention.sliding_window_pattern",
}

// ggufScalarSizes is the encoded size of each value type, indexed by type (0 for strings and arrays).
var ggufScalarSizes = [...]int{1, 1, 2, 2, 4, 4, 4, 1, 0, 0, 8, 8, 8}

// copyHeader copies at most maxHeaderSize bytes of the GGUF header from the reader to the writer.
// It validates the magic number first, then copies the rest of the data.
func copyHeader(w io.Writer, r io.Reader) error {
	r = io.LimitReader(r, maxHeaderSize)

	// Read initial chunk to validate magic number
	// GGUF format: magic(4) + version(4) + tensor_count(8) + metadata_kv_count(8) + metadata_kvs + tensors_info
	initialBuf := make([]byte, 24) // Enough for magic, version, tensor count, and kv count
	if _, err := io.ReadFull(r, initialBuf); err != nil {
		return fmt.Errorf("failed to read GGUF header prefix: %w", err)
	}

	// Verify magic number
	magic := binary.LittleEndian.Uint32(initialBuf[0:4])
	if magic != ggufMagicNumber {
		return fmt.Errorf("invalid GGUF magic number: 0x%08X", magic)
	}

	// Write the initial buffer to the writer
	if _, err := w.Write(initialBuf); err != nil {
		return fmt.Errorf("failed to write GGUF header prefix: %w", err)
	}

	// Copy the rest of the header from reader to writer
	if _, err := io.Copy(w, r); err != nil {
		return fmt.Errorf("failed to copy GGUF header: %w", err)
	}

	return nil
}

// validateGGUFHeader walks the metadata KV section and rejects values that gguf-parser-go would panic
// on, recurse on without bound, or overallocate for. It reads without storing anything.
// ponytail: tensor infos are not checked here (zero block size types, dimension overflow); those
// panics are recoverable and are left to the per-file panic recovery in the generic cataloger.
func validateGGUFHeader(r io.Reader) error {
	v := &ggufHeaderValidator{
		r:                   bufio.NewReader(r),
		decodedBudget:       maxGGUFDecodedItems,
		readStringBudget:    maxGGUFReadStringBytes,
		skippedStringBudget: maxGGUFSkippedStrings,
	}
	var prefix struct {
		Magic, Version uint32
	}
	if err := binary.Read(v.r, binary.LittleEndian, &prefix); err != nil {
		return fmt.Errorf("reading header prefix: %w", err)
	}
	v.v1 = prefix.Version <= 1
	// the tensor count is validated by the library
	if _, err := v.readLen(); err != nil {
		return fmt.Errorf("reading tensor count: %w", err)
	}
	kvCount, err := v.readLen()
	if err != nil {
		return fmt.Errorf("reading metadata count: %w", err)
	}
	if kvCount > maxGGUFKVCount {
		return fmt.Errorf("metadata count %d exceeds %d", kvCount, maxGGUFKVCount)
	}

	for i := uint64(0); i < kvCount; i++ {
		key, err := v.readKey()
		if err != nil {
			return fmt.Errorf("metadata key %d: %w", i, err)
		}
		var vt uint32
		if err := binary.Read(v.r, binary.LittleEndian, &vt); err != nil {
			return fmt.Errorf("metadata key %q: %w", key, err)
		}
		if err := v.checkKey(key, gguf_parser.GGUFMetadataValueType(vt)); err != nil {
			return fmt.Errorf("metadata key %q: %w", key, err)
		}
	}
	return nil
}

type ggufHeaderValidator struct {
	r                   *bufio.Reader
	v1                  bool // v1 uses 32-bit lengths
	decodedBudget       uint64
	readStringBudget    uint64
	skippedStringBudget uint64
}

func (v *ggufHeaderValidator) checkKey(key string, vt gguf_parser.GGUFMetadataValueType) error {
	decoded := slices.ContainsFunc(ggufDecodedArraySuffixes, func(s string) bool { return strings.HasSuffix(key, s) })
	n, err := v.readValue(vt, decoded, 1)
	if err != nil {
		return err
	}

	// these are read with typed accessors that panic on a type mismatch
	switch key {
	case "general.architecture", "general.name", "general.license", "general.type", "general.author",
		"general.url", "general.description", "controlvector.model_hint":
		if vt != gguf_parser.GGUFMetadataValueTypeString {
			return fmt.Errorf("expected string, got %v", vt)
		}
	case "general.quantization_version", "general.file_type":
		if !vt.IsNumeric() {
			return fmt.Errorf("expected number, got %v", vt)
		}
	case "general.alignment":
		if vt != gguf_parser.GGUFMetadataValueTypeUint32 || n == 0 {
			return fmt.Errorf("expected non-zero uint32, got %v %v", vt, n)
		}
	case "split.tensors.count":
		if !vt.IsNumeric() {
			return fmt.Errorf("expected number, got %v", vt)
		}
		if math.IsNaN(n) || n < 0 || n > maxGGUFSplitTensors {
			return fmt.Errorf("unreasonable split tensor count %.0f", n)
		}
	}
	return nil
}

// readValue consumes one value, returning scalar numbers as float64 for the key checks.
func (v *ggufHeaderValidator) readValue(vt gguf_parser.GGUFMetadataValueType, decoded bool, depth int) (float64, error) {
	if uint32(vt) >= uint32(len(ggufScalarSizes)) {
		return 0, fmt.Errorf("invalid value type %d", vt)
	}
	switch vt {
	case gguf_parser.GGUFMetadataValueTypeString:
		// only strings inside skipped arrays are skipped by the library, the rest are read in full
		return 0, v.skipString(depth > 1 && !decoded)
	case gguf_parser.GGUFMetadataValueTypeArray:
		return 0, v.readArray(decoded, depth)
	}
	size := ggufScalarSizes[vt]
	b, err := v.r.Peek(size)
	if err != nil {
		return 0, err
	}
	var buf [8]byte
	copy(buf[:], b)
	if _, err := v.r.Discard(size); err != nil {
		return 0, err
	}
	u := binary.LittleEndian.Uint64(buf[:])
	switch vt {
	case gguf_parser.GGUFMetadataValueTypeInt8:
		return float64(int8(u)), nil
	case gguf_parser.GGUFMetadataValueTypeInt16:
		return float64(int16(u)), nil
	case gguf_parser.GGUFMetadataValueTypeInt32:
		return float64(int32(u)), nil
	case gguf_parser.GGUFMetadataValueTypeInt64:
		return float64(int64(u)), nil
	case gguf_parser.GGUFMetadataValueTypeFloat32:
		return float64(math.Float32frombits(uint32(u))), nil
	case gguf_parser.GGUFMetadataValueTypeFloat64:
		return math.Float64frombits(u), nil
	}
	return float64(u), nil
}

func (v *ggufHeaderValidator) readArray(decoded bool, depth int) error {
	var itemType uint32
	if err := binary.Read(v.r, binary.LittleEndian, &itemType); err != nil {
		return err
	}
	n, err := v.readLen()
	if err != nil {
		return err
	}
	it := gguf_parser.GGUFMetadataValueType(itemType)
	switch {
	case itemType >= uint32(len(ggufScalarSizes)):
		return fmt.Errorf("invalid array item type %d", itemType)
	case decoded && n > v.decodedBudget:
		return fmt.Errorf("decoded arrays exceed %d items", maxGGUFDecodedItems)
	case it == gguf_parser.GGUFMetadataValueTypeArray && (!decoded || depth >= maxGGUFArrayDepth):
		// the library can only skip over arrays of scalars
		return errors.New("unsupported nested array")
	case n > maxHeaderSize:
		return fmt.Errorf("array length %d exceeds header size", n)
	case !decoded && ggufScalarSizes[itemType] > 0:
		// skipped arrays of fixed size items can be passed over in one go
		_, err := v.r.Discard(int(n) * ggufScalarSizes[itemType])
		return err
	}
	if decoded {
		v.decodedBudget -= n
	}
	for i := uint64(0); i < n; i++ {
		if _, err := v.readValue(it, decoded, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (v *ggufHeaderValidator) readLen() (uint64, error) {
	if v.v1 {
		var n uint32
		err := binary.Read(v.r, binary.LittleEndian, &n)
		return uint64(n), err
	}
	var n uint64
	err := binary.Read(v.r, binary.LittleEndian, &n)
	return n, err
}

// readKey reads a key the way gguf-parser-go will see it, whitespace trimmed.
func (v *ggufHeaderValidator) readKey() (string, error) {
	n, err := v.readLen()
	if err != nil {
		return "", err
	}
	if n == 0 || n > maxGGUFKeyLength {
		return "", fmt.Errorf("invalid key length %d", n)
	}
	if err := v.spendReadString(n); err != nil {
		return "", err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(v.r, buf); err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf)), nil
}

func (v *ggufHeaderValidator) skipString(allowEmpty bool) error {
	n, err := v.readLen()
	if err != nil {
		return err
	}
	// gguf-parser-go reads an empty string as a full pool buffer, so everything after it would be
	// parsed out of step with this walk
	if n == 0 && !allowEmpty {
		return errors.New("empty string")
	}
	if n > maxHeaderSize {
		return fmt.Errorf("string length %d exceeds header size", n)
	}
	if allowEmpty {
		if v.skippedStringBudget == 0 {
			return fmt.Errorf("skipped strings exceed %d", maxGGUFSkippedStrings)
		}
		v.skippedStringBudget--
	} else if err := v.spendReadString(n); err != nil {
		return err
	}
	_, err = v.r.Discard(int(n))
	return err
}

func (v *ggufHeaderValidator) spendReadString(n uint64) error {
	if n > v.readStringBudget {
		return fmt.Errorf("strings exceed %d bytes", maxGGUFReadStringBytes)
	}
	v.readStringBudget -= n
	return nil
}

// sanitizeGGUFValue replaces non-finite floats, which JSON can not encode, leaving everything else as is.
func sanitizeGGUFValue(v any) any {
	switch t := v.(type) {
	case float32:
		if f := float64(t); math.IsNaN(f) || math.IsInf(f, 0) {
			return nonFiniteString(f)
		}
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return nonFiniteString(t)
		}
	case gguf_parser.GGUFMetadataKVArrayValue:
		// keep the library shape as is; items are only present for the few keys the library
		// decodes in full, which the pre-scan keeps small and shallow
		if len(t.Array) > 0 {
			items := make([]any, len(t.Array))
			for i, item := range t.Array {
				items[i] = sanitizeGGUFValue(item)
			}
			t.Array = items
		}
		return t
	}
	return v
}

func nonFiniteString(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	}
	return "NaN"
}

// helper to convert gguf_parser metadata to simpler types
func convertGGUFMetadataKVs(kvs gguf_parser.GGUFMetadataKVs) map[string]any {
	result := make(map[string]any)

	for _, kv := range kvs {
		// Skip standard fields that are extracted separately
		switch kv.Key {
		case "general.architecture", "general.name", "general.license",
			"general.version", "general.parameter_count", "general.quantization":
			continue
		}
		result[kv.Key] = sanitizeGGUFValue(kv.Value)
	}

	return result
}
