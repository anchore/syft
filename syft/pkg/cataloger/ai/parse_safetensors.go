package ai

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/bits"
	"sort"
	"strings"

	"github.com/cespare/xxhash/v2"

	"github.com/anchore/syft/syft/pkg"
)

// SafeTensors file format: [8 bytes u64 LE header size] [N bytes JSON header] [tensor data].
// Reference: https://github.com/huggingface/safetensors#format
// The header JSON is capped at maxSafeTensorsHeaderSize (see limits.go).

// safeTensorsHeader is the decoded JSON header. Tensor entries live alongside a
// reserved "__metadata__" key holding a string-to-string producer map. We decode
// tensor entries into a generic map so we can iterate and count without a fixed
// schema for every field.
type safeTensorsHeader struct {
	metadata map[string]string
	tensors  map[string]safeTensorsEntry
}

// safeTensorsEntry describes a single tensor within the header JSON.
type safeTensorsEntry struct {
	DType       string  `json:"dtype"`
	Shape       []int64 `json:"shape"`
	DataOffsets []int64 `json:"data_offsets"`
}

// readSafeTensorsHeader reads and parses the JSON header from a .safetensors
// file (the leading `[8-byte LE length] [length bytes of JSON]` block) and
// returns the decoded header.
func readSafeTensorsHeader(r io.Reader) (*safeTensorsHeader, error) {
	var lenBuf [8]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to read header length: %w", err)
	}
	headerLen := binary.LittleEndian.Uint64(lenBuf[:])
	if headerLen == 0 {
		return nil, fmt.Errorf("safetensors header length is zero")
	}
	if headerLen > maxSafeTensorsHeaderSize {
		return nil, fmt.Errorf("safetensors header size %d exceeds maximum %d", headerLen, maxSafeTensorsHeaderSize)
	}

	// Read incrementally rather than pre-allocating headerLen up front
	body, err := io.ReadAll(io.LimitReader(r, int64(headerLen)))
	if err != nil {
		return nil, fmt.Errorf("failed to read header body: %w", err)
	}
	if uint64(len(body)) != headerLen {
		return nil, fmt.Errorf("safetensors header truncated: read %d of %d bytes", len(body), headerLen)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to decode safetensors header JSON: %w", err)
	}

	h := &safeTensorsHeader{tensors: make(map[string]safeTensorsEntry, len(raw))}
	for key, val := range raw {
		if key == "__metadata__" {
			if err := json.Unmarshal(val, &h.metadata); err != nil {
				return nil, fmt.Errorf("failed to decode __metadata__: %w", err)
			}
			continue
		}
		var entry safeTensorsEntry
		if err := json.Unmarshal(val, &entry); err != nil {
			// Not all entries must conform; skip anything we cannot decode rather than fail.
			continue
		}
		h.tensors[key] = entry
	}

	return h, nil
}

// modelInfo returns the metadata derivable from the header bytes alone. Naming,
// licenses and ShardCount are left to the merge processor.
func (h *safeTensorsHeader) modelInfo() pkg.SafeTensorsModelInfo {
	params, dtype := h.parameterStats()
	return pkg.SafeTensorsModelInfo{
		Format:       "safetensors",
		TensorCount:  uint64(len(h.tensors)),
		Parameters:   params,
		Quantization: normalizeDType(dtype),
		UserMetadata: userMetadataKeyValues(h.metadata),
		MetadataHash: h.metadataHash(),
	}
}

// parameterStats sums the element counts across all tensors and returns the
// dtype that accounts for the largest share of them. For mixed-precision models
// the "dominant" dtype is still a useful summary. Totals saturate rather than wrap.
func (h *safeTensorsHeader) parameterStats() (total uint64, dominantDType string) {
	sizeByDType := make(map[string]uint64)
	for _, t := range h.tensors {
		count, ok := tensorElements(t.Shape)
		if !ok {
			continue
		}
		total = saturatingAdd(total, count)
		sizeByDType[t.DType] = saturatingAdd(sizeByDType[t.DType], count)
	}
	var bestSize uint64
	for dtype, size := range sizeByDType {
		if size > bestSize || (size == bestSize && dtype < dominantDType) {
			dominantDType = dtype
			bestSize = size
		}
	}
	return total, dominantDType
}

// tensorElements returns the element count for a shape, or ok=false on a
// non-positive dim or when the product overflows uint64.
func tensorElements(shape []int64) (uint64, bool) {
	n := uint64(1)
	for _, d := range shape {
		if d <= 0 {
			return 0, false
		}
		hi, lo := bits.Mul64(n, uint64(d))
		if hi != 0 {
			return 0, false
		}
		n = lo
	}
	return n, true
}

// saturatingAdd returns a+b, clamped to math.MaxUint64 instead of wrapping.
func saturatingAdd(a, b uint64) uint64 {
	sum, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return math.MaxUint64
	}
	return sum
}

// metadataHash returns a stable xxhash64 over the logical tensor content
// (name + dtype + shape) plus the __metadata__ map. Tensor keys are sorted to
// keep the hash deterministic across producers.
func (h *safeTensorsHeader) metadataHash() string {
	type logicalEntry struct {
		Name  string  `json:"name"`
		DType string  `json:"dtype"`
		Shape []int64 `json:"shape"`
	}
	entries := make([]logicalEntry, 0, len(h.tensors))
	for name, t := range h.tensors {
		entries = append(entries, logicalEntry{Name: name, DType: t.DType, Shape: t.Shape})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	type hashInput struct {
		Tensors  []logicalEntry    `json:"tensors"`
		Metadata map[string]string `json:"metadata,omitempty"`
	}
	b, err := json.Marshal(hashInput{Tensors: entries, Metadata: h.metadata})
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%016x", xxhash.Sum64(b))
}

// userMetadataKeyValues converts the safetensors __metadata__ map into a
// KeyValues slice sorted by key, so SBOM output is stable across runs. Returns
// nil for empty input (omitempty then drops the field).
func userMetadataKeyValues(m map[string]string) pkg.KeyValues {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(pkg.KeyValues, 0, len(keys))
	for _, k := range keys {
		out = append(out, pkg.KeyValue{Key: k, Value: m[k]})
	}
	return out
}

// normalizeDType maps a safetensors/torch dtype label to an uppercase quantization
// shorthand matching conventions used elsewhere in syft (e.g., BF16, F16, I8).
func normalizeDType(dtype string) string {
	switch strings.ToUpper(dtype) {
	case "BF16":
		return "BF16"
	case "F16", "FP16", "FLOAT16", "HALF":
		return "F16"
	case "F32", "FP32", "FLOAT32", "FLOAT":
		return "F32"
	case "F64", "FP64", "FLOAT64", "DOUBLE":
		return "F64"
	case "I8", "INT8":
		return "I8"
	case "U8", "UINT8":
		return "U8"
	case "I16", "INT16":
		return "I16"
	case "I32", "INT32":
		return "I32"
	case "I64", "INT64":
		return "I64"
	case "BOOL":
		return "BOOL"
	default:
		return strings.ToUpper(dtype)
	}
}
