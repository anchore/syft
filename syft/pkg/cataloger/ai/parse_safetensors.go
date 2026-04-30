package ai

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/cespare/xxhash/v2"
)

// SafeTensors file format: [8 bytes u64 LE header size] [N bytes JSON header] [tensor data].
// Reference: https://github.com/huggingface/safetensors#format
const (
	maxSafeTensorsHeaderSize = 100 * 1024 * 1024 // 100MB ceiling on header JSON to prevent OOM
)

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

// readSafeTensorsHeader reads and parses the JSON header from a .safetensors file.
// It returns the decoded header plus the on-disk size of the header JSON in bytes.
func readSafeTensorsHeader(r io.Reader) (*safeTensorsHeader, uint64, error) {
	var lenBuf [8]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, 0, fmt.Errorf("failed to read header length: %w", err)
	}
	headerLen := binary.LittleEndian.Uint64(lenBuf[:])
	if headerLen == 0 {
		return nil, 0, fmt.Errorf("safetensors header length is zero")
	}
	if headerLen > maxSafeTensorsHeaderSize {
		return nil, 0, fmt.Errorf("safetensors header size %d exceeds maximum %d", headerLen, maxSafeTensorsHeaderSize)
	}

	body := make([]byte, headerLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, 0, fmt.Errorf("failed to read header body: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, 0, fmt.Errorf("failed to decode safetensors header JSON: %w", err)
	}

	h := &safeTensorsHeader{tensors: make(map[string]safeTensorsEntry, len(raw))}
	for key, val := range raw {
		if key == "__metadata__" {
			if err := json.Unmarshal(val, &h.metadata); err != nil {
				return nil, 0, fmt.Errorf("failed to decode __metadata__: %w", err)
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

	return h, headerLen, nil
}

// parameterCount sums the element counts across all tensors in the header.
func (h *safeTensorsHeader) parameterCount() uint64 {
	var total uint64
	for _, t := range h.tensors {
		count := uint64(1)
		for _, dim := range t.Shape {
			if dim <= 0 {
				count = 0
				break
			}
			count *= uint64(dim)
		}
		total += count
	}
	return total
}

// dominantDType returns the dtype that accounts for the largest fraction of parameters.
// For mixed-precision models the "dominant" dtype is still a useful summary.
func (h *safeTensorsHeader) dominantDType() string {
	sizeByDType := make(map[string]uint64)
	for _, t := range h.tensors {
		count := uint64(1)
		for _, dim := range t.Shape {
			if dim <= 0 {
				count = 0
				break
			}
			count *= uint64(dim)
		}
		sizeByDType[t.DType] += count
	}
	var best string
	var bestSize uint64
	for dtype, size := range sizeByDType {
		if size > bestSize || (size == bestSize && dtype < best) {
			best = dtype
			bestSize = size
		}
	}
	return best
}

// metadataHash returns a stable xxhash64 over the tensor entries + __metadata__.
// Tensor keys are sorted to keep the hash deterministic across producers.
func (h *safeTensorsHeader) metadataHash() string {
	type entry struct {
		Name        string           `json:"name"`
		Entry       safeTensorsEntry `json:"entry"`
	}
	entries := make([]entry, 0, len(h.tensors))
	for name, t := range h.tensors {
		entries = append(entries, entry{Name: name, Entry: t})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	type hashInput struct {
		Tensors  []entry           `json:"tensors"`
		Metadata map[string]string `json:"metadata,omitempty"`
	}
	b, err := json.Marshal(hashInput{Tensors: entries, Metadata: h.metadata})
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%016x", xxhash.Sum64(b))
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
