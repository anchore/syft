package aiartifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

// GGUF file format constants
const (
	ggufMagic   = 0x46554747 // "GGUF" in little-endian
	maxKVPairs  = 10000      // Safety limit for KV pairs
	maxKeyLen   = 65535      // Maximum key length
	maxTensors  = 100000     // Safety limit for tensors
	maxHeaderKV = 200        // Maximum KV pairs to include in Header map (to avoid bloat)
)

// GGUF value types (from GGUF spec)
const (
	ggufTypeUint8   = 0
	ggufTypeInt8    = 1
	ggufTypeUint16  = 2
	ggufTypeInt16   = 3
	ggufTypeUint32  = 4
	ggufTypeInt32   = 5
	ggufTypeFloat32 = 6
	ggufTypeUint64  = 7
	ggufTypeInt64   = 8
	ggufTypeFloat64 = 9
	ggufTypeBool    = 10
	ggufTypeString  = 11
	ggufTypeArray   = 12
)

const unkownGGUFData = "unknown"

//nolint:funlen
func parseGGUFHeader(data []byte, location string) (*pkg.GGUFFileMetadata, error) {
	reader := bytes.NewReader(data)
	// Read magic number
	var magic uint32
	if err := binary.Read(reader, binary.LittleEndian, &magic); err != nil {
		return nil, fmt.Errorf("failed to read magic number: %w", err)
	}

	if magic != ggufMagic {
		return nil, fmt.Errorf("invalid GGUF magic number: 0x%08X", magic)
	}

	// Read version
	var version uint32
	if err := binary.Read(reader, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}

	// Read tensor count
	var tensorCount uint64
	if err := binary.Read(reader, binary.LittleEndian, &tensorCount); err != nil {
		return nil, fmt.Errorf("failed to read tensor count: %w", err)
	}

	if tensorCount > maxTensors {
		log.Warnf("GGUF file has suspicious tensor count: %d (max: %d)", tensorCount, maxTensors)
		tensorCount = maxTensors
	}

	// Read metadata KV count
	var kvCount uint64
	if err := binary.Read(reader, binary.LittleEndian, &kvCount); err != nil {
		return nil, fmt.Errorf("failed to read KV count: %w", err)
	}

	if kvCount > maxKVPairs {
		log.Warnf("GGUF file has suspicious KV count: %d (max: %d)", kvCount, maxKVPairs)
		return nil, fmt.Errorf("KV count exceeds safety limit: %d", kvCount)
	}

	// Parse metadata key-value pairs
	kvMap := make(map[string]any)
	truncated := false

	for i := uint64(0); i < kvCount; i++ {
		key, value, err := readKVPair(reader)
		if err != nil {
			log.Warnf("failed to read KV pair %d: %v", i, err)
			truncated = true
			break
		}
		if len(kvMap) < maxHeaderKV {
			kvMap[key] = value
		} else {
			truncated = true
		}
	}

	// Extract common metadata fields
	metadata := &pkg.GGUFFileMetadata{
		ModelFormat:     "gguf",
		GGUFVersion:     version,
		TensorCount:     tensorCount,
		Header:          kvMap,
		TruncatedHeader: truncated,
	}

	// Extract known fields from KV map and remove them to avoid duplication in Header
	if arch, ok := kvMap["general.architecture"].(string); ok {
		metadata.Architecture = arch
		delete(kvMap, "general.architecture")
	}

	if name, ok := kvMap["general.name"].(string); ok {
		metadata.ModelName = name
		delete(kvMap, "general.name")
	} else {
		// Fall back to filename if general.name not present
		filename := filepath.Base(location)
		metadata.ModelName = strings.TrimSuffix(filename, filepath.Ext(filename))
	}

	if license, ok := kvMap["general.license"].(string); ok {
		metadata.License = license
		delete(kvMap, "general.license")
	}

	if version, ok := kvMap["general.version"].(string); ok {
		metadata.ModelVersion = version
		delete(kvMap, "general.version")
	} else {
		metadata.ModelVersion = unkownGGUFData
	}

	// Extract parameters count if present
	if params, ok := kvMap["general.parameter_count"].(uint64); ok {
		metadata.Parameters = params
		delete(kvMap, "general.parameter_count")
	}

	// Try to infer quantization from general.quantization or from filename
	if quant, ok := kvMap["general.quantization"].(string); ok {
		metadata.Quantization = quant
		delete(kvMap, "general.quantization")
	} else if quantizedBy, ok := kvMap["general.quantized_by"].(string); ok && quantizedBy != "" {
		// If quantized but no explicit quantization field, try to extract from filename
		metadata.Quantization = inferQuantizationFromFilename(location)
		// Note: we keep general.quantized_by in Header since it's not directly mapped to a field
	} else {
		metadata.Quantization = unkownGGUFData
	}

	// Compute hash of metadata for stable identifier
	metadata.Hash = computeMetadataHash(metadata)

	return metadata, nil
}

// readKVPair reads a single key-value pair from the GGUF header
func readKVPair(reader io.Reader) (string, interface{}, error) {
	// Read key length
	var keyLen uint64
	if err := binary.Read(reader, binary.LittleEndian, &keyLen); err != nil {
		return "", nil, fmt.Errorf("failed to read key length: %w", err)
	}

	if keyLen > maxKeyLen {
		return "", nil, fmt.Errorf("key length exceeds maximum: %d", keyLen)
	}

	// Read key
	keyBytes := make([]byte, keyLen)
	if _, err := io.ReadFull(reader, keyBytes); err != nil {
		return "", nil, fmt.Errorf("failed to read key: %w", err)
	}
	key := string(keyBytes)

	// Read value type
	var valueType uint32
	if err := binary.Read(reader, binary.LittleEndian, &valueType); err != nil {
		return "", nil, fmt.Errorf("failed to read value type: %w", err)
	}

	// Read value based on type
	value, err := readValue(reader, valueType)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read value for key %s: %w", key, err)
	}

	return key, value, nil
}

//nolint:funlen
func readValue(reader io.Reader, valueType uint32) (any, error) {
	switch valueType {
	case ggufTypeUint8:
		var v uint8
		err := binary.Read(reader, binary.LittleEndian, &v)
		return v, err
	case ggufTypeInt8:
		var v int8
		err := binary.Read(reader, binary.LittleEndian, &v)
		return v, err
	case ggufTypeUint16:
		var v uint16
		err := binary.Read(reader, binary.LittleEndian, &v)
		return v, err
	case ggufTypeInt16:
		var v int16
		err := binary.Read(reader, binary.LittleEndian, &v)
		return v, err
	case ggufTypeUint32:
		var v uint32
		err := binary.Read(reader, binary.LittleEndian, &v)
		return v, err
	case ggufTypeInt32:
		var v int32
		err := binary.Read(reader, binary.LittleEndian, &v)
		return v, err
	case ggufTypeFloat32:
		var v float32
		err := binary.Read(reader, binary.LittleEndian, &v)
		return v, err
	case ggufTypeUint64:
		var v uint64
		err := binary.Read(reader, binary.LittleEndian, &v)
		return v, err
	case ggufTypeInt64:
		var v int64
		err := binary.Read(reader, binary.LittleEndian, &v)
		return v, err
	case ggufTypeFloat64:
		var v float64
		err := binary.Read(reader, binary.LittleEndian, &v)
		return v, err
	case ggufTypeBool:
		var v uint8
		err := binary.Read(reader, binary.LittleEndian, &v)
		return v != 0, err
	case ggufTypeString:
		return readString(reader)
	case ggufTypeArray:
		return readArray(reader)
	default:
		return nil, fmt.Errorf("unknown value type: %d", valueType)
	}
}

// readString reads a length-prefixed UTF-8 string
func readString(reader io.Reader) (string, error) {
	var length uint64
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return "", fmt.Errorf("failed to read string length: %w", err)
	}

	if length > maxKeyLen {
		return "", fmt.Errorf("string length exceeds maximum: %d", length)
	}

	strBytes := make([]byte, length)
	if _, err := io.ReadFull(reader, strBytes); err != nil {
		return "", fmt.Errorf("failed to read string: %w", err)
	}

	return string(strBytes), nil
}

// readArray reads an array value
func readArray(reader io.Reader) (interface{}, error) {
	// Read array element type
	var elemType uint32
	if err := binary.Read(reader, binary.LittleEndian, &elemType); err != nil {
		return nil, fmt.Errorf("failed to read array element type: %w", err)
	}

	// Read array length
	var length uint64
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return nil, fmt.Errorf("failed to read array length: %w", err)
	}

	if length > 1000 {
		// Limit array size to avoid memory issues
		return nil, fmt.Errorf("array length too large: %d", length)
	}

	// Read array elements
	var elements []interface{}
	for i := uint64(0); i < length; i++ {
		value, err := readValue(reader, elemType)
		if err != nil {
			return nil, fmt.Errorf("failed to read array element %d: %w", i, err)
		}
		elements = append(elements, value)
	}

	return elements, nil
}

// inferQuantizationFromFilename attempts to extract quantization info from filename
func inferQuantizationFromFilename(filename string) string {
	// Common quantization patterns: Q4_K_M, IQ4_NL, Q5_K_S, etc.
	quantPattern := regexp.MustCompile(`[IQ]\d+_[A-Z_]+`)
	if match := quantPattern.FindString(filename); match != "" {
		return match
	}
	return unkownGGUFData
}

// computeMetadataHash computes a stable hash of the metadata for use as a global identifier
func computeMetadataHash(metadata *pkg.GGUFFileMetadata) string {
	// Create a stable representation of the metadata
	hashData := struct {
		Format       string
		Name         string
		Version      string
		Architecture string
		GGUFVersion  uint32
		TensorCount  uint64
	}{
		Format:       metadata.ModelFormat,
		Name:         metadata.ModelName,
		Version:      metadata.ModelVersion,
		Architecture: metadata.Architecture,
		GGUFVersion:  metadata.GGUFVersion,
		TensorCount:  metadata.TensorCount,
	}

	// Marshal to JSON for stable hashing
	jsonBytes, err := json.Marshal(hashData)
	if err != nil {
		log.Warnf("failed to marshal metadata for hashing: %v", err)
		return ""
	}

	// Compute SHA256 hash
	hash := sha256.Sum256(jsonBytes)
	return fmt.Sprintf("%x", hash[:8]) // Use first 8 bytes (16 hex chars)
}
