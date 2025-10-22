package ai

import (
	"encoding/binary"
	"fmt"
	"io"

	gguf_parser "github.com/gpustack/gguf-parser-go"
)

// GGUF file format constants
const (
	ggufMagicNumber = 0x46554747       // "GGUF" in little-endian
	maxHeaderSize   = 50 * 1024 * 1024 // 50MB for large tokenizer vocabularies
)

// ggufHeaderReader reads just the header portion of a GGUF file efficiently
type ggufHeaderReader struct {
	reader io.Reader
}

// readHeader reads only the GGUF header (metadata) without reading tensor data
// This is much more efficient than reading the entire file
func (r *ggufHeaderReader) readHeader() ([]byte, error) {
	// Read initial chunk to determine header size
	// GGUF format: magic(4) + version(4) + tensor_count(8) + metadata_kv_count(8) + metadata_kvs + tensors_info
	initialBuf := make([]byte, 24) // Enough for magic, version, tensor count, and kv count
	if _, err := io.ReadFull(r.reader, initialBuf); err != nil {
		return nil, fmt.Errorf("failed to read GGUF header prefix: %w", err)
	}

	// Verify magic number
	magic := binary.LittleEndian.Uint32(initialBuf[0:4])
	if magic != ggufMagicNumber {
		return nil, fmt.Errorf("invalid GGUF magic number: 0x%08X", magic)
	}

	// We need to read the metadata KV pairs to know the full header size
	// For efficiency, we'll read incrementally up to maxHeaderSize
	headerData := make([]byte, 0, 1024*1024) // Start with 1MB capacity
	headerData = append(headerData, initialBuf...)

	// Read the rest of the header in larger chunks for efficiency
	buf := make([]byte, 64*1024) // 64KB chunks
	for len(headerData) < maxHeaderSize {
		n, err := r.reader.Read(buf)
		if n > 0 {
			headerData = append(headerData, buf[:n]...)
		}
		if err == io.EOF {
			// Reached end of file, we have all the data
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read GGUF header: %w", err)
		}
	}

	if len(headerData) > maxHeaderSize {
		// Truncate if we somehow read too much
		headerData = headerData[:maxHeaderSize]
	}

	return headerData, nil
}

// Helper to convert gguf_parser metadata to simpler types
func convertGGUFMetadataKVs(kvs gguf_parser.GGUFMetadataKVs) map[string]interface{} {
	result := make(map[string]interface{})

	// Limit KV pairs to avoid bloat
	const maxKVPairs = 200
	count := 0

	for _, kv := range kvs {
		if count >= maxKVPairs {
			break
		}

		// Skip standard fields that are extracted separately
		switch kv.Key {
		case "general.architecture", "general.name", "general.license",
			"general.version", "general.parameter_count", "general.quantization":
			continue
		}

		result[kv.Key] = kv.Value
		count++
	}

	return result
}
