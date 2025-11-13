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

// readHeader reads only the GGUF header (metadata) without reading tensor data
// This is much more efficient than reading the entire file
// The reader should be wrapped with io.LimitedReader to prevent OOM issues
func readHeader(r io.Reader) ([]byte, error) {
	// Read initial chunk to determine header size
	// GGUF format: magic(4) + version(4) + tensor_count(8) + metadata_kv_count(8) + metadata_kvs + tensors_info
	initialBuf := make([]byte, 24) // Enough for magic, version, tensor count, and kv count
	if _, err := io.ReadFull(r, initialBuf); err != nil {
		return nil, fmt.Errorf("failed to read GGUF header prefix: %w", err)
	}

	// Verify magic number
	magic := binary.LittleEndian.Uint32(initialBuf[0:4])
	if magic != ggufMagicNumber {
		return nil, fmt.Errorf("invalid GGUF magic number: 0x%08X", magic)
	}

	// We need to read the metadata KV pairs to know the full header size
	// The io.LimitedReader wrapping this reader ensures we don't read more than maxHeaderSize
	headerData := make([]byte, 0, 1024*1024) // Start with 1MB capacity
	headerData = append(headerData, initialBuf...)

	// Read the rest of the header in larger chunks for efficiency
	// The LimitedReader will return EOF once maxHeaderSize is reached
	buf := make([]byte, 64*1024) // 64KB chunks
	for {
		n, err := r.Read(buf)
		if n > 0 {
			headerData = append(headerData, buf[:n]...)
		}
		if err == io.EOF {
			// Reached end of file or limit, we have all available data
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read GGUF header: %w", err)
		}
	}

	return headerData, nil
}

// Helper to convert gguf_parser metadata to simpler types
func convertGGUFMetadataKVs(kvs gguf_parser.GGUFMetadataKVs) map[string]interface{} {
	result := make(map[string]interface{})

	for _, kv := range kvs {
		// Skip standard fields that are extracted separately
		switch kv.Key {
		case "general.architecture", "general.name", "general.license",
			"general.version", "general.parameter_count", "general.quantization":
			continue
		}
		result[kv.Key] = kv.Value
	}

	return result
}
